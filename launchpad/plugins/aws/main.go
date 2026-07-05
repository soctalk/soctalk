// launchpad-plugin-aws provisions VMs on AWS EC2 using aws-sdk-go-v2.
//
// It launches an EC2 instance with a cloud-init user-data payload (the host
// builds the Tailscale join script and passes it via VMSpec.UserData; this
// plugin additionally injects the VMSpec SSH public keys for the login user).
// Instances are tagged for idempotent lookup, so create/wait_ready/destroy/
// inspect all reconcile against the same (run_id, vm_key) pair. The tailnet
// IP is discovered by the orchestrator over Tailscale; this plugin only
// reports the instance's public/private addresses.
//
// Config (from launchpad, via plugin.initialize params.config):
//   region:            fallback for VMSpec.Region (default: $AWS_REGION)
//   instance_type:     fallback for VMSpec.SizeHint (default: "t3.large")
//   ami:               fallback for VMSpec.Image (default: latest Ubuntu 24.04 LTS amd64)
//   subnet_id:         optional VPC subnet to launch into
//   security_group_id: optional security group to attach
//   tailnet:           tailnet name (used by the orchestrator/user-data)
//   ssh_keys:          fallback authorized public keys
//
// Env:
//   AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY / AWS_SESSION_TOKEN / AWS_PROFILE
//   AWS_REGION (default cred chain + region resolution)
//   TAILSCALE_API_KEY
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	sdk "github.com/soctalk/launchpad-sdk-go"
)

const (
	name    = "aws"
	version = "0.1.0"

	tagRunID   = "lp:run_id"
	tagVMKey   = "lp:vm_key"
	tagManaged = "lp:managed"
	tagName    = "Name"

	// Canonical (099720109477) publishes the official Ubuntu AMIs.
	ubuntuOwner     = "099720109477"
	ubuntuNameGlob  = "ubuntu/images/hvm-ssd*/ubuntu-noble-24.04-amd64-server-*"
	defaultType     = "t3.large"
	defaultDiskGB   = 50 // root volume; the SOC tenant (k3s + Wazuh) needs headroom
	defaultProbeReg = "us-east-1" // only used to reach AWS for the auth probe
	loginUser       = "ops"       // provisioned by cloud-init (composeUserData)
)

type plugin struct {
	client *ec2.Client
	cfg    config
}

type config struct {
	Region          string   `json:"region,omitempty"`
	InstanceType    string   `json:"instance_type,omitempty"`
	AMI             string   `json:"ami,omitempty"`
	SubnetID        string   `json:"subnet_id,omitempty"`
	SecurityGroupID string   `json:"security_group_id,omitempty"`
	Tailnet         string   `json:"tailnet,omitempty"`
	TagPrefix       string   `json:"tag_prefix,omitempty"`
	DiskGB          int      `json:"disk_gb,omitempty"`
	SSHKeys         []string `json:"ssh_keys,omitempty"`
}

var p plugin

// tsAPIKey is the Tailscale API key used to mint ephemeral device auth keys.
// Set once in initialize from the TAILSCALE_API_KEY env (injected per-run from
// the Network resource).
var tsAPIKey string

func main() {
	err := sdk.Serve(sdk.Plugin{
		Name:    name,
		Version: version,

		AllowedEnvVars: []string{
			"TAILSCALE_API_KEY",
			"AWS_ACCESS_KEY_ID",
			"AWS_SECRET_ACCESS_KEY",
			"AWS_SESSION_TOKEN",
			"AWS_REGION",
			"AWS_PROFILE",
			"HOME",
			"SSH_AUTH_SOCK",
		},

		ConfigSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"region":            map[string]any{"type": "string"},
				"instance_type":     map[string]any{"type": "string", "default": defaultType},
				"ami":               map[string]any{"type": "string"},
				"disk_gb":           map[string]any{"type": "integer", "default": defaultDiskGB},
				"subnet_id":         map[string]any{"type": "string"},
				"security_group_id": map[string]any{"type": "string"},
				"tailnet":           map[string]any{"type": "string"},
				"ssh_keys": map[string]any{
					"type":  "array",
					"items": map[string]any{"type": "string"},
				},
			},
			"additionalProperties": false,
		},

		Initialize: initialize,
		Plan:       plan,
		Create:     create,
		WaitReady:  waitReady,
		Destroy:    destroy,
		Inspect:    inspect,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "aws plugin:", err)
		os.Exit(1)
	}
}

func initialize(ctx context.Context, params sdk.InitializeParams) (sdk.InitializeResult, error) {
	cfg := config{
		Region:       os.Getenv("AWS_REGION"),
		InstanceType: defaultType,
	}
	if raw, ok := params.Config["region"].(string); ok && raw != "" {
		cfg.Region = raw
	}
	if raw, ok := params.Config["instance_type"].(string); ok && raw != "" {
		cfg.InstanceType = raw
	}
	if raw, ok := params.Config["ami"].(string); ok {
		cfg.AMI = raw
	}
	if raw, ok := params.Config["subnet_id"].(string); ok {
		cfg.SubnetID = raw
	}
	if raw, ok := params.Config["security_group_id"].(string); ok {
		cfg.SecurityGroupID = raw
	}
	if raw, ok := params.Config["tailnet"].(string); ok {
		cfg.Tailnet = raw
	}
	if raw, ok := params.Config["tag_prefix"].(string); ok {
		cfg.TagPrefix = raw
	}
	cfg.DiskGB = defaultDiskGB
	if raw, ok := params.Config["disk_gb"]; ok {
		if n, ok := toInt(raw); ok && n > 0 {
			cfg.DiskGB = n
		}
	}
	cfg.SSHKeys = toStringSlice(params.Config["ssh_keys"])
	p.cfg = cfg

	// Tailscale API key: injected per-run from the Network resource. Required to
	// mint the ephemeral device auth key baked into the instance's cloud-init.
	tsAPIKey = os.Getenv("TAILSCALE_API_KEY")

	// Region for the AWS SDK: config value, else AWS_REGION (already folded in),
	// else a safe fallback so the auth probe still reaches AWS.
	region := cfg.Region
	if region == "" {
		region = defaultProbeReg
	}
	awsCfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(region))
	if err != nil {
		return sdk.InitializeResult{}, sdk.Errf(sdk.CatAuth,
			"aws.auth.failed", "loading AWS config failed: %v", err)
	}
	client := ec2.NewFromConfig(awsCfg)

	// One cheap authenticated call to validate credentials.
	if _, err := client.DescribeRegions(ctx, &ec2.DescribeRegionsInput{}); err != nil {
		return sdk.InitializeResult{}, sdk.Errf(sdk.CatAuth,
			"aws.auth.failed", "AWS credential probe failed: %v", err)
	}

	p.client = client
	if p.cfg.Region == "" {
		p.cfg.Region = awsCfg.Region
	}
	return sdk.InitializeResult{Ready: true}, nil
}

// resolveSpec merges spec defaults with plugin config fallbacks.
func resolveSpec(spec *sdk.VMSpec) {
	if spec.Region == "" {
		spec.Region = p.cfg.Region
	}
	if spec.Image == "" {
		spec.Image = p.cfg.AMI
	}
	if spec.SizeHint == "" {
		spec.SizeHint = p.cfg.InstanceType
	}
	if spec.SizeHint == "" {
		spec.SizeHint = defaultType
	}
	if len(spec.SSHKeys) == 0 {
		spec.SSHKeys = p.cfg.SSHKeys
	}
}

func plan(ctx context.Context, params sdk.VMPlanParams, emit sdk.Emitter) (sdk.VMPlanResult, error) {
	spec := params.Spec
	resolveSpec(&spec)
	if err := validateSpec(spec); err != nil {
		return sdk.VMPlanResult{}, err
	}
	img := spec.Image
	if img == "" {
		img = "latest Ubuntu 24.04 LTS amd64"
	}
	return sdk.VMPlanResult{
		Summary:              fmt.Sprintf("aws: %s in %s (ami=%s)", spec.SizeHint, spec.Region, img),
		EstimatedDurationSec: 90,
	}, nil
}

func validateSpec(spec sdk.VMSpec) error {
	if spec.RunID == "" || spec.VMKey == "" {
		return sdk.Errf(sdk.CatValidation, "aws.spec.missing_key",
			"run_id and vm_key are required")
	}
	if spec.Region == "" {
		return sdk.Errf(sdk.CatValidation, "aws.spec.missing_region",
			"region is required (set on VMSpec, plugin config, or AWS_REGION)")
	}
	if spec.SizeHint == "" {
		return sdk.Errf(sdk.CatValidation, "aws.spec.missing_instance_type",
			"instance_type is required (e.g. t3.large)")
	}
	return nil
}

func requireClient() error {
	if p.client == nil {
		return sdk.Errf(sdk.CatAuth, "aws.not_initialized",
			"plugin.initialize has not been called successfully (check AWS credentials)")
	}
	return nil
}

func create(ctx context.Context, params sdk.VMCreateParams, emit sdk.Emitter) (sdk.VMCreateResult, error) {
	if err := requireClient(); err != nil {
		return sdk.VMCreateResult{}, err
	}
	spec := params.Spec
	resolveSpec(&spec)
	if err := validateSpec(spec); err != nil {
		return sdk.VMCreateResult{}, err
	}

	emit.Progress("lookup", 5, "checking for existing instance")
	if existing, err := findByTags(ctx, spec.RunID, spec.VMKey); err != nil {
		return sdk.VMCreateResult{}, sdk.Errf(sdk.CatInternal,
			"aws.describe_failed", "listing existing instances: %v", err)
	} else if existing != nil {
		emit.Log("info", "reusing existing instance", map[string]any{"instance_id": aws.ToString(existing.InstanceId)})
		return instanceToCreateResult(existing), nil
	}

	ami := spec.Image
	if ami == "" {
		emit.Progress("resolve_ami", 15, "resolving latest Ubuntu 24.04 AMI")
		resolved, err := resolveUbuntuAMI(ctx)
		if err != nil {
			return sdk.VMCreateResult{}, err
		}
		ami = resolved
	}

	// Mint a Tailscale ephemeral auth key and compose cloud-init that installs
	// Tailscale and joins the tailnet on first boot. The orchestrator then
	// resolves this instance by its tailnet hostname (lp-<vmKey>).
	emit.Progress("tailscale", 25, "minting device auth key")
	tag := tailscaleTagForSpec(spec)
	tskey, err := mintTailscaleKey(ctx, p.cfg.Tailnet, tag)
	if err != nil {
		return sdk.VMCreateResult{}, err
	}
	userData := base64.StdEncoding.EncodeToString([]byte(composeUserData(cloudInitInputs{
		Hostname:      hostnameFor(spec.VMKey),
		SSHKeys:       mergeSSHKeys(p.cfg.SSHKeys, spec.SSHKeys),
		TailscaleKey:  tskey,
		TailscaleTag:  tag,
		ExtraUserData: spec.UserData,
	})))

	tags := []ec2types.Tag{
		{Key: aws.String(tagRunID), Value: aws.String(spec.RunID)},
		{Key: aws.String(tagVMKey), Value: aws.String(spec.VMKey)},
		{Key: aws.String(tagManaged), Value: aws.String("true")},
		{Key: aws.String(tagName), Value: aws.String(fmt.Sprintf("lp-%s-%s", spec.RunID, spec.VMKey))},
	}
	for k, v := range spec.Tags {
		tags = append(tags, ec2types.Tag{Key: aws.String(k), Value: aws.String(v)})
	}

	input := &ec2.RunInstancesInput{
		ImageId:      aws.String(ami),
		InstanceType: ec2types.InstanceType(spec.SizeHint),
		MinCount:     aws.Int32(1),
		MaxCount:     aws.Int32(1),
		UserData:     aws.String(userData),
		TagSpecifications: []ec2types.TagSpecification{
			{ResourceType: ec2types.ResourceTypeInstance, Tags: tags},
		},
	}
	if p.cfg.SubnetID != "" {
		input.SubnetId = aws.String(p.cfg.SubnetID)
	}
	if p.cfg.SecurityGroupID != "" {
		input.SecurityGroupIds = []string{p.cfg.SecurityGroupID}
	}
	// Size the root volume: the default Ubuntu AMI volume (~8GB) is too small
	// for the SOC tenant (k3s + Wazuh), which hits DiskPressure and evicts pods.
	if p.cfg.DiskGB > 0 {
		root := rootDeviceName(ctx, ami)
		input.BlockDeviceMappings = []ec2types.BlockDeviceMapping{{
			DeviceName: aws.String(root),
			Ebs: &ec2types.EbsBlockDevice{
				VolumeSize:          aws.Int32(int32(p.cfg.DiskGB)),
				VolumeType:          ec2types.VolumeTypeGp3,
				DeleteOnTermination: aws.Bool(true),
			},
		}}
	}

	emit.Progress("create", 40, "launching instance")
	out, err := p.client.RunInstances(ctx, input)
	if err != nil {
		return sdk.VMCreateResult{}, sdk.Errf(sdk.CatProviderUnavailable,
			"aws.run_instances_failed", "%v", err)
	}
	if len(out.Instances) == 0 {
		return sdk.VMCreateResult{}, sdk.Errf(sdk.CatInternal,
			"aws.run_instances_empty", "RunInstances returned no instances")
	}
	inst := out.Instances[0]
	emit.Progress("create", 100, "instance launched")
	return instanceToCreateResult(&inst), nil
}

func waitReady(ctx context.Context, params sdk.VMWaitReadyParams, emit sdk.Emitter) (sdk.VMWaitReadyResult, error) {
	if err := requireClient(); err != nil {
		return sdk.VMWaitReadyResult{}, err
	}
	deadline := time.Now().Add(20 * time.Minute)
	for time.Now().Before(deadline) {
		inst, err := lookupInstance(ctx, params.VMID, params.RunID, params.VMKey)
		if err != nil {
			// AWS is eventually consistent: for a few seconds after RunInstances a
			// DescribeInstances by that ID can transiently return
			// InvalidInstanceID.NotFound. Treat it as "not visible yet" and keep
			// polling rather than failing the whole run.
			if isTransientNotFound(err) {
				emit.Progress("wait_ready", 20, "instance not yet visible (AWS eventual consistency)")
				if !sleepCtx(ctx, 5*time.Second) {
					return sdk.VMWaitReadyResult{}, ctx.Err()
				}
				continue
			}
			return sdk.VMWaitReadyResult{}, sdk.Errf(sdk.CatNotFound,
				"aws.describe_failed", "%v", err)
		}
		if inst == nil {
			// Not yet visible by id/tags — propagation in progress; keep waiting.
			emit.Progress("wait_ready", 20, "instance not yet visible")
			if !sleepCtx(ctx, 5*time.Second) {
				return sdk.VMWaitReadyResult{}, ctx.Err()
			}
			continue
		}
		state := instanceState(inst)
		if state == ec2types.InstanceStateNameRunning {
			emit.Progress("wait_ready", 100, "running")
			return sdk.VMWaitReadyResult{
				Ready: true,
				IPv4:  aws.ToString(inst.PublicIpAddress),
				IPv6:  ipv6Of(inst),
			}, nil
		}
		emit.Progress("wait_ready", 50, "instance state: "+string(state))
		if !sleepCtx(ctx, 5*time.Second) {
			return sdk.VMWaitReadyResult{}, ctx.Err()
		}
	}
	return sdk.VMWaitReadyResult{}, sdk.Errf(sdk.CatTimeout,
		"aws.wait_ready.timeout", "instance did not reach running within 20m")
}

// isTransientNotFound reports whether err is AWS's eventual-consistency
// "instance ID not found yet" error, which is safe to retry shortly after
// RunInstances rather than treating as a hard failure.
func isTransientNotFound(err error) bool {
	return err != nil && strings.Contains(err.Error(), "InvalidInstanceID.NotFound")
}

// sleepCtx sleeps for d or until ctx is cancelled; returns false if cancelled.
func sleepCtx(ctx context.Context, d time.Duration) bool {
	select {
	case <-ctx.Done():
		return false
	case <-time.After(d):
		return true
	}
}

func destroy(ctx context.Context, params sdk.VMDestroyParams, emit sdk.Emitter) (sdk.VMDestroyResult, error) {
	if err := requireClient(); err != nil {
		return sdk.VMDestroyResult{}, err
	}
	var ids []string
	if params.VMID != "" {
		ids = []string{params.VMID}
	} else {
		found, err := findInstanceIDsByTags(ctx, params.RunID, params.VMKey)
		if err != nil {
			return sdk.VMDestroyResult{}, sdk.Errf(sdk.CatInternal,
				"aws.describe_failed", "%v", err)
		}
		ids = found
	}
	if len(ids) == 0 {
		return sdk.VMDestroyResult{Destroyed: false}, nil
	}
	emit.Progress("destroy", 50, "terminating instance(s)")
	_, err := p.client.TerminateInstances(ctx, &ec2.TerminateInstancesInput{InstanceIds: ids})
	if err != nil {
		return sdk.VMDestroyResult{}, sdk.Errf(sdk.CatProviderUnavailable,
			"aws.terminate_failed", "%v", err)
	}
	return sdk.VMDestroyResult{Destroyed: true}, nil
}

func inspect(ctx context.Context, params sdk.VMInspectParams, emit sdk.Emitter) (sdk.VMInspectResult, error) {
	if err := requireClient(); err != nil {
		return sdk.VMInspectResult{}, err
	}
	inst, err := lookupInstance(ctx, params.VMID, params.RunID, params.VMKey)
	if err != nil {
		return sdk.VMInspectResult{}, err
	}
	if inst == nil {
		return sdk.VMInspectResult{Exists: false}, nil
	}
	return sdk.VMInspectResult{
		Exists:  true,
		VMID:    aws.ToString(inst.InstanceId),
		State:   mapInstanceState(instanceState(inst)),
		IPv4:    aws.ToString(inst.PublicIpAddress),
		IPv6:    ipv6Of(inst),
		SSHUser: loginUser,
		Metadata: map[string]string{
			"provider":          "aws",
			"region":            p.cfg.Region,
			"availability_zone": azOf(inst),
			"instance_type":     string(inst.InstanceType),
			"private_ip":        aws.ToString(inst.PrivateIpAddress),
		},
	}, nil
}

// ------------------------------------------------------------------
// helpers
// ------------------------------------------------------------------

// lookupInstance resolves an instance by VMID if given, else by tags. When
// looked up by VMID it returns the instance even if terminated (so inspect
// can report state); tag lookups only return non-terminated instances.
func lookupInstance(ctx context.Context, vmID, runID, vmKey string) (*ec2types.Instance, error) {
	if vmID != "" {
		return getInstanceByID(ctx, vmID)
	}
	return findByTags(ctx, runID, vmKey)
}

func getInstanceByID(ctx context.Context, id string) (*ec2types.Instance, error) {
	out, err := p.client.DescribeInstances(ctx, &ec2.DescribeInstancesInput{
		InstanceIds: []string{id},
	})
	if err != nil {
		return nil, err
	}
	return firstInstance(out), nil
}

func tagFilters(runID, vmKey string) []ec2types.Filter {
	return []ec2types.Filter{
		{Name: aws.String("tag:" + tagRunID), Values: []string{runID}},
		{Name: aws.String("tag:" + tagVMKey), Values: []string{vmKey}},
		// non-terminated states only (terminated/shutting-down excluded)
		{Name: aws.String("instance-state-name"), Values: []string{"pending", "running", "stopping", "stopped"}},
	}
}

func findByTags(ctx context.Context, runID, vmKey string) (*ec2types.Instance, error) {
	out, err := p.client.DescribeInstances(ctx, &ec2.DescribeInstancesInput{
		Filters: tagFilters(runID, vmKey),
	})
	if err != nil {
		return nil, err
	}
	return firstInstance(out), nil
}

func findInstanceIDsByTags(ctx context.Context, runID, vmKey string) ([]string, error) {
	out, err := p.client.DescribeInstances(ctx, &ec2.DescribeInstancesInput{
		Filters: tagFilters(runID, vmKey),
	})
	if err != nil {
		return nil, err
	}
	var ids []string
	for _, r := range out.Reservations {
		for _, inst := range r.Instances {
			ids = append(ids, aws.ToString(inst.InstanceId))
		}
	}
	return ids, nil
}

func firstInstance(out *ec2.DescribeInstancesOutput) *ec2types.Instance {
	if out == nil {
		return nil
	}
	for _, r := range out.Reservations {
		for i := range r.Instances {
			inst := r.Instances[i]
			return &inst
		}
	}
	return nil
}

func resolveUbuntuAMI(ctx context.Context) (string, error) {
	out, err := p.client.DescribeImages(ctx, &ec2.DescribeImagesInput{
		Owners: []string{ubuntuOwner},
		Filters: []ec2types.Filter{
			{Name: aws.String("name"), Values: []string{ubuntuNameGlob}},
			{Name: aws.String("architecture"), Values: []string{"x86_64"}},
			{Name: aws.String("root-device-type"), Values: []string{"ebs"}},
			{Name: aws.String("virtualization-type"), Values: []string{"hvm"}},
			{Name: aws.String("state"), Values: []string{"available"}},
		},
	})
	if err != nil {
		return "", sdk.Errf(sdk.CatProviderUnavailable,
			"aws.ami.lookup_failed", "%v", err)
	}
	if len(out.Images) == 0 {
		return "", sdk.Errf(sdk.CatNotFound,
			"aws.ami.not_found", "no Ubuntu 24.04 LTS amd64 AMI found for owner %s", ubuntuOwner)
	}
	// Newest by CreationDate (ISO-8601 sorts lexicographically).
	sort.Slice(out.Images, func(i, j int) bool {
		return aws.ToString(out.Images[i].CreationDate) > aws.ToString(out.Images[j].CreationDate)
	})
	return aws.ToString(out.Images[0].ImageId), nil
}

// --- Tailscale join + cloud-init composition -------------------------------
// Ported from the qemu-family plugins: cloud VMs join the tailnet on first boot
// via a plugin-minted ephemeral auth key baked into cloud-init. The orchestrator
// discovers each VM by its tailnet hostname (lp-<vmKey>) rather than a public IP.

type cloudInitInputs struct {
	Hostname      string
	SSHKeys       []string
	TailscaleKey  string
	TailscaleTag  string
	ExtraUserData string
}

// composeUserData builds a #cloud-config that provisions the ops user, installs
// Tailscale, and joins the tailnet with the minted auth key.
func composeUserData(in cloudInitInputs) string {
	var b bytes.Buffer
	b.WriteString("#cloud-config\n")
	fmt.Fprintf(&b, "hostname: %s\n", in.Hostname)
	b.WriteString("manage_etc_hosts: true\n")
	b.WriteString("users:\n")
	b.WriteString("  - default\n")
	b.WriteString("  - name: ops\n")
	b.WriteString("    sudo: ALL=(ALL) NOPASSWD:ALL\n")
	b.WriteString("    shell: /bin/bash\n")
	if len(in.SSHKeys) > 0 {
		b.WriteString("    ssh_authorized_keys:\n")
		for _, k := range in.SSHKeys {
			fmt.Fprintf(&b, "      - %s\n", k)
		}
	}
	b.WriteString("package_update: true\n")
	b.WriteString("packages: [curl, ca-certificates, jq]\n")
	b.WriteString("runcmd:\n")
	b.WriteString("  - curl -fsSL https://tailscale.com/install.sh | sh\n")
	fmt.Fprintf(&b,
		"  - tailscale up --auth-key=%q --advertise-tags=%s --hostname=%s\n",
		in.TailscaleKey, in.TailscaleTag, in.Hostname)
	if in.ExtraUserData != "" {
		for _, line := range strings.Split(strings.TrimSpace(in.ExtraUserData), "\n") {
			fmt.Fprintf(&b, "  - %s\n", line)
		}
	}
	return b.String()
}

// mintTailscaleKey creates a single-use, ephemeral, pre-authorized device auth
// key tagged for this VM. Requires TAILSCALE_API_KEY (tsAPIKey).
func mintTailscaleKey(ctx context.Context, tailnet, tag string) (string, error) {
	if tailnet == "" {
		return "", sdk.Errf(sdk.CatValidation, "aws.tailscale.no_tailnet", "tailnet is empty")
	}
	if tsAPIKey == "" {
		return "", sdk.Errf(sdk.CatAuth, "aws.tailscale.no_api_key",
			"TAILSCALE_API_KEY is required for minting device auth keys")
	}
	payload := map[string]any{
		"capabilities": map[string]any{
			"devices": map[string]any{
				"create": map[string]any{
					"reusable":      false,
					"ephemeral":     true,
					"preauthorized": true,
					"tags":          []string{tag},
				},
			},
		},
		"expirySeconds": 3600,
	}
	body, _ := json.Marshal(payload)
	url := fmt.Sprintf("https://api.tailscale.com/api/v2/tailnet/%s/keys", tailnet)
	req, _ := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth(tsAPIKey, "")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", sdk.Errf(sdk.CatProviderUnavailable, "aws.tailscale.api_error", "%v", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return "", sdk.Errf(sdk.CatAuth, "aws.tailscale.api_status",
			"tailscale API %d: %s", resp.StatusCode, string(raw))
	}
	var out struct {
		Key string `json:"key"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return "", err
	}
	if out.Key == "" {
		return "", sdk.Errf(sdk.CatInternal, "aws.tailscale.key_missing",
			"no key in tailscale response: %s", string(raw))
	}
	return out.Key, nil
}

// tailscaleTagForSpec derives the advertised tag from the VM role/slug so the
// tailnet ACL can group MSSP and tenant devices. Matches the qemu/vmware plugins.
func tailscaleTagForSpec(spec sdk.VMSpec) string {
	prefix := p.cfg.TagPrefix
	role := spec.Tags["role"]
	slug := spec.Tags["tenant_slug"]
	if role == "mssp" {
		return "tag:" + prefix + "mssp"
	}
	if role == "tenant" && slug != "" {
		return "tag:" + prefix + "tenant-" + slug
	}
	return "tag:" + prefix + "lp-" + spec.VMKey
}

func hostnameFor(vmKey string) string {
	return "lp-" + sanitizeHostname(vmKey)
}

func sanitizeHostname(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
			b.WriteRune(r)
		} else {
			b.WriteRune('-')
		}
	}
	out := strings.Trim(b.String(), "-")
	if len(out) > 40 {
		out = out[:40]
	}
	if out == "" {
		buf := make([]byte, 4)
		_, _ = rand.Read(buf)
		out = "lp-" + hex.EncodeToString(buf)
	}
	return out
}

func mergeSSHKeys(a, b []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(a)+len(b))
	for _, k := range append(append([]string{}, a...), b...) {
		if k = strings.TrimSpace(k); k != "" && !seen[k] {
			seen[k] = true
			out = append(out, k)
		}
	}
	return out
}

func instanceToCreateResult(inst *ec2types.Instance) sdk.VMCreateResult {
	id := aws.ToString(inst.InstanceId)
	return sdk.VMCreateResult{
		VMID:        id,
		IPv4:        aws.ToString(inst.PublicIpAddress),
		IPv6:        ipv6Of(inst),
		SSHUser:     loginUser,
		SSHPort:     22,
		ProviderURL: fmt.Sprintf("https://console.aws.amazon.com/ec2/home?region=%s#InstanceDetails:instanceId=%s", p.cfg.Region, id),
		Metadata: map[string]string{
			"provider":          "aws",
			"region":            p.cfg.Region,
			"availability_zone": azOf(inst),
			"instance_type":     string(inst.InstanceType),
			"private_ip":        aws.ToString(inst.PrivateIpAddress),
		},
	}
}

func instanceState(inst *ec2types.Instance) ec2types.InstanceStateName {
	if inst == nil || inst.State == nil {
		return ""
	}
	return inst.State.Name
}

func mapInstanceState(s ec2types.InstanceStateName) string {
	switch s {
	case ec2types.InstanceStateNameRunning:
		return "running"
	case ec2types.InstanceStateNamePending:
		return "provisioning"
	case ec2types.InstanceStateNameStopping, ec2types.InstanceStateNameStopped:
		return "stopped"
	case ec2types.InstanceStateNameShuttingDown:
		return "deleting"
	case ec2types.InstanceStateNameTerminated:
		return "destroyed"
	default:
		return "unknown"
	}
}

func ipv6Of(inst *ec2types.Instance) string {
	if inst == nil {
		return ""
	}
	for _, ni := range inst.NetworkInterfaces {
		for _, a := range ni.Ipv6Addresses {
			if v := aws.ToString(a.Ipv6Address); v != "" {
				return v
			}
		}
	}
	return ""
}

func azOf(inst *ec2types.Instance) string {
	if inst == nil || inst.Placement == nil {
		return ""
	}
	return aws.ToString(inst.Placement.AvailabilityZone)
}

// rootDeviceName returns the AMI's root block-device name (e.g. /dev/sda1) so
// the resized root volume overrides the right device. Falls back to /dev/sda1
// (the Ubuntu HVM default) if the image can't be described.
func rootDeviceName(ctx context.Context, ami string) string {
	out, err := p.client.DescribeImages(ctx, &ec2.DescribeImagesInput{
		ImageIds: []string{ami},
	})
	if err == nil && len(out.Images) > 0 && aws.ToString(out.Images[0].RootDeviceName) != "" {
		return aws.ToString(out.Images[0].RootDeviceName)
	}
	return "/dev/sda1"
}

// toInt coerces a JSON-decoded config value (float64, int, or numeric string).
func toInt(v any) (int, bool) {
	switch n := v.(type) {
	case float64:
		return int(n), true
	case int:
		return n, true
	case int64:
		return int(n), true
	case string:
		if i, err := strconv.Atoi(strings.TrimSpace(n)); err == nil {
			return i, true
		}
	}
	return 0, false
}

func toStringSlice(v any) []string {
	arr, ok := v.([]any)
	if !ok {
		return nil
	}
	var out []string
	for _, e := range arr {
		if s, ok := e.(string); ok && s != "" {
			out = append(out, s)
		}
	}
	return out
}
