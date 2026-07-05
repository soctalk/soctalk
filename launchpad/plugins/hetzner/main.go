// launchpad-plugin-hetzner provisions VMs on Hetzner Cloud.
//
// Config (from launchpad, via plugin.initialize params.config):
//   region: fallback for VMSpec.Region ("fsn1", "nbg1", "hel1", ...)
//   image:  fallback for VMSpec.Image ("ubuntu-24.04", ...)
//   size:   fallback for VMSpec.SizeHint ("cx22", "cpx31", ...)
//
// Env:
//   HCLOUD_TOKEN (required)
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/hetznercloud/hcloud-go/v2/hcloud"
	sdk "github.com/soctalk/launchpad-sdk-go"
)

const (
	name    = "hetzner"
	version = "0.1.0"

	labelRunID   = "launchpad.run_id"
	labelVMKey   = "launchpad.vm_key"
	labelManaged = "launchpad.managed"
)

type plugin struct {
	client *hcloud.Client
	cfg    config
}

type config struct {
	Region    string `json:"region,omitempty"`
	Image     string `json:"image,omitempty"`
	Size      string `json:"size,omitempty"`
	Tailnet   string `json:"tailnet,omitempty"`
	TagPrefix string `json:"tag_prefix,omitempty"`
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

		AllowedEnvVars: []string{"HCLOUD_TOKEN", "TAILSCALE_API_KEY", "HOME"},

		ConfigSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"region":     map[string]any{"type": "string"},
				"image":      map[string]any{"type": "string"},
				"size":       map[string]any{"type": "string"},
				"tailnet":    map[string]any{"type": "string"},
				"tag_prefix": map[string]any{"type": "string"},
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
		fmt.Fprintln(os.Stderr, "hetzner plugin:", err)
		os.Exit(1)
	}
}

func initialize(ctx context.Context, params sdk.InitializeParams) (sdk.InitializeResult, error) {
	token := os.Getenv("HCLOUD_TOKEN")
	if token == "" {
		return sdk.InitializeResult{}, sdk.Errf(sdk.CatAuth,
			"hetzner.credentials.missing",
			"HCLOUD_TOKEN is not set")
	}
	if raw, ok := params.Config["region"].(string); ok {
		p.cfg.Region = raw
	}
	if raw, ok := params.Config["image"].(string); ok {
		p.cfg.Image = raw
	}
	if raw, ok := params.Config["size"].(string); ok {
		p.cfg.Size = raw
	}
	if raw, ok := params.Config["tailnet"].(string); ok {
		p.cfg.Tailnet = raw
	}
	if raw, ok := params.Config["tag_prefix"].(string); ok {
		p.cfg.TagPrefix = raw
	}

	// Tailscale API key: injected per-run from the Network resource. Required to
	// mint the ephemeral device auth key baked into the server's cloud-init.
	tsAPIKey = os.Getenv("TAILSCALE_API_KEY")

	p.client = hcloud.NewClient(hcloud.WithToken(token))
	// Cheap ping: list images with limit=1. Confirms creds.
	_, _, err := p.client.ServerType.List(ctx, hcloud.ServerTypeListOpts{
		ListOpts: hcloud.ListOpts{PerPage: 1, Page: 1},
	})
	if err != nil {
		return sdk.InitializeResult{}, sdk.Errf(sdk.CatAuth,
			"hetzner.credentials.probe_failed",
			"Hetzner API probe failed: %v", err)
	}
	return sdk.InitializeResult{Ready: true}, nil
}

// resolveSpec merges spec defaults with plugin config fallbacks.
func resolveSpec(spec *sdk.VMSpec) {
	if spec.Region == "" {
		spec.Region = p.cfg.Region
	}
	if spec.Image == "" {
		spec.Image = p.cfg.Image
	}
	if spec.SizeHint == "" {
		spec.SizeHint = p.cfg.Size
	}
}

func plan(ctx context.Context, params sdk.VMPlanParams, emit sdk.Emitter) (sdk.VMPlanResult, error) {
	// plan can run in the compliance suite before Initialize; guard nil client.
	spec := params.Spec
	resolveSpec(&spec)
	if err := validateSpec(spec); err != nil {
		return sdk.VMPlanResult{}, err
	}
	return sdk.VMPlanResult{
		Summary: fmt.Sprintf("hetzner: %s in %s (image=%s)", spec.SizeHint, spec.Region, spec.Image),
		// Cost estimation would need pricing API; punt for v1.
		EstimatedDurationSec: 60,
	}, nil
}

func validateSpec(spec sdk.VMSpec) error {
	if spec.RunID == "" || spec.VMKey == "" {
		return sdk.Errf(sdk.CatValidation, "hetzner.spec.missing_key",
			"run_id and vm_key are required")
	}
	if spec.Region == "" {
		return sdk.Errf(sdk.CatValidation, "hetzner.spec.missing_region",
			"region is required (set on VMSpec or plugin config)")
	}
	if spec.Image == "" {
		return sdk.Errf(sdk.CatValidation, "hetzner.spec.missing_image",
			"image is required")
	}
	if spec.SizeHint == "" {
		return sdk.Errf(sdk.CatValidation, "hetzner.spec.missing_size",
			"size_hint is required (e.g. cx22, cpx31)")
	}
	return nil
}

// requireClient returns a typed error if Initialize hasn't been called (or
// failed). Every method that touches the API must call this first.
func requireClient() error {
	if p.client == nil {
		return sdk.Errf(sdk.CatAuth,
			"hetzner.not_initialized",
			"plugin.initialize has not been called successfully (check HCLOUD_TOKEN)")
	}
	return nil
}

// findByLabels locates a server previously created for this (run_id, vm_key).
func findByLabels(ctx context.Context, runID, vmKey string) (*hcloud.Server, error) {
	selector := fmt.Sprintf("%s=%s,%s=%s", labelRunID, runID, labelVMKey, vmKey)
	servers, err := p.client.Server.AllWithOpts(ctx, hcloud.ServerListOpts{
		ListOpts: hcloud.ListOpts{LabelSelector: selector},
	})
	if err != nil {
		return nil, err
	}
	if len(servers) == 0 {
		return nil, nil
	}
	return servers[0], nil
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
	emit.Progress("lookup", 5, "checking for existing VM")
	// Idempotent hit: return existing.
	if existing, err := findByLabels(ctx, spec.RunID, spec.VMKey); err != nil {
		return sdk.VMCreateResult{}, sdk.Errf(sdk.CatInternal,
			"hetzner.list_failed", "listing existing servers: %v", err)
	} else if existing != nil {
		emit.Log("info", "reusing existing server", map[string]any{"server_id": existing.ID})
		return serverToCreateResult(existing), nil
	}

	// Resolve image + location + type.
	image, _, err := p.client.Image.GetByName(ctx, spec.Image)
	if err != nil {
		return sdk.VMCreateResult{}, sdk.Errf(sdk.CatProviderUnavailable,
			"hetzner.api.image_lookup_failed", "%v", err)
	}
	if image == nil {
		return sdk.VMCreateResult{}, sdk.Errf(sdk.CatValidation,
			"hetzner.image.not_found", "image %q not found", spec.Image)
	}
	loc, _, err := p.client.Location.GetByName(ctx, spec.Region)
	if err != nil || loc == nil {
		return sdk.VMCreateResult{}, sdk.Errf(sdk.CatValidation,
			"hetzner.location.not_found", "location %q not found", spec.Region)
	}
	st, _, err := p.client.ServerType.GetByName(ctx, spec.SizeHint)
	if err != nil || st == nil {
		return sdk.VMCreateResult{}, sdk.Errf(sdk.CatValidation,
			"hetzner.server_type.not_found", "server type %q not found", spec.SizeHint)
	}

	// SSH keys.
	var sshKeys []*hcloud.SSHKey
	for _, pub := range spec.SSHKeys {
		key, err := ensureSSHKey(ctx, spec.RunID, pub)
		if err != nil {
			return sdk.VMCreateResult{}, err
		}
		sshKeys = append(sshKeys, key)
	}

	labels := map[string]string{
		labelRunID:   spec.RunID,
		labelVMKey:   spec.VMKey,
		labelManaged: "true",
	}
	for k, v := range spec.Tags {
		labels[sanitizeLabelKey(k)] = v
	}

	// Mint a Tailscale ephemeral auth key and compose cloud-init that installs
	// Tailscale and joins the tailnet on first boot. The orchestrator then
	// resolves this server by its tailnet hostname (lp-<vmKey>). Hetzner takes
	// raw cloud-config user-data (no base64).
	emit.Progress("tailscale", 15, "minting device auth key")
	tag := tailscaleTagForSpec(spec)
	tskey, err := mintTailscaleKey(ctx, p.cfg.Tailnet, tag)
	if err != nil {
		return sdk.VMCreateResult{}, err
	}
	userData := composeUserData(cloudInitInputs{
		Hostname:      hostnameFor(spec.VMKey),
		SSHKeys:       mergeSSHKeys(nil, spec.SSHKeys),
		TailscaleKey:  tskey,
		TailscaleTag:  tag,
		ExtraUserData: spec.UserData,
	})

	emit.Progress("create", 20, "requesting server")
	res, _, err := p.client.Server.Create(ctx, hcloud.ServerCreateOpts{
		Name:             hetznerName(spec),
		ServerType:       st,
		Image:            image,
		Location:         loc,
		SSHKeys:          sshKeys,
		UserData:         userData,
		Labels:           labels,
		StartAfterCreate: hcloud.Ptr(true),
	})
	if err != nil {
		// Hetzner prices a server type in more locations than it can currently
		// allocate in; a capacity mismatch surfaces as an opaque "unsupported
		// location for server type". Turn it into actionable guidance.
		if strings.Contains(err.Error(), "unsupported location") {
			if locs := availableLocationsFor(ctx, st); len(locs) > 0 {
				return sdk.VMCreateResult{}, sdk.Errf(sdk.CatProviderUnavailable,
					"hetzner.location.unavailable",
					"server type %s is not available in location %q; currently available in: %s",
					spec.SizeHint, spec.Region, strings.Join(locs, ", "))
			}
		}
		return sdk.VMCreateResult{}, sdk.Errf(sdk.CatProviderUnavailable,
			"hetzner.api.create_failed", "%v", err)
	}

	// Wait for the create action to complete (server allocated + started).
	if res.Action != nil {
		emit.Progress("create", 60, "waiting for boot")
		if err := waitAction(ctx, res.Action, 5*time.Minute); err != nil {
			return sdk.VMCreateResult{}, sdk.Errf(sdk.CatTimeout,
				"hetzner.action.create_timeout", "%v", err)
		}
	}

	fresh, _, err := p.client.Server.GetByID(ctx, res.Server.ID)
	if err != nil || fresh == nil {
		return sdk.VMCreateResult{}, sdk.Errf(sdk.CatInternal,
			"hetzner.api.refresh_failed", "%v", err)
	}
	emit.Progress("create", 100, "server ready")
	return serverToCreateResult(fresh), nil
}

func waitReady(ctx context.Context, params sdk.VMWaitReadyParams, emit sdk.Emitter) (sdk.VMWaitReadyResult, error) {
	if err := requireClient(); err != nil {
		return sdk.VMWaitReadyResult{}, err
	}
	// Hetzner reports "running" via server status; we don't SSH-probe in v1.
	// For a stricter check the launchpad orchestrator can add its own SSH poll.
	deadline := time.Now().Add(20 * time.Minute)
	for time.Now().Before(deadline) {
		server, _, err := p.client.Server.GetByID(ctx, mustParseID(params.VMID))
		if err != nil || server == nil {
			return sdk.VMWaitReadyResult{}, sdk.Errf(sdk.CatNotFound,
				"hetzner.server.get_failed", "%v", err)
		}
		if server.Status == hcloud.ServerStatusRunning {
			emit.Progress("wait_ready", 100, "running")
			return sdk.VMWaitReadyResult{Ready: true}, nil
		}
		emit.Progress("wait_ready", 50, "server status: "+string(server.Status))
		select {
		case <-ctx.Done():
			return sdk.VMWaitReadyResult{}, ctx.Err()
		case <-time.After(5 * time.Second):
		}
	}
	return sdk.VMWaitReadyResult{}, sdk.Errf(sdk.CatTimeout,
		"hetzner.wait_ready.timeout", "server did not reach running within 20m")
}

func destroy(ctx context.Context, params sdk.VMDestroyParams, emit sdk.Emitter) (sdk.VMDestroyResult, error) {
	if err := requireClient(); err != nil {
		return sdk.VMDestroyResult{}, err
	}
	var server *hcloud.Server
	if params.VMID != "" {
		s, _, err := p.client.Server.GetByID(ctx, mustParseID(params.VMID))
		if err != nil {
			return sdk.VMDestroyResult{}, sdk.Errf(sdk.CatInternal,
				"hetzner.get_failed", "%v", err)
		}
		server = s
	}
	if server == nil {
		// Fall back to label lookup (idempotent cleanup after state loss).
		s, err := findByLabels(ctx, params.RunID, params.VMKey)
		if err != nil {
			return sdk.VMDestroyResult{}, sdk.Errf(sdk.CatInternal,
				"hetzner.list_failed", "%v", err)
		}
		server = s
	}
	if server == nil {
		return sdk.VMDestroyResult{Destroyed: false}, nil
	}
	emit.Progress("destroy", 50, "deleting server")
	_, _, err := p.client.Server.DeleteWithResult(ctx, server)
	if err != nil {
		return sdk.VMDestroyResult{}, sdk.Errf(sdk.CatProviderUnavailable,
			"hetzner.delete_failed", "%v", err)
	}
	return sdk.VMDestroyResult{Destroyed: true}, nil
}

func inspect(ctx context.Context, params sdk.VMInspectParams, emit sdk.Emitter) (sdk.VMInspectResult, error) {
	if err := requireClient(); err != nil {
		return sdk.VMInspectResult{}, err
	}
	var server *hcloud.Server
	if params.VMID != "" {
		s, _, err := p.client.Server.GetByID(ctx, mustParseID(params.VMID))
		if err != nil {
			return sdk.VMInspectResult{}, err
		}
		server = s
	}
	if server == nil {
		s, err := findByLabels(ctx, params.RunID, params.VMKey)
		if err != nil {
			return sdk.VMInspectResult{}, err
		}
		server = s
	}
	if server == nil {
		return sdk.VMInspectResult{Exists: false}, nil
	}
	return sdk.VMInspectResult{
		Exists:  true,
		VMID:    fmt.Sprintf("%d", server.ID),
		State:   mapServerStatus(server.Status),
		IPv4:    ipv4Of(server),
		IPv6:    ipv6Of(server),
		SSHUser: "root",
	}, nil
}

// ------------------------------------------------------------------
// helpers
// ------------------------------------------------------------------

func serverToCreateResult(server *hcloud.Server) sdk.VMCreateResult {
	return sdk.VMCreateResult{
		VMID:        fmt.Sprintf("%d", server.ID),
		IPv4:        ipv4Of(server),
		IPv6:        ipv6Of(server),
		SSHUser:     "root",
		SSHPort:     22,
		ProviderURL: fmt.Sprintf("https://console.hetzner.cloud/projects/-/servers/%d", server.ID),
		Metadata: map[string]string{
			"provider":       "hetzner",
			"datacenter":     dcName(server),
			"server_type":    stName(server),
		},
	}
}

func ipv4Of(s *hcloud.Server) string {
	if s == nil || s.PublicNet.IPv4.IP == nil {
		return ""
	}
	return s.PublicNet.IPv4.IP.String()
}
func ipv6Of(s *hcloud.Server) string {
	if s == nil || s.PublicNet.IPv6.IP == nil {
		return ""
	}
	return s.PublicNet.IPv6.IP.String()
}
func dcName(s *hcloud.Server) string {
	if s.Datacenter == nil {
		return ""
	}
	return s.Datacenter.Name
}
func stName(s *hcloud.Server) string {
	if s.ServerType == nil {
		return ""
	}
	return s.ServerType.Name
}

func mapServerStatus(s hcloud.ServerStatus) string {
	switch s {
	case hcloud.ServerStatusRunning:
		return "running"
	case hcloud.ServerStatusStarting, hcloud.ServerStatusInitializing:
		return "starting"
	case hcloud.ServerStatusOff, hcloud.ServerStatusStopping:
		return "stopped"
	case hcloud.ServerStatusDeleting:
		return "destroying"
	default:
		return "unknown"
	}
}

// availableLocationsFor returns the location names where the given server type
// can currently be created. Hetzner's datacenters endpoint (ServerTypes.Available)
// is the real availability signal — a type may be priced in a location yet be out
// of capacity there.
func availableLocationsFor(ctx context.Context, st *hcloud.ServerType) []string {
	if st == nil {
		return nil
	}
	dcs, err := p.client.Datacenter.All(ctx)
	if err != nil {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, dc := range dcs {
		if dc.Location == nil || seen[dc.Location.Name] {
			continue
		}
		for _, a := range dc.ServerTypes.Available {
			if a.ID == st.ID {
				seen[dc.Location.Name] = true
				out = append(out, dc.Location.Name)
				break
			}
		}
	}
	sort.Strings(out)
	return out
}

func hetznerName(spec sdk.VMSpec) string {
	// Hetzner names must match a specific regex; sanitize.
	n := spec.Name
	if n == "" {
		n = spec.VMKey
	}
	n = strings.ToLower(n)
	// Replace anything non-alnum/dash with '-'.
	var b strings.Builder
	for _, r := range n {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
			b.WriteRune(r)
		} else {
			b.WriteRune('-')
		}
	}
	name := b.String()
	if len(name) > 32 {
		name = name[:32]
	}
	// Append a suffix of run_id's last 6 chars for uniqueness across runs.
	suffix := spec.RunID
	if len(suffix) > 6 {
		suffix = suffix[len(suffix)-6:]
	}
	return strings.TrimRight(name, "-") + "-" + strings.ToLower(suffix)
}

func mustParseID(s string) int64 {
	var id int64
	_, _ = fmt.Sscanf(s, "%d", &id)
	return id
}

func waitAction(ctx context.Context, action *hcloud.Action, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if action.Status == hcloud.ActionStatusSuccess {
			return nil
		}
		if action.Status == hcloud.ActionStatusError {
			if action.ErrorMessage != "" {
				return fmt.Errorf("action error: %s", action.ErrorMessage)
			}
			return fmt.Errorf("action failed (code=%s)", action.ErrorCode)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
		}
		fresh, _, err := p.client.Action.GetByID(ctx, action.ID)
		if err != nil {
			return err
		}
		action = fresh
	}
	return fmt.Errorf("action %d did not complete within %s", action.ID, timeout)
}

// ensureSSHKey uploads a public key if not present, returns the hcloud key.
func ensureSSHKey(ctx context.Context, runID, pub string) (*hcloud.SSHKey, error) {
	// Look up by content fingerprint via label — cheapest approach.
	pub = strings.TrimSpace(pub)
	// Hetzner accepts direct SSH key content in the create call, but requires
	// pre-uploaded keys as references. We list-and-match by public_key.
	keys, err := p.client.SSHKey.All(ctx)
	if err != nil {
		return nil, sdk.Errf(sdk.CatProviderUnavailable,
			"hetzner.ssh_key.list_failed", "%v", err)
	}
	for _, k := range keys {
		if strings.TrimSpace(k.PublicKey) == pub {
			return k, nil
		}
	}
	// Upload.
	name := fmt.Sprintf("launchpad-%s", runID)
	if len(name) > 40 {
		name = name[:40]
	}
	created, _, err := p.client.SSHKey.Create(ctx, hcloud.SSHKeyCreateOpts{
		Name:      name,
		PublicKey: pub,
		Labels:    map[string]string{labelRunID: runID, labelManaged: "true"},
	})
	if err != nil {
		return nil, sdk.Errf(sdk.CatProviderUnavailable,
			"hetzner.ssh_key.upload_failed", "%v", err)
	}
	return created, nil
}

func sanitizeLabelKey(k string) string {
	// Hetzner labels are strict; sanitize aggressively.
	k = strings.ToLower(k)
	if len(k) > 63 {
		k = k[:63]
	}
	return k
}

// --- Tailscale join + cloud-init composition -------------------------------
// Ported from the qemu-family and aws plugins: cloud VMs join the tailnet on
// first boot via a plugin-minted ephemeral auth key baked into cloud-init. The
// orchestrator discovers each VM by its tailnet hostname (lp-<vmKey>) rather
// than a public IP.

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
		return "", sdk.Errf(sdk.CatValidation, "hetzner.tailscale.no_tailnet", "tailnet is empty")
	}
	if tsAPIKey == "" {
		return "", sdk.Errf(sdk.CatAuth, "hetzner.tailscale.no_api_key",
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
		return "", sdk.Errf(sdk.CatProviderUnavailable, "hetzner.tailscale.api_error", "%v", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return "", sdk.Errf(sdk.CatAuth, "hetzner.tailscale.api_status",
			"tailscale API %d: %s", resp.StatusCode, string(raw))
	}
	var out struct {
		Key string `json:"key"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return "", err
	}
	if out.Key == "" {
		return "", sdk.Errf(sdk.CatInternal, "hetzner.tailscale.key_missing",
			"no key in tailscale response: %s", string(raw))
	}
	return out.Key, nil
}

// tailscaleTagForSpec derives the advertised tag from the VM role/slug so the
// tailnet ACL can group MSSP and tenant devices. Matches the qemu/vmware/aws
// plugins.
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
