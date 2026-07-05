// launchpad-plugin-virtualbox provisions VMs on a remote host over SSH by
// driving VirtualBox's VBoxManage CLI with a cloud-init seed ISO. The VMs join
// a Tailscale tailnet at first boot, and the plugin returns the assigned
// Tailscale IPv4 as the primary contact address.
//
// The cached Ubuntu cloud image (qcow2) is converted to a VDI with qemu-img,
// then a VM is created via `VBoxManage createvm`, given memory/cpus and a NAT
// NIC, has the VDI attached on a SATA controller and the cloud-init seed.iso
// attached as a DVD on an IDE controller, and is booted headless with
// `VBoxManage startvm --type headless`.
//
// Config (params.config):
//   ssh_host:     ops@100.102.223.8    (Tailscale IP or hostname)
//   ssh_port:     22                    (optional)
//   base_image:   /home/ops/noble.img   (backing store, cloud-init-ready)
//   work_dir:     /home/ops/lp-vms      (per-run subdirs created here)
//   tailnet:      tail6397c.ts.net      (tailnet name for hostname suffix)
//   cpu:          4                     (default vCPUs)
//   memory_mb:    8192                  (default memory)
//   disk_gb:      60                    (grown from base image, default)
//   tag_prefix:   ""                    (optional prefix on advertised tags)
//   ssh_keys:     ["ssh-ed25519 ..."]  (authorized keys added to ops user)
//
// Env:
//   TAILSCALE_API_KEY  (from https://login.tailscale.com/admin/settings/keys)
//
// Every VM ends up on the tailnet as `lp-<vm_key>.<tailnet>` with either
// `tag:mssp` (Role=mssp) or `tag:tenant-<slug>` (Role=tenant, from spec.tags).
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
	"strings"
	"time"

	sdk "github.com/soctalk/launchpad-sdk-go"
	"golang.org/x/crypto/ssh"
)

const (
	name    = "virtualbox"
	version = "0.1.0"
)

type config struct {
	SSHHost string `json:"ssh_host"`
	SSHPort int    `json:"ssh_port,omitempty"`

	// Cloud base image. Either supply a pre-staged local path (BaseImage) OR
	// let the plugin download from a public URL (BaseImageURL) and cache it
	// on the target host. If neither is set, defaults to Ubuntu Noble.
	BaseImage       string `json:"base_image,omitempty"`
	BaseImageURL    string `json:"base_image_url,omitempty"`
	BaseImageSHA256 string `json:"base_image_sha256,omitempty"`
	ImageCacheDir   string `json:"image_cache_dir,omitempty"`

	WorkDir   string   `json:"work_dir"`
	Tailnet   string   `json:"tailnet"`
	CPU       int      `json:"cpu,omitempty"`
	MemoryMB  int      `json:"memory_mb,omitempty"`
	DiskGB    int      `json:"disk_gb,omitempty"`
	TagPrefix string   `json:"tag_prefix,omitempty"`
	SSHKeys   []string `json:"ssh_keys,omitempty"`
}

// defaultBaseImageURL is Canonical's current Ubuntu Noble amd64 cloud image.
// It is rebuilt periodically; pin base_image_sha256 in config to freeze.
const defaultBaseImageURL = "https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img"

var cfg config
var sshClient *ssh.Client

// tsAPIKey is the Tailscale API key. Set once in initialize.
var tsAPIKey string

func main() {
	err := sdk.Serve(sdk.Plugin{
		Name:    name,
		Version: version,

		AllowedEnvVars: []string{"TAILSCALE_API_KEY", "SSH_AUTH_SOCK", "HOME"},

		ConfigSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"ssh_host":            map[string]any{"type": "string"},
				"ssh_port":            map[string]any{"type": "integer", "minimum": 1, "maximum": 65535},
				"base_image":          map[string]any{"type": "string"},
				"base_image_url":      map[string]any{"type": "string"},
				"base_image_sha256":   map[string]any{"type": "string"},
				"image_cache_dir":     map[string]any{"type": "string"},
				"work_dir":            map[string]any{"type": "string"},
				"tailnet":             map[string]any{"type": "string"},
				"cpu":                 map[string]any{"type": "integer", "minimum": 1},
				"memory_mb":           map[string]any{"type": "integer", "minimum": 512},
				"disk_gb":             map[string]any{"type": "integer", "minimum": 5},
				"tag_prefix":          map[string]any{"type": "string"},
				"ssh_keys":            map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
			},
			"required": []string{"ssh_host", "work_dir", "tailnet"},
		},

		Initialize: initialize,
		Plan:       plan,
		Create:     create,
		WaitReady:  waitReady,
		Destroy:    destroy,
		Inspect:    inspect,
		Shutdown:   shutdown,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "virtualbox plugin:", err)
		os.Exit(1)
	}
}

func initialize(ctx context.Context, params sdk.InitializeParams) (sdk.InitializeResult, error) {
	// Unmarshal typed config.
	if raw, err := json.Marshal(params.Config); err == nil {
		_ = json.Unmarshal(raw, &cfg)
	}
	if cfg.SSHHost == "" || cfg.WorkDir == "" || cfg.Tailnet == "" {
		return sdk.InitializeResult{}, sdk.Errf(sdk.CatValidation,
			"virtualbox.config.incomplete",
			"ssh_host, work_dir, tailnet are all required")
	}
	// Base-image source: pre-staged path OR URL to download. Default to
	// Ubuntu Noble amd64 cloud image if neither is set.
	if cfg.BaseImage == "" && cfg.BaseImageURL == "" {
		cfg.BaseImageURL = defaultBaseImageURL
	}
	if cfg.SSHPort == 0 {
		cfg.SSHPort = 22
	}
	if cfg.CPU == 0 {
		cfg.CPU = 4
	}
	if cfg.MemoryMB == 0 {
		cfg.MemoryMB = 8192
	}
	if cfg.DiskGB == 0 {
		cfg.DiskGB = 60
	}
	tsAPIKey = os.Getenv("TAILSCALE_API_KEY")
	if tsAPIKey == "" {
		return sdk.InitializeResult{}, sdk.Errf(sdk.CatAuth,
			"virtualbox.tailscale.missing_api_key",
			"TAILSCALE_API_KEY is required for minting device auth keys")
	}
	// Open SSH to the host and hold it for the plugin's lifetime.
	c, err := dialSSH(cfg.SSHHost, cfg.SSHPort)
	if err != nil {
		return sdk.InitializeResult{}, sdk.Errf(sdk.CatProviderUnavailable,
			"virtualbox.ssh.unreachable",
			"cannot SSH to %s: %v (agent-loaded key expected)", cfg.SSHHost, err)
	}
	sshClient = c
	// Quick probe: VirtualBox CLI plus seed-ISO + qcow2->vdi tooling. curl is
	// only needed when we download the cloud image from a URL rather than
	// using a pre-staged local path.
	probe := "which VBoxManage && which genisoimage && which qemu-img"
	if cfg.BaseImage == "" {
		probe += " && which curl"
	}
	if _, err := runOverSSH(ctx, sshClient, probe); err != nil {
		return sdk.InitializeResult{}, sdk.Errf(sdk.CatValidation,
			"virtualbox.host.missing_tools",
			"host is missing VBoxManage / genisoimage / qemu-img / curl: %v", err)
	}
	// Ensure work_dir exists.
	if _, err := runOverSSH(ctx, sshClient, "mkdir -p "+shellEscape(cfg.WorkDir)); err != nil {
		return sdk.InitializeResult{}, err
	}
	return sdk.InitializeResult{Ready: true}, nil
}

func shutdown(ctx context.Context) error {
	if sshClient != nil {
		_ = sshClient.Close()
		sshClient = nil
	}
	return nil
}

func plan(ctx context.Context, params sdk.VMPlanParams, emit sdk.Emitter) (sdk.VMPlanResult, error) {
	return sdk.VMPlanResult{
		Summary: fmt.Sprintf("virtualbox: %s on %s (%dvCPU/%dMB, tailscale hostname lp-%s)",
			params.Spec.Name, cfg.SSHHost, cfg.CPU, cfg.MemoryMB, params.Spec.VMKey),
		EstimatedDurationSec: 180,
	}, nil
}

// tailscaleTagForSpec returns the tag this VM will advertise on the tailnet.
// Role=mssp → tag:mssp, Role=tenant → tag:tenant-<slug>. Falls back to
// tag:lp-<vm_key> if neither is set.
func tailscaleTagForSpec(spec sdk.VMSpec) string {
	role := spec.Tags["role"]
	slug := spec.Tags["tenant_slug"]
	prefix := cfg.TagPrefix
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

// mergeSSHKeys returns the union of provider-config and spec-level SSH keys,
// de-duplicated, preserving order (config keys first).
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

func vmWorkDir(runID, vmKey string) string {
	return cfg.WorkDir + "/" + runID + "/" + vmKey
}

// vboxManage is the VirtualBox CLI. Runs as the SSH user (no sudo); NAT
// networking matches the tailnet-overlay model.
const vboxManage = "VBoxManage"

// vmName is the VirtualBox VM name for a VM — unique per run so repeated runs
// don't collide.
func vmName(runID, vmKey string) string {
	return "lp-" + sanitizeHostname(runID+"-"+vmKey)
}

// vmExists reports whether a VM with this name is registered (any state).
func vmExists(ctx context.Context, vm string) bool {
	_, err := runOverSSH(ctx, sshClient,
		vboxManage+" showvminfo "+shellEscape(vm)+" --machinereadable >/dev/null 2>&1")
	return err == nil
}

// vmRunning reports whether the VM is registered and its VMState is "running".
func vmRunning(ctx context.Context, vm string) bool {
	out, err := runOverSSH(ctx, sshClient,
		vboxManage+" showvminfo "+shellEscape(vm)+" --machinereadable 2>/dev/null")
	return err == nil && strings.Contains(out, `VMState="running"`)
}

func create(ctx context.Context, params sdk.VMCreateParams, emit sdk.Emitter) (sdk.VMCreateResult, error) {
	if sshClient == nil {
		return sdk.VMCreateResult{}, sdk.Errf(sdk.CatAuth,
			"virtualbox.not_initialized",
			"plugin.initialize has not been called successfully")
	}
	spec := params.Spec

	work := vmWorkDir(spec.RunID, spec.VMKey)
	vm := vmName(spec.RunID, spec.VMKey)

	// Idempotency: reuse only when the VM is running AND its tailnet device is
	// online. A VM whose device was revoked is unreachable forever (NAT means
	// the tailnet is the only path in), so tear it down + re-provision.
	emit.Progress("lookup", 3, "checking for existing VM")
	if vmExists(ctx, vm) {
		if vmRunning(ctx, vm) {
			d, _ := findTailscaleDevice(ctx, cfg.Tailnet, hostnameFor(spec.VMKey))
			if d != nil && d.online() {
				emit.Log("info", "reusing running VirtualBox VM (tailnet device online)",
					map[string]any{"vm_name": vm, "ipv4": d.primaryIPv4()})
				return currentResult(ctx, spec, emit)
			}
			emit.Log("warn", "existing VirtualBox VM has no live tailnet device — tearing down and re-provisioning",
				map[string]any{"vm_name": vm})
		}
		// Tear down any existing VM (running or stopped) so createvm below
		// starts clean. poweroff of a stopped VM errors harmlessly.
		_, _ = runOverSSH(ctx, sshClient,
			vboxManage+" controlvm "+shellEscape(vm)+" poweroff 2>/dev/null; "+
				vboxManage+" unregistervm "+shellEscape(vm)+" --delete 2>/dev/null || true")
		_, _ = runOverSSH(ctx, sshClient,
			fmt.Sprintf("[ -d %s ] && mv %s /tmp/lp-stale-%s-$(date +%%s) || true",
				shellEscape(work), shellEscape(work), spec.VMKey))
		if d, _ := findTailscaleDevice(ctx, cfg.Tailnet, hostnameFor(spec.VMKey)); d != nil {
			_ = deleteTailscaleDevice(ctx, d.ID)
		}
	}

	// Prepare work dir.
	emit.Progress("prepare", 10, "creating work dir on host")
	if _, err := runOverSSH(ctx, sshClient, "mkdir -p "+shellEscape(work)); err != nil {
		return sdk.VMCreateResult{}, err
	}

	// Ensure the base cloud image is present on the target host. Downloads
	// once and caches; subsequent VMs on the same host reuse.
	baseImagePath, err := ensureBaseImage(ctx, sshClient, emit)
	if err != nil {
		return sdk.VMCreateResult{}, err
	}

	// Mint a Tailscale ephemeral auth key.
	emit.Progress("tailscale", 20, "minting device auth key")
	tag := tailscaleTagForSpec(spec)
	tskey, err := mintTailscaleKey(ctx, cfg.Tailnet, tag)
	if err != nil {
		return sdk.VMCreateResult{}, err
	}

	// Compose cloud-init user-data. Authorize both provider-config keys and
	// launchpad-level keys (spec.SSHKeys) so a run that sets ssh_keys only at
	// the top level still boots the ops user with the operator's key.
	hostname := hostnameFor(spec.VMKey)
	userData := composeUserData(cloudInitInputs{
		Hostname:       hostname,
		SSHKeys:        mergeSSHKeys(cfg.SSHKeys, spec.SSHKeys),
		TailscaleKey:   tskey,
		TailscaleTag:   tag,
		ExtraUserData:  spec.UserData,
	})
	metaData := fmt.Sprintf("instance-id: lp-%s\nlocal-hostname: %s\n", spec.VMKey, hostname)

	// Upload user-data and meta-data.
	emit.Progress("cloud_init", 35, "writing user-data + meta-data")
	if err := writeRemoteFile(sshClient, work+"/user-data", []byte(userData)); err != nil {
		return sdk.VMCreateResult{}, err
	}
	if err := writeRemoteFile(sshClient, work+"/meta-data", []byte(metaData)); err != nil {
		return sdk.VMCreateResult{}, err
	}
	// Build seed.iso on the host.
	if _, err := runOverSSH(ctx, sshClient,
		"cd "+shellEscape(work)+" && genisoimage -output seed.iso -volid cidata -joliet -rock user-data meta-data"); err != nil {
		return sdk.VMCreateResult{}, err
	}

	// Convert the cached qcow2 base image to a VDI for VirtualBox, then grow it
	// to the requested size (the cloud image auto-expands its rootfs on boot).
	emit.Progress("disk", 50, "converting base image to VDI")
	vdi := work + "/disk.vdi"
	if out, err := runOverSSH(ctx, sshClient,
		fmt.Sprintf("qemu-img convert -O vdi %s %s",
			shellEscape(baseImagePath), shellEscape(vdi))); err != nil {
		return sdk.VMCreateResult{}, sdk.Errf(sdk.CatInternal,
			"virtualbox.qemu-img.convert_failed", "%v: %s", err, out)
	}
	if out, err := runOverSSH(ctx, sshClient,
		fmt.Sprintf("%s modifymedium disk %s --resize %d",
			vboxManage, shellEscape(vdi), cfg.DiskGB*1024)); err != nil {
		return sdk.VMCreateResult{}, sdk.Errf(sdk.CatInternal,
			"virtualbox.modifymedium.resize_failed", "%v: %s", err, out)
	}

	// Create + configure the VM.
	//
	// Networking: NAT so the guest reaches the internet to install Tailscale +
	// apt. No port forwards needed — Tailscale becomes the overlay path in.
	// SATA controller holds the boot VDI; IDE controller holds the cloud-init
	// seed.iso as a DVD.
	emit.Progress("define", 65, "creating + configuring VM")
	define := fmt.Sprintf(`set -e
%s createvm --name %s --ostype Ubuntu_64 --register
%s modifyvm %s --memory %d --cpus %d --nic1 nat --natdnshostresolver1 on
%s storagectl %s --name SATA --add sata --controller IntelAhci --portcount 1
%s storageattach %s --storagectl SATA --port 0 --device 0 --type hdd --medium %s
%s storagectl %s --name IDE --add ide
%s storageattach %s --storagectl IDE --port 0 --device 0 --type dvddrive --medium %s`,
		vboxManage, shellEscape(vm),
		vboxManage, shellEscape(vm), cfg.MemoryMB, cfg.CPU,
		vboxManage, shellEscape(vm),
		vboxManage, shellEscape(vm), shellEscape(vdi),
		vboxManage, shellEscape(vm),
		vboxManage, shellEscape(vm), shellEscape(work+"/seed.iso"),
	)
	if out, err := runOverSSH(ctx, sshClient, define); err != nil {
		return sdk.VMCreateResult{}, sdk.Errf(sdk.CatInternal,
			"virtualbox.createvm.failed", "%v: %s", err, out)
	}

	// Boot headless.
	emit.Progress("boot", 85, "starting VM headless")
	if out, err := runOverSSH(ctx, sshClient,
		vboxManage+" startvm "+shellEscape(vm)+" --type headless"); err != nil {
		return sdk.VMCreateResult{}, sdk.Errf(sdk.CatInternal,
			"virtualbox.startvm.failed", "%v: %s", err, out)
	}

	emit.Progress("boot", 95, "VM started; tailscale + cloud-init running inside")
	return sdk.VMCreateResult{
		VMID:    spec.RunID + "/" + spec.VMKey,
		SSHUser: "ops",
		SSHPort: 22,
		Metadata: map[string]string{
			"provider":           "virtualbox",
			"host":               cfg.SSHHost,
			"vm_name":            vm,
			"work_dir":           work,
			"tailscale_hostname": hostname,
			"tailscale_tag":      tag,
		},
	}, nil
}

func waitReady(ctx context.Context, params sdk.VMWaitReadyParams, emit sdk.Emitter) (sdk.VMWaitReadyResult, error) {
	if tsAPIKey == "" {
		return sdk.VMWaitReadyResult{}, sdk.Errf(sdk.CatAuth,
			"virtualbox.not_initialized",
			"plugin.initialize has not been called successfully")
	}
	// Poll Tailscale API for a device matching lp-<vm_key> and wait until it's Online.
	hostname := hostnameFor(params.VMKey)
	deadline := time.Now().Add(20 * time.Minute)
	for time.Now().Before(deadline) {
		device, err := findTailscaleDevice(ctx, cfg.Tailnet, hostname)
		if err != nil {
			emit.Log("debug", "tailscale API error", map[string]any{"err": err.Error()})
		}
		if device != nil {
			online := "yes"
			if !device.online() {
				online = "no"
			}
			emit.Progress("wait_ready", 60, fmt.Sprintf("tailscale device found; online=%s", online))
			if device.online() {
				v4, v6 := "", ""
				for _, a := range device.Addresses {
					if strings.Contains(a, ":") {
						if v6 == "" {
							v6 = a
						}
					} else if v4 == "" {
						v4 = a
					}
				}
				return sdk.VMWaitReadyResult{Ready: true, IPv4: v4, IPv6: v6}, nil
			}
		}
		select {
		case <-ctx.Done():
			return sdk.VMWaitReadyResult{}, ctx.Err()
		case <-time.After(6 * time.Second):
		}
	}
	return sdk.VMWaitReadyResult{}, sdk.Errf(sdk.CatTimeout,
		"virtualbox.wait_ready.timeout",
		"tailscale device %s did not come online within 20m", hostname)
}

func destroy(ctx context.Context, params sdk.VMDestroyParams, emit sdk.Emitter) (sdk.VMDestroyResult, error) {
	if sshClient == nil {
		return sdk.VMDestroyResult{}, sdk.Errf(sdk.CatAuth,
			"virtualbox.not_initialized",
			"plugin.initialize has not been called successfully")
	}
	work := vmWorkDir(params.RunID, params.VMKey)
	vm := vmName(params.RunID, params.VMKey)

	// Track whether we did any real work. Destroyed=false means "nothing to
	// destroy" so callers can treat repeated destroys as idempotent no-ops.
	didWork := false

	emit.Progress("destroy", 30, "powering off + unregistering VM")
	// controlvm poweroff stops a running VM (rc 0); unregistervm --delete
	// removes its config + disks. Echo markers tell us whether the VM existed.
	out, _ := runOverSSH(ctx, sshClient, fmt.Sprintf(
		"if %s controlvm %s poweroff 2>/dev/null; then echo poweredoff; fi; if %s unregistervm %s --delete 2>/dev/null; then echo unregistered; fi",
		vboxManage, shellEscape(vm), vboxManage, shellEscape(vm)))
	if strings.Contains(out, "poweredoff") || strings.Contains(out, "unregistered") {
		didWork = true
	}

	emit.Progress("destroy", 60, "removing work dir")
	// Move aside rather than rm-rf (reversible for forensics).
	if out, _ := runOverSSH(ctx, sshClient,
		fmt.Sprintf("[ -d %s ] && mv %s /tmp/lp-destroyed-%s-$(date +%%s) && echo moved || true",
			shellEscape(work), shellEscape(work), params.VMKey)); strings.Contains(out, "moved") {
		didWork = true
	}

	emit.Progress("destroy", 85, "revoking tailscale device")
	hostname := hostnameFor(params.VMKey)
	if device, _ := findTailscaleDevice(ctx, cfg.Tailnet, hostname); device != nil {
		if err := deleteTailscaleDevice(ctx, device.ID); err == nil {
			didWork = true
		}
	}
	return sdk.VMDestroyResult{Destroyed: didWork}, nil
}

func inspect(ctx context.Context, params sdk.VMInspectParams, emit sdk.Emitter) (sdk.VMInspectResult, error) {
	if sshClient == nil {
		return sdk.VMInspectResult{Exists: false}, nil
	}
	vm := vmName(params.RunID, params.VMKey)
	alive := vmRunning(ctx, vm)
	hostname := hostnameFor(params.VMKey)
	ipv4 := ""
	state := "unknown"
	if device, _ := findTailscaleDevice(ctx, cfg.Tailnet, hostname); device != nil {
		ipv4 = device.primaryIPv4()
		if device.online() {
			state = "running"
		} else {
			state = "stopped"
		}
	} else if alive {
		state = "starting"
	}
	return sdk.VMInspectResult{
		Exists:  alive || ipv4 != "",
		VMID:    params.RunID + "/" + params.VMKey,
		State:   state,
		IPv4:    ipv4,
		SSHUser: "ops",
	}, nil
}

// currentResult builds a VMCreateResult for an existing running VM by
// checking tailscale for its IP. Called during idempotent reuse.
func currentResult(ctx context.Context, spec sdk.VMSpec, emit sdk.Emitter) (sdk.VMCreateResult, error) {
	res := sdk.VMCreateResult{
		VMID:    spec.RunID + "/" + spec.VMKey,
		SSHUser: "ops",
		SSHPort: 22,
		Metadata: map[string]string{
			"provider":           "virtualbox",
			"host":               cfg.SSHHost,
			"vm_name":            vmName(spec.RunID, spec.VMKey),
			"tailscale_hostname": hostnameFor(spec.VMKey),
		},
	}
	if d, _ := findTailscaleDevice(ctx, cfg.Tailnet, hostnameFor(spec.VMKey)); d != nil {
		res.IPv4 = d.primaryIPv4()
	}
	return res, nil
}

// ------------------------------------------------------------------
// cloud-init user-data assembly
// ------------------------------------------------------------------

type cloudInitInputs struct {
	Hostname      string
	SSHKeys       []string
	TailscaleKey  string
	TailscaleTag  string
	ExtraUserData string
}

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
	// Install-then-join, each retried: on VirtualBox the NAT stack settles
	// slower than qemu's SLIRP, so a single-shot `install.sh` may not have
	// finished when `tailscale up` runs (yielding "tailscale: not found").
	// Retry the install until the binary exists, then retry the join.
	fmt.Fprintf(&b,
		"  - 'for i in $(seq 1 40); do command -v tailscale >/dev/null 2>&1 && break; curl -fsSL https://tailscale.com/install.sh | sh; sleep 5; done; "+
			"for i in $(seq 1 40); do tailscale up --auth-key=%s --advertise-tags=%s --hostname=%s && break; sleep 5; done'\n",
		in.TailscaleKey, in.TailscaleTag, in.Hostname)
	if in.ExtraUserData != "" {
		b.WriteString("write_files:\n")
		b.WriteString("  - path: /etc/launchpad/user-extra.sh\n")
		b.WriteString("    permissions: '0755'\n")
		b.WriteString("    content: |\n")
		for _, line := range strings.Split(in.ExtraUserData, "\n") {
			fmt.Fprintf(&b, "      %s\n", line)
		}
		b.WriteString("  - path: /etc/systemd/system/lp-user-extra.service\n")
		b.WriteString("    content: |\n")
		b.WriteString("      [Unit]\n")
		b.WriteString("      Description=Launchpad user-extra bootstrap\n")
		b.WriteString("      After=network-online.target\n")
		b.WriteString("      Wants=network-online.target\n")
		b.WriteString("      [Service]\n")
		b.WriteString("      Type=oneshot\n")
		b.WriteString("      ExecStart=/etc/launchpad/user-extra.sh\n")
		b.WriteString("      RemainAfterExit=yes\n")
		b.WriteString("      [Install]\n")
		b.WriteString("      WantedBy=multi-user.target\n")
		b.WriteString("  - path: /etc/launchpad/enable.sh\n")
		b.WriteString("    permissions: '0755'\n")
		b.WriteString("    content: |\n")
		b.WriteString("      #!/bin/bash\n")
		b.WriteString("      systemctl daemon-reload\n")
		b.WriteString("      systemctl enable --now lp-user-extra.service\n")
		b.WriteString("  - path: /etc/launchpad/marker\n")
		b.WriteString("    content: ready\n")
		b.WriteString("runcmd:\n")
		b.WriteString("  - /etc/launchpad/enable.sh\n")
	}
	return b.String()
}

// ------------------------------------------------------------------
// SSH helpers
// ------------------------------------------------------------------

func dialSSH(userHost string, port int) (*ssh.Client, error) {
	user := "root"
	host := userHost
	if i := strings.IndexByte(userHost, '@'); i >= 0 {
		user, host = userHost[:i], userHost[i+1:]
	}
	// Rely on the operator's ssh-agent for authentication. Explicit
	// credential handling is out of scope for the plugin.
	// (Callers should have SSH_AUTH_SOCK populated.)
	sock := os.Getenv("SSH_AUTH_SOCK")
	if sock == "" {
		return nil, fmt.Errorf("SSH_AUTH_SOCK is not set; add key with `ssh-add` first")
	}
	agentConn, err := netDial("unix", sock)
	if err != nil {
		return nil, fmt.Errorf("dial ssh-agent: %w", err)
	}
	agentCli := newAgentClient(agentConn)
	signers, err := agentCli.Signers()
	if err != nil {
		return nil, fmt.Errorf("ssh-agent signers: %w", err)
	}
	cfg := &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signers...)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         15 * time.Second,
	}
	return ssh.Dial("tcp", fmt.Sprintf("%s:%d", host, port), cfg)
}

// runOverSSH runs a command on the remote host and returns its combined output.
func runOverSSH(ctx context.Context, c *ssh.Client, cmd string) (string, error) {
	sess, err := c.NewSession()
	if err != nil {
		return "", err
	}
	defer sess.Close()
	// Wire stdin/stdout/stderr into a single buffer.
	var buf bytes.Buffer
	sess.Stdout = &buf
	sess.Stderr = &buf
	done := make(chan error, 1)
	go func() {
		done <- sess.Run(cmd)
	}()
	select {
	case err := <-done:
		if err != nil {
			return buf.String(), fmt.Errorf("%s: %w: %s", cmd, err, buf.String())
		}
		return buf.String(), nil
	case <-ctx.Done():
		_ = sess.Close()
		return "", ctx.Err()
	}
}

// writeRemoteFile writes content to a remote path by running `cat > path`.
// Simpler than sftp; adequate for user-data ISOs and similar.
func writeRemoteFile(c *ssh.Client, path string, content []byte) error {
	sess, err := c.NewSession()
	if err != nil {
		return err
	}
	defer sess.Close()
	stdin, err := sess.StdinPipe()
	if err != nil {
		return err
	}
	cmd := "cat > " + shellEscape(path)
	if err := sess.Start(cmd); err != nil {
		return err
	}
	if _, err := stdin.Write(content); err != nil {
		return err
	}
	if err := stdin.Close(); err != nil {
		return err
	}
	return sess.Wait()
}

func pidAliveOverSSH(ctx context.Context, c *ssh.Client, pidPath string) (bool, error) {
	out, err := runOverSSH(ctx, c,
		"if [ -f "+shellEscape(pidPath)+" ]; then kill -0 $(cat "+shellEscape(pidPath)+") 2>/dev/null && echo yes; fi")
	if err != nil {
		return false, err
	}
	return strings.Contains(out, "yes"), nil
}

// ------------------------------------------------------------------
// Tailscale API
// ------------------------------------------------------------------

// mintTailscaleKey requests a new ephemeral auth key from the tailnet API.
// The key is single-use, ephemeral, non-preauthorized (tag-scoped so it can
// be auto-approved when the tag is trusted in the ACL).
func mintTailscaleKey(ctx context.Context, tailnet, tag string) (string, error) {
	if tailnet == "" {
		return "", fmt.Errorf("tailnet is empty")
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
		return "", sdk.Errf(sdk.CatProviderUnavailable,
			"virtualbox.tailscale.api_error", "%v", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return "", sdk.Errf(sdk.CatAuth,
			"virtualbox.tailscale.api_status",
			"tailscale API %d: %s", resp.StatusCode, string(raw))
	}
	var out struct {
		Key string `json:"key"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return "", err
	}
	if out.Key == "" {
		return "", sdk.Errf(sdk.CatInternal,
			"virtualbox.tailscale.key_missing", "no key in tailscale response: %s", string(raw))
	}
	return out.Key, nil
}

// tsDevice mirrors just the fields we consume.
type tsDevice struct {
	ID          string   `json:"id"`
	Hostname    string   `json:"hostname"`
	Name        string   `json:"name"`
	Addresses   []string `json:"addresses"`
	LastSeen    string   `json:"lastSeen"`
	Authorized  bool     `json:"authorized"`
	NodeKey     string   `json:"nodeKey"`
	Machine     string   `json:"machine"`
	Tags        []string `json:"tags"`
	Expires     string   `json:"expires"`
	KeyExpiryDisabled bool `json:"keyExpiryDisabled"`
}

func (d *tsDevice) primaryIPv4() string {
	for _, a := range d.Addresses {
		if strings.Count(a, ".") == 3 {
			return a
		}
	}
	return ""
}

// online returns true if the device has been seen within the last 3 minutes.
func (d *tsDevice) online() bool {
	if d.LastSeen == "" {
		return false
	}
	t, err := time.Parse(time.RFC3339, d.LastSeen)
	if err != nil {
		return false
	}
	return time.Since(t) < 3*time.Minute
}

func findTailscaleDevice(ctx context.Context, tailnet, hostname string) (*tsDevice, error) {
	url := fmt.Sprintf("https://api.tailscale.com/api/v2/tailnet/%s/devices", tailnet)
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	req.SetBasicAuth(tsAPIKey, "")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("tailscale API %d: %s", resp.StatusCode, string(raw))
	}
	var out struct {
		Devices []tsDevice `json:"devices"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	for i := range out.Devices {
		d := &out.Devices[i]
		if d.Hostname == hostname {
			return d, nil
		}
		// Match Name prefix (name is hostname.tailnet).
		if strings.HasPrefix(d.Name, hostname+".") {
			return d, nil
		}
	}
	return nil, nil
}

func deleteTailscaleDevice(ctx context.Context, id string) error {
	req, _ := http.NewRequestWithContext(ctx, "DELETE",
		"https://api.tailscale.com/api/v2/device/"+id, nil)
	req.SetBasicAuth(tsAPIKey, "")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		raw, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("delete device %s: %d %s", id, resp.StatusCode, string(raw))
	}
	return nil
}

// ------------------------------------------------------------------
// tiny helpers
// ------------------------------------------------------------------

func shellEscape(s string) string {
	if !strings.ContainsAny(s, " '\"$\\`&|;<>*()[]{}?!#~") {
		return s
	}
	// Wrap in single quotes; escape inner single quotes with '\''.
	return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'"
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
