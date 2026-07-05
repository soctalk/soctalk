// launchpad-plugin-docker provisions "VMs" as Docker containers on the
// operator's local Docker daemon. Useful for developing the launchpad
// orchestration flow without cloud credentials.
//
// Implementation: shells out to `docker` CLI (no cgo/API-version dance).
package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"

	sdk "github.com/soctalk/launchpad-sdk-go"
)

const (
	name    = "docker"
	version = "0.1.0"

	labelRunID   = "launchpad.run_id"
	labelVMKey   = "launchpad.vm_key"
	labelManaged = "launchpad.managed"
)

type config struct {
	Image   string `json:"image,omitempty"`
	Network string `json:"network,omitempty"`
}

var cfg config

func main() {
	err := sdk.Serve(sdk.Plugin{
		Name:    name,
		Version: version,

		AllowedEnvVars: []string{"DOCKER_HOST", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH"},
		ConfigSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"image":   map[string]any{"type": "string"},
				"network": map[string]any{"type": "string"},
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
		fmt.Fprintln(os.Stderr, "docker plugin:", err)
		os.Exit(1)
	}
}

func initialize(ctx context.Context, params sdk.InitializeParams) (sdk.InitializeResult, error) {
	if raw, ok := params.Config["image"].(string); ok {
		cfg.Image = raw
	}
	if raw, ok := params.Config["network"].(string); ok {
		cfg.Network = raw
	}
	if cfg.Image == "" {
		cfg.Image = "ubuntu:24.04"
	}
	if cfg.Network == "" {
		cfg.Network = "bridge"
	}
	// Probe: docker version. Any non-zero exit means daemon is unreachable.
	out, err := run(ctx, "docker", "version", "--format", "{{.Server.APIVersion}}")
	if err != nil {
		return sdk.InitializeResult{}, sdk.Errf(sdk.CatProviderUnavailable,
			"docker.daemon.unreachable",
			"cannot reach Docker daemon: %v (is Docker running?)", firstLine(out))
	}
	return sdk.InitializeResult{Ready: true}, nil
}

func plan(ctx context.Context, params sdk.VMPlanParams, emit sdk.Emitter) (sdk.VMPlanResult, error) {
	return sdk.VMPlanResult{
		Summary:              fmt.Sprintf("docker: %s (image=%s network=%s)", params.Spec.Name, cfg.Image, cfg.Network),
		EstimatedDurationSec: 15,
	}, nil
}

func create(ctx context.Context, params sdk.VMCreateParams, emit sdk.Emitter) (sdk.VMCreateResult, error) {
	spec := params.Spec
	emit.Progress("lookup", 5, "checking for existing container")
	// Idempotent hit.
	if id, err := findByLabels(ctx, spec.RunID, spec.VMKey); err != nil {
		return sdk.VMCreateResult{}, err
	} else if id != "" {
		emit.Log("info", "reusing existing container", map[string]any{"container_id": id})
		return inspectToCreateResult(ctx, id)
	}

	emit.Progress("image", 20, "pulling "+cfg.Image)
	if _, err := run(ctx, "docker", "pull", cfg.Image); err != nil {
		return sdk.VMCreateResult{}, sdk.Errf(sdk.CatProviderUnavailable,
			"docker.pull_failed", "%v", err)
	}

	entrypoint := buildEntrypoint(spec)
	entrypointB64 := base64.StdEncoding.EncodeToString([]byte(entrypoint))
	containerName := sanitize("lp-" + spec.RunID + "-" + spec.VMKey)

	emit.Progress("create", 60, "starting container "+containerName)
	args := []string{
		"docker", "run", "-d",
		"--name", containerName,
		"--label", labelRunID + "=" + spec.RunID,
		"--label", labelVMKey + "=" + spec.VMKey,
		"--label", labelManaged + "=true",
		"--hostname", firstNonEmpty(spec.Name, spec.VMKey),
		"--publish", "127.0.0.1::22",
		"--network", cfg.Network,
		"--entrypoint", "bash",
		cfg.Image,
		"-c",
		"echo " + entrypointB64 + " | base64 -d > /etc/lp-entrypoint.sh && chmod +x /etc/lp-entrypoint.sh && /etc/lp-entrypoint.sh",
	}
	out, err := run(ctx, args...)
	if err != nil {
		return sdk.VMCreateResult{}, sdk.Errf(sdk.CatProviderUnavailable,
			"docker.run_failed", "%v: %s", err, firstLine(out))
	}
	id := strings.TrimSpace(out)
	emit.Progress("create", 100, "container running")
	return inspectToCreateResult(ctx, id)
}

func waitReady(ctx context.Context, params sdk.VMWaitReadyParams, emit sdk.Emitter) (sdk.VMWaitReadyResult, error) {
	// Container is running as soon as `docker run -d` returns. Deeper checks
	// (like SSH-dial) are the launchpad's job.
	emit.Progress("wait_ready", 100, "container running")
	return sdk.VMWaitReadyResult{Ready: true}, nil
}

func destroy(ctx context.Context, params sdk.VMDestroyParams, emit sdk.Emitter) (sdk.VMDestroyResult, error) {
	id := params.VMID
	if id == "" {
		found, err := findByLabels(ctx, params.RunID, params.VMKey)
		if err != nil {
			return sdk.VMDestroyResult{}, err
		}
		id = found
	}
	if id == "" {
		return sdk.VMDestroyResult{Destroyed: false}, nil
	}
	emit.Progress("destroy", 50, "removing container")
	if _, err := run(ctx, "docker", "rm", "-f", id); err != nil {
		return sdk.VMDestroyResult{}, sdk.Errf(sdk.CatProviderUnavailable,
			"docker.rm_failed", "%v", err)
	}
	return sdk.VMDestroyResult{Destroyed: true}, nil
}

func inspect(ctx context.Context, params sdk.VMInspectParams, emit sdk.Emitter) (sdk.VMInspectResult, error) {
	id := params.VMID
	if id == "" {
		found, err := findByLabels(ctx, params.RunID, params.VMKey)
		if err != nil {
			return sdk.VMInspectResult{}, err
		}
		id = found
	}
	if id == "" {
		return sdk.VMInspectResult{Exists: false}, nil
	}
	info, err := dockerInspect(ctx, id)
	if err != nil {
		return sdk.VMInspectResult{Exists: false}, nil
	}
	res := sdk.VMInspectResult{
		Exists:  true,
		VMID:    id,
		SSHUser: "root",
		State:   dockerState(info),
	}
	if ip, port := dockerSSHBinding(info); ip != "" {
		res.IPv4 = ip
		_ = port // captured for symmetry; not used in inspect result
	}
	return res, nil
}

// ------------------------------------------------------------------
// helpers
// ------------------------------------------------------------------

// buildEntrypoint returns a shell script that installs openssh-server, seeds
// authorized_keys, writes user-data to /etc/lp-userdata, and starts sshd.
func buildEntrypoint(spec sdk.VMSpec) string {
	keys := strings.Join(spec.SSHKeys, "\n")
	return fmt.Sprintf(`#!/bin/bash
set -e
apt-get update -qq
apt-get install -y openssh-server sudo >/dev/null
mkdir -p /root/.ssh
cat >/root/.ssh/authorized_keys <<KEYS
%s
KEYS
chmod 700 /root/.ssh && chmod 600 /root/.ssh/authorized_keys
mkdir -p /run/sshd
cat >/etc/lp-userdata <<'USERDATA'
%s
USERDATA
exec /usr/sbin/sshd -D -e -p 22
`, keys, spec.UserData)
}

// findByLabels returns the container ID matching run_id + vm_key, or "".
func findByLabels(ctx context.Context, runID, vmKey string) (string, error) {
	out, err := run(ctx, "docker", "ps", "-a", "-q",
		"--filter", "label="+labelRunID+"="+runID,
		"--filter", "label="+labelVMKey+"="+vmKey)
	if err != nil {
		return "", sdk.Errf(sdk.CatProviderUnavailable, "docker.ps_failed", "%v", err)
	}
	line := firstLine(out)
	if line == "" {
		return "", nil
	}
	return line, nil
}

// inspectToCreateResult reads `docker inspect` for a container and translates
// it into VMCreateResult.
func inspectToCreateResult(ctx context.Context, id string) (sdk.VMCreateResult, error) {
	info, err := dockerInspect(ctx, id)
	if err != nil {
		return sdk.VMCreateResult{}, sdk.Errf(sdk.CatInternal, "docker.inspect_failed", "%v", err)
	}
	res := sdk.VMCreateResult{
		VMID:    id,
		SSHUser: "root",
		SSHPort: 22,
		Metadata: map[string]string{
			"provider": "docker",
		},
	}
	if info.Name != "" {
		res.Metadata["container_name"] = strings.TrimPrefix(info.Name, "/")
	}
	if ip, port := dockerSSHBinding(info); ip != "" {
		res.IPv4 = ip
		res.SSHPort = port
	}
	// Internal container IP for other containers on the same network.
	for _, ns := range info.NetworkSettings.Networks {
		if ns.IPAddress != "" {
			res.Metadata["internal_ipv4"] = ns.IPAddress
			break
		}
	}
	return res, nil
}

// dockerInspectRaw mirrors just the fields we care about.
type dockerInspectRaw struct {
	Name  string `json:"Name"`
	State struct {
		Status  string `json:"Status"`
		Running bool   `json:"Running"`
	} `json:"State"`
	NetworkSettings struct {
		Ports    map[string][]struct {
			HostIP   string `json:"HostIp"`
			HostPort string `json:"HostPort"`
		} `json:"Ports"`
		Networks map[string]struct {
			IPAddress string `json:"IPAddress"`
		} `json:"Networks"`
	} `json:"NetworkSettings"`
}

func dockerInspect(ctx context.Context, id string) (*dockerInspectRaw, error) {
	out, err := run(ctx, "docker", "inspect", id)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", err, firstLine(out))
	}
	var arr []dockerInspectRaw
	if err := json.Unmarshal([]byte(out), &arr); err != nil {
		return nil, err
	}
	if len(arr) == 0 {
		return nil, errors.New("empty inspect output")
	}
	return &arr[0], nil
}

func dockerState(i *dockerInspectRaw) string {
	if i.State.Running {
		return "running"
	}
	if i.State.Status == "" {
		return "unknown"
	}
	return i.State.Status
}

func dockerSSHBinding(i *dockerInspectRaw) (string, int) {
	if bindings, ok := i.NetworkSettings.Ports["22/tcp"]; ok && len(bindings) > 0 {
		port := 0
		fmt.Sscanf(bindings[0].HostPort, "%d", &port)
		return bindings[0].HostIP, port
	}
	return "", 0
}

func run(ctx context.Context, cmd ...string) (string, error) {
	c := exec.CommandContext(ctx, cmd[0], cmd[1:]...)
	// Inherit DOCKER_HOST etc. from our own env (allow-listed at spawn time).
	out, err := c.CombinedOutput()
	return string(out), err
}

func firstLine(s string) string {
	if i := strings.IndexRune(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

func firstNonEmpty(s ...string) string {
	for _, v := range s {
		if v != "" {
			return v
		}
	}
	return ""
}

func sanitize(s string) string {
	var b strings.Builder
	for i, r := range s {
		ok := (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')
		if !ok && (i == 0 || (r != '_' && r != '.' && r != '-')) {
			b.WriteRune('-')
			continue
		}
		b.WriteRune(r)
	}
	name := b.String()
	if len(name) > 63 {
		name = name[:63]
	}
	return name
}
