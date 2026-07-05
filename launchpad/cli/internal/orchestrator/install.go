package orchestrator

// Post-provision SocTalk install runner.
//
// The launchpad has SSH access to each VM through the tailnet (MagicDNS
// hostname lp-<vm_key>.<tailnet>.ts.net). We shell out to the system `ssh`
// so the operator's already-loaded agent handles auth.
//
// For MSSP: download the public installer, run it in --demo mode with
// SOCTALK_* env, then poll the API until 200.
//
// For each tenant: on MSSP, login + issue-agent to get the helm_install_hint,
// then on the tenant VM install k3s + helm + run the hint verbatim.

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

const (
	defaultInstallerURL = "https://raw.githubusercontent.com/soctalk/soctalk/main/install.sh"
	defaultSSHUser      = "ops"
)

func (o *Orchestrator) runInstall(ctx context.Context) error {
	icfg := o.cfg.Install
	if icfg.MSSPAdminEmail == "" || icfg.MSSPAdminPassword == "" {
		o.emit(Event{Ev: EvVMLog, VMKey: o.cfg.MSSP.Key, Level: "info",
			Message: "install config missing (mssp_admin_email/password); skipping install phase"})
		return nil
	}

	tailnet, _ := o.cfg.PluginConfig["tailnet"].(string)
	if tailnet == "" {
		return fmt.Errorf("cannot resolve tailnet from plugin_config")
	}
	sshUser := icfg.SSHUser
	if sshUser == "" {
		sshUser = defaultSSHUser
	}
	installerURL := icfg.InstallerURL
	if installerURL == "" {
		installerURL = defaultInstallerURL
	}

	msspHost := fmt.Sprintf("lp-%s.%s", o.cfg.MSSP.Key, tailnet)
	msspIP, err := o.resolveTailscaleIPWait(ctx, o.cfg.MSSP.Key, "lp-"+o.cfg.MSSP.Key, 12*time.Minute)
	if err != nil {
		return fmt.Errorf("resolve mssp tailnet IP: %w", err)
	}

	if err := o.installMSSP(ctx, sshUser, msspIP, msspHost, installerURL); err != nil {
		return err
	}

	// Cache session cookie for reuse across tenants.
	sessionJar, err := o.msspLogin(ctx, sshUser, msspIP, msspHost)
	if err != nil {
		return fmt.Errorf("mssp login for tenant enrollment: %w", err)
	}

	for _, t := range o.cfg.Tenants {
		tenantIP, err := o.resolveTailscaleIPWait(ctx, t.Key, "lp-"+t.Key, 12*time.Minute)
		if err != nil {
			return fmt.Errorf("resolve tenant %s tailnet IP: %w", t.Key, err)
		}
		slug := t.TenantSlug
		if slug == "" {
			slug = t.Key
		}
		displayName := t.Name
		if displayName == "" {
			displayName = slug
		}
		if err := o.onboardTenant(ctx, sshUser, msspIP, msspHost, slug, displayName, sessionJar); err != nil {
			return fmt.Errorf("onboard tenant %s: %w", slug, err)
		}
		if err := o.installTenant(ctx, sshUser, msspIP, msspHost, tenantIP, slug, sessionJar, msspIP); err != nil {
			return err
		}
	}
	return nil
}

// tailscaleAPIKey returns the Tailscale API key the orchestrator should use to
// resolve tailnet device IPs. It prefers the key injected from the run's Network
// resource (present in extraEnv, keyed per target) so the install phase works
// even when the launchpad process itself has no TAILSCALE_API_KEY in its env;
// it falls back to the process env for backward compatibility.
func (o *Orchestrator) tailscaleAPIKey() string {
	for _, envs := range o.extraEnv {
		for _, kv := range envs {
			if v, ok := strings.CutPrefix(kv, "TAILSCALE_API_KEY="); ok && v != "" {
				return v
			}
		}
	}
	return os.Getenv("TAILSCALE_API_KEY")
}

// resolveTailscaleIPWait polls resolveTailscaleIP until the device is ONLINE on
// the tailnet or the timeout elapses. Cloud VMs (aws/azure/hetzner) join the
// tailnet asynchronously a minute or two after the provider reports them
// "running", so a single lookup right after create often misses them. Emits
// progress so the wait is visible in the run timeline.
func (o *Orchestrator) resolveTailscaleIPWait(ctx context.Context, vmKey, hostname string, timeout time.Duration) (string, error) {
	deadline := time.Now().Add(timeout)
	var lastErr error
	for attempt := 0; ; attempt++ {
		ip, err := o.resolveTailscaleIP(hostname)
		if err == nil {
			return ip, nil
		}
		lastErr = err
		if time.Now().After(deadline) {
			return "", lastErr
		}
		if attempt == 0 || attempt%3 == 0 {
			o.emit(Event{Ev: EvVMProgress, VMKey: vmKey, Step: "tailnet",
				Message: fmt.Sprintf("waiting for %s to come online on the tailnet…", hostname)})
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(10 * time.Second):
		}
	}
}

// resolveTailscaleIP asks the Tailscale API for the IPv4 of a device by
// hostname prefix (case-insensitive). Returns the first match.
func (o *Orchestrator) resolveTailscaleIP(hostname string) (string, error) {
	apiKey := o.tailscaleAPIKey()
	if apiKey == "" {
		return "", fmt.Errorf("TAILSCALE_API_KEY not set")
	}
	req, _ := http.NewRequest("GET", "https://api.tailscale.com/api/v2/tailnet/-/devices", nil)
	req.SetBasicAuth(apiKey, "")
	req.Header.Set("Accept", "application/json")
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("tailscale devices API returned %d", resp.StatusCode)
	}
	var payload struct {
		Devices []struct {
			Hostname  string   `json:"hostname"`
			Addresses []string `json:"addresses"`
			LastSeen  string   `json:"lastSeen"`
		} `json:"devices"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return "", err
	}
	want := strings.ToLower(hostname)
	// Tailscale disambiguates duplicate hostnames by suffixing -1, -2, etc.
	// The prior VM (killed but still in the tailnet inventory) can outrank
	// the current one alphabetically, so we filter to devices "seen recently"
	// and prefer the most recent match.
	type cand struct {
		ipv4 string
		last time.Time
	}
	var candidates []cand
	for _, d := range payload.Devices {
		if !strings.HasPrefix(strings.ToLower(d.Hostname), want) {
			continue
		}
		var ipv4 string
		for _, a := range d.Addresses {
			if strings.Contains(a, ".") && !strings.Contains(a, ":") {
				ipv4 = a
				break
			}
		}
		if ipv4 == "" {
			continue
		}
		last, _ := time.Parse(time.RFC3339, d.LastSeen)
		// Only consider devices seen within the last 5 minutes as "current".
		// Stale ones (offline, minutes ago) are demoted.
		if !last.IsZero() && time.Since(last) > 5*time.Minute {
			continue
		}
		candidates = append(candidates, cand{ipv4: ipv4, last: last})
	}
	if len(candidates) == 0 {
		return "", fmt.Errorf("no ONLINE tailnet device found with hostname prefix %q", hostname)
	}
	// Prefer the most recently seen.
	best := candidates[0]
	for _, c := range candidates[1:] {
		if c.last.After(best.last) {
			best = c
		}
	}
	return best.ipv4, nil
}

// onboardTenant idempotently creates the tenant record on the MSSP so the
// subsequent :issue-agent has something to resolve. --demo already onboards
// a "demo" tenant; anything else in the config needs an explicit POST.
func (o *Orchestrator) onboardTenant(ctx context.Context, user, msspSSHTarget, msspHost, slug, name, sessionJar string) error {
	script := fmt.Sprintf(`set -eu
echo %s | base64 -d > /tmp/jar-onboard-%s
# If tenant already exists (idempotent), skip. GET /api/mssp/tenants and
# check for the slug.
EXISTING=$(curl -sfk -b /tmp/jar-onboard-%s \
  -H "Host: %s" -H "Origin: https://%s" \
  "https://127.0.0.1/api/mssp/tenants" | \
  python3 -c 'import json,sys; d=json.load(sys.stdin); items=d.get("items",d) if isinstance(d,dict) else d; print(next((t.get("id","") for t in items if t.get("slug")==%q), ""))')
if [ -n "$EXISTING" ]; then
  echo "tenant %s already exists (id=$EXISTING); skipping onboard"
  exit 0
fi
curl -sfk -b /tmp/jar-onboard-%s -X POST \
  -H "Host: %s" -H "Origin: https://%s" -H "Content-Type: application/json" \
  -d '{"slug":%q,"display_name":%q,"profile":"poc"}' \
  "https://127.0.0.1/api/mssp/tenants/onboard" > /dev/null
echo "tenant %s onboarded"
`,
		sessionJar, slug,
		slug,
		msspHost, msspHost,
		slug,
		slug,
		slug,
		msspHost, msspHost,
		slug, name,
		slug,
	)
	o.emit(Event{Ev: EvVMProgress, VMKey: slug,
		Step: "install", Percent: 5, Message: "onboarding tenant record on MSSP"})
	return o.runRemoteScript(ctx, slug, user, msspSSHTarget, script, 3*time.Minute)
}

// installMSSP SSHes into sshTarget (IP) but uses hostname for the
// SOCTALK_HOSTNAME env var + Host header (since Traefik ingress + cert
// are keyed on the hostname, not IP).
func (o *Orchestrator) installMSSP(ctx context.Context, user, sshTarget, hostname, installerURL string) error {
	// Idempotence: if the MSSP API is already answering, install.sh has
	// already run successfully. Skip — install.sh's db-init is not
	// re-runnable (unique-slug violation on the bootstrap organization).
	probe := fmt.Sprintf(
		`curl -sk -m 5 -o /dev/null -w "%%{http_code}" -H "Host: %s" https://127.0.0.1/api/auth/me 2>/dev/null || echo 000`,
		hostname,
	)
	if out, err := o.captureRemote(ctx, user, sshTarget, probe, 30*time.Second); err == nil {
		code := strings.TrimSpace(out)
		if code == "200" || code == "401" {
			o.emit(Event{Ev: EvVMProgress, VMKey: o.cfg.MSSP.Key,
				Step: "install", Percent: 100, Message: "MSSP already installed (API answering " + code + "); skipping install.sh"})
			return nil
		}
	}

	icfg := o.cfg.Install
	msspName := icfg.MSSPDisplayName
	if msspName == "" {
		msspName = "Launchpad Demo MSSP"
	}
	llmProvider := icfg.LLMProvider
	if llmProvider == "" {
		llmProvider = "anthropic"
	}
	llmKey := icfg.LLMAPIKey
	if llmKey == "" {
		llmKey = "sk-launchpad-smoke-placeholder"
	}

	script := fmt.Sprintf(`#!/usr/bin/env bash
set -euo pipefail
export SOCTALK_MSSP_NAME=%q
export SOCTALK_ADMIN_EMAIL=%q
export SOCTALK_ADMIN_PASSWORD=%q
export SOCTALK_HOSTNAME=%q
export SOCTALK_LLM_PROVIDER=%q
export SOCTALK_LLM_API_KEY=%q
# install.sh writes an empty tenantProvisioning: block when no SOCTALK_TENANT_*
# vars are set, which nulls the chart's defaults and breaks the 30-api.yaml
# template on adapterImageRepo. Set the tenant chart pins to the chart's own
# defaults so install.sh emits a non-empty block and the chart defaults survive.
export SOCTALK_TENANT_CHART_REF=oci://ghcr.io/soctalk/charts/soctalk-tenant
export SOCTALK_AGENT_CHART_REF=oci://ghcr.io/soctalk/charts/soctalk-cloud-agent
export SOCTALK_ASSUME_YES=true
# Wait for cloud-init + tailscale-up to fully settle before we start.
cloud-init status --wait >/dev/null 2>&1 || true
curl -sfL %s | sudo -E bash -s -- --demo
`,
		msspName,
		icfg.MSSPAdminEmail,
		icfg.MSSPAdminPassword,
		hostname,
		llmProvider,
		llmKey,
		installerURL,
	)

	o.emit(Event{Ev: EvVMProgress, VMKey: o.cfg.MSSP.Key,
		Step: "install", Percent: 5, Message: "starting soctalk install.sh --demo (k3s + helm + soctalk-system)"})

	if err := o.runRemoteScript(ctx, o.cfg.MSSP.Key, user, sshTarget, script, 25*time.Minute); err != nil {
		return fmt.Errorf("mssp install: %w", err)
	}

	// Wait for the API to answer through Traefik.
	if err := o.waitMSSPReady(ctx, user, sshTarget, hostname); err != nil {
		return fmt.Errorf("mssp readiness: %w", err)
	}

	o.emit(Event{Ev: EvVMProgress, VMKey: o.cfg.MSSP.Key,
		Step: "install", Percent: 100, Message: "MSSP installed + API answering"})
	return nil
}

// waitMSSPReady polls /api/auth/me until it answers 200/401 (i.e. server up).
func (o *Orchestrator) waitMSSPReady(ctx context.Context, user, sshTarget, hostname string) error {
	probe := fmt.Sprintf(`for i in $(seq 1 60); do
  code=$(curl -sk -m 5 -o /dev/null -w "%%{http_code}" -H "Host: %s" https://127.0.0.1/api/auth/me 2>/dev/null || echo 000)
  case "$code" in 200|401) echo "ready ($code)"; exit 0;; esac
  sleep 5
done
echo "api never answered"; exit 1
`, hostname)
	return o.runRemoteScript(ctx, o.cfg.MSSP.Key, user, sshTarget, probe, 10*time.Minute)
}

// msspLogin returns a base64-encoded cookie jar (safe to embed inside remote
// scripts as `printf ... | base64 -d > jar`).
func (o *Orchestrator) msspLogin(ctx context.Context, user, sshTarget, hostname string) (string, error) {
	icfg := o.cfg.Install
	// Marshal the credentials in Go and ship them base64-encoded so admin
	// emails/passwords containing JSON or shell metacharacters (" \ ') can't
	// break the request body.
	body, _ := json.Marshal(map[string]string{
		"email":    icfg.MSSPAdminEmail,
		"password": icfg.MSSPAdminPassword,
	})
	bodyB64 := base64.StdEncoding.EncodeToString(body)
	loginScript := fmt.Sprintf(`set -eu
JAR=$(mktemp)
BODY=$(mktemp)
echo %s | base64 -d > "$BODY"
curl -sfk -m 10 -c "$JAR" \
  -H "Host: %s" -H "Origin: https://%s" \
  -H "Content-Type: application/json" \
  --data-binary @"$BODY" \
  https://127.0.0.1/api/auth/login > /dev/null
base64 -w0 "$JAR"
`,
		bodyB64, hostname, hostname,
	)
	out, err := o.captureRemote(ctx, user, sshTarget, loginScript, 3*time.Minute)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(out), nil
}

// installTenant provisions the tenant SOC stack with active recovery for the
// degraded-tailnet failure mode. The cloud-agent registers + claims the
// install_helm_release job, then hangs if the tenant→MSSP control-plane path
// drops (symptom: empty tenant namespace, agent silent). Neither a plain agent
// restart nor a fresh MSSP :issue-agent recovers it — on any restart the agent
// finds its persisted runtime_token in the identity Secret and skips
// re-registration ("runtime_token_present"), so it never re-claims the job.
// The recovery that works (verified): clear runtime_token + installation_id
// from the identity Secret (keeping the Secret so its volume mount survives),
// then restart — the agent re-registers via its bootstrap_token and re-claims
// install_helm_release. (Codex P3, refined by empirical agent behavior.)
func (o *Orchestrator) installTenant(ctx context.Context, user, msspSSHTarget, msspHost, tenantSSHTarget, slug, sessionJar, msspTailscaleIP string) error {
	o.emit(Event{Ev: EvVMProgress, VMKey: slug, Step: "install", Percent: 10,
		Message: "issuing agent bootstrap token on MSSP"})
	hintB64, err := o.issueAgentHint(ctx, user, msspSSHTarget, msspHost, slug, sessionJar)
	if err != nil {
		return err
	}
	o.emit(Event{Ev: EvVMProgress, VMKey: slug, Step: "install", Percent: 40,
		Message: "installing k3s + helm + soctalk-cloud-agent on tenant"})
	if err := o.installAgentOnTenant(ctx, hintB64, user, tenantSSHTarget, slug, msspTailscaleIP, msspHost); err != nil {
		return fmt.Errorf("tenant install: %w", err)
	}
	o.emit(Event{Ev: EvVMProgress, VMKey: slug, Step: "install", Percent: 70,
		Message: "tenant agent installed; waiting for Wazuh stack"})

	// Wait for the tenant chart (Wazuh) in bounded windows, recovering the
	// stuck agent when the namespace stays empty. code 0 = operational,
	// 4 = pods present but not ready (keep waiting — recovery would disrupt an
	// in-progress install), 5 = namespace empty (agent stuck — recover).
	const maxRecoveries = 3
	recoveries := 0
	deadline := time.Now().Add(35 * time.Minute)
	for time.Now().Before(deadline) {
		code := o.waitWazuhBounded(ctx, user, tenantSSHTarget, slug, 7*time.Minute)
		if code == 0 {
			o.emit(Event{Ev: EvVMProgress, VMKey: slug, Step: "install", Percent: 100,
				Message: "tenant SOC stack operational (wazuh ready)"})
			return nil
		}
		if code == 5 {
			if recoveries >= maxRecoveries {
				break
			}
			recoveries++
			o.emit(Event{Ev: EvVMLog, VMKey: slug, Level: "warn",
				Message: fmt.Sprintf("recovery %d/%d: tenant namespace empty — clearing agent runtime token to force re-registration + job re-claim", recoveries, maxRecoveries)})
			if err := o.recoverStuckAgent(ctx, user, tenantSSHTarget, slug); err != nil {
				o.emit(Event{Ev: EvVMLog, VMKey: slug, Level: "warn",
					Message: "recovery action error (continuing): " + err.Error()})
			}
		}
		// code 4 (pulling) or transient ssh error: keep waiting.
	}
	return fmt.Errorf("tenant %s wazuh stack not operational after %d recovery attempts", slug, recoveries)
}

// recoverStuckAgent forces the cloud-agent to re-register (and thus re-claim
// its stuck install_helm_release job) by removing the persisted runtime_token
// and installation_id from its identity Secret, then restarting it. The Secret
// itself is kept (it's a required volume mount); only the runtime identity is
// cleared so the agent falls back to registering via its bootstrap_token.
func (o *Orchestrator) recoverStuckAgent(ctx context.Context, user, tenantSSHTarget, slug string) error {
	script := fmt.Sprintf(`#!/usr/bin/env bash
set -uo pipefail
export KUBECONFIG=/etc/rancher/k3s/k3s.yaml
SEC=soctalk-agent-%s-identity
echo "==> recovery: clearing agent runtime token + restarting to force re-registration"
kubectl -n soctalk-agent patch secret "$SEC" --type=json \
  -p '[{"op":"remove","path":"/data/runtime_token"},{"op":"remove","path":"/data/installation_id"}]' 2>/dev/null \
  || echo "   (runtime_token already absent)"
kubectl -n soctalk-agent rollout restart deploy 2>/dev/null || kubectl -n soctalk-agent delete pod --all 2>/dev/null || true
echo "==> agent restarting; it will re-register via bootstrap_token and re-claim install_helm_release"
`, slug)
	return o.runRemoteScript(ctx, slug, user, tenantSSHTarget, script, 3*time.Minute)
}

// issueAgentHint logs into the MSSP (via the session jar) and POSTs
// :issue-agent for the tenant, returning the base64 helm_install_hint. Each
// call mints a fresh agent bootstrap token.
func (o *Orchestrator) issueAgentHint(ctx context.Context, user, msspSSHTarget, msspHost, slug, sessionJar string) (string, error) {
	lookup := fmt.Sprintf(`set -eu
echo %s | base64 -d > /tmp/jar-%s
TENANT=$(curl -sfk -b /tmp/jar-%s \
  -H "Host: %s" -H "Origin: https://%s" \
  "https://127.0.0.1/api/mssp/tenants" | \
  python3 -c 'import json,sys; d=json.load(sys.stdin); items=d.get("items",d) if isinstance(d,dict) else d; print(next((t["id"] for t in items if t.get("slug")==%q), ""))')
if [ -z "$TENANT" ]; then
  echo "tenant slug %s not found in mssp inventory" >&2; exit 2
fi
HINT=$(curl -sfk -b /tmp/jar-%s -X POST \
  -H "Host: %s" -H "Origin: https://%s" -H "Content-Type: application/json" \
  "https://127.0.0.1/api/mssp/tenants/$TENANT:issue-agent" | \
  python3 -c 'import json,sys; print(json.load(sys.stdin).get("helm_install_hint",""))')
if [ -z "$HINT" ]; then
  echo "no helm_install_hint in issue-agent response" >&2; exit 3
fi
printf '%%s' "$HINT" | base64 -w0
`,
		sessionJar, slug, slug,
		msspHost, msspHost,
		slug,
		slug,
		slug,
		msspHost, msspHost,
	)
	b, err := o.captureRemote(ctx, user, msspSSHTarget, lookup, 5*time.Minute)
	if err != nil {
		return "", fmt.Errorf("issue-agent for tenant %s: %w", slug, err)
	}
	return strings.TrimSpace(b), nil
}

// installAgentOnTenant installs k3s + helm on the tenant (idempotent) and runs
// the issue-agent hint as `helm upgrade --install`, so re-running it with a
// fresh hint re-registers the agent with a new bootstrap token.
func (o *Orchestrator) installAgentOnTenant(ctx context.Context, hintB64, user, tenantSSHTarget, slug, msspTailscaleIP, msspHost string) error {
	install := fmt.Sprintf(`#!/usr/bin/env bash
set -euo pipefail
cloud-init status --wait >/dev/null 2>&1 || true
if ! command -v k3s >/dev/null; then
  # sudo strips env by default, so pass INSTALL_K3S_EXEC inside sudo.
  curl -sfL https://get.k3s.io | sudo INSTALL_K3S_EXEC="--write-kubeconfig-mode=644" sh -
fi
# Belt + suspenders: the k3s.yaml may already exist from an earlier run
# that didn't pass the flag through; chmod it so the ops user can read.
sudo chmod 0644 /etc/rancher/k3s/k3s.yaml || true
if ! command -v helm >/dev/null; then
  curl -fsSL https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | sudo bash
fi
export KUBECONFIG=/etc/rancher/k3s/k3s.yaml
# Wait for the k8s API to be reachable before installing.
for i in $(seq 1 60); do
  if kubectl get --raw='/healthz' >/dev/null 2>&1; then break; fi
  sleep 2
done
HINT=$(printf '%%s' %q | base64 -d)
# Rewrite as helm upgrade --install so the phase is re-runnable (idempotent
# on our side; the launchpad may retry after fixing config on the MSSP).
HINT=$(printf '%%s' "$HINT" | sed 's/^helm install /helm upgrade --install /')
# The hint doesn't include --set-string insecureTLS=true; the MSSP cert is
# self-signed while the launchpad-owned certs are pending, so we splice it in.
if ! echo "$HINT" | grep -q 'insecureTLS'; then
  HINT="$HINT --set-string insecureTLS=true"
fi
# Tailnet MagicDNS isn't reachable from inside the pod's cluster DNS,
# so inject the MSSP hostname → tailnet IP mapping as a hostAlias.
if ! echo "$HINT" | grep -q 'hostAliases'; then
  HINT="$HINT --set hostAliases[0].ip=%s --set hostAliases[0].hostnames[0]=%s"
fi
echo "==> helm_install_hint:"
echo "$HINT"
eval "$HINT"
`, hintB64, msspTailscaleIP, msspHost)
	return o.runRemoteScript(ctx, slug, user, tenantSSHTarget, install, 25*time.Minute)
}

// waitWazuhBounded polls for the tenant Wazuh stack for one bounded window and
// returns an exit code: 0 = operational (3/3 core pods Running), 5 = namespace
// empty the whole window (agent stuck — caller should reissue), 4 = pods
// present but not all ready (still pulling — caller should keep waiting), -1 =
// transient ssh error.
func (o *Orchestrator) waitWazuhBounded(ctx context.Context, user, tenantSSHTarget, slug string, window time.Duration) int {
	iters := int(window.Seconds() / 5)
	if iters < 12 {
		iters = 12
	}
	script := fmt.Sprintf(`#!/usr/bin/env bash
set -uo pipefail
export KUBECONFIG=/etc/rancher/k3s/k3s.yaml
NS=tenant-%s
sawpods=0
for i in $(seq 1 %d); do
  ready=$(kubectl -n "$NS" get pods --no-headers 2>/dev/null | awk '$2=="1/1" && $3=="Running"' | grep -c -E 'wazuh-(manager|indexer|dashboard)')
  if [ "${ready:-0}" -ge 3 ]; then
    echo "==> wazuh operational: $ready/3 core pods ready"
    kubectl -n "$NS" get pods --no-headers | sed 's/^/    /'
    exit 0
  fi
  nres=$(kubectl -n "$NS" get pods --no-headers 2>/dev/null | wc -l | tr -d ' ')
  [ "${nres:-0}" -gt 0 ] && sawpods=1
  if [ $((i %% 6)) -eq 0 ]; then echo "wazuh: ${ready:-0}/3 ready, ns has ${nres:-0} pods — waiting"; fi
  sleep 5
done
if [ "$sawpods" -eq 1 ]; then
  echo "==> wazuh pods present but not all ready in this window — keep waiting"
  exit 4
fi
echo "==> tenant namespace empty this window — cloud-agent has not installed the chart" >&2
exit 5
`, slug, iters)
	err := o.runRemoteScript(ctx, slug, user, tenantSSHTarget, script, window+2*time.Minute)
	if err == nil {
		return 0
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode()
	}
	return -1
}

// runRemoteScript pipes a script over SSH and streams each stdout/stderr line
// as a vm_log event so the operator sees progress in real time.
func (o *Orchestrator) runRemoteScript(ctx context.Context, vmKey, user, host, script string, timeout time.Duration) error {
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(cctx, "ssh",
		"-o", "BatchMode=yes",
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null",
		"-o", "ServerAliveInterval=30",
		"-o", "ConnectTimeout=15",
		user+"@"+host, "bash -s",
	)
	cmd.Stdin = strings.NewReader(script)
	cmd.Env = append(os.Environ(), "LC_ALL=C")

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); o.streamLines(vmKey, "info", stdout) }()
	go func() { defer wg.Done(); o.streamLines(vmKey, "warn", stderr) }()
	waitErr := cmd.Wait()
	// Drain both pipes fully before returning — otherwise the goroutines
	// may still be emitting when Run() closes o.events (send on closed chan).
	wg.Wait()
	if waitErr != nil {
		if cctx.Err() == context.DeadlineExceeded {
			return fmt.Errorf("timeout after %s", timeout)
		}
		return waitErr
	}
	return nil
}

// captureRemote is a variant that returns stdout as a string (for scripts
// that produce a single-value result rather than streaming logs).
func (o *Orchestrator) captureRemote(ctx context.Context, user, host, script string, timeout time.Duration) (string, error) {
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(cctx, "ssh",
		"-o", "BatchMode=yes",
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null",
		"-o", "ConnectTimeout=15",
		user+"@"+host, "bash -s",
	)
	cmd.Stdin = strings.NewReader(script)
	out, err := cmd.Output()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return "", fmt.Errorf("remote script failed: %s: stderr=%s", err, string(ee.Stderr))
		}
		return "", err
	}
	return string(out), nil
}

func (o *Orchestrator) streamLines(vmKey, level string, r io.Reader) {
	s := bufio.NewScanner(r)
	s.Buffer(make([]byte, 64*1024), 1024*1024)
	for s.Scan() {
		o.emit(Event{Ev: EvVMLog, VMKey: vmKey, Level: level, Message: s.Text()})
	}
}
