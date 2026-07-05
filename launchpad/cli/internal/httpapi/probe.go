package httpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"time"

	"github.com/soctalk/launchpad/internal/pluginhost"
	sdk "github.com/soctalk/launchpad-sdk-go"
)

// ProbeResult is the outcome of a connectivity/credential check for a Host or
// Network resource, run BEFORE it is attached to a run so operators can catch
// bad credentials or unreachable endpoints early.
type ProbeResult struct {
	OK      bool   `json:"ok"`
	Message string `json:"message"`
}

// probeReq is the optional body for a host probe. Supplying a network lets the
// probe use that network's tailnet + Tailscale key; otherwise a placeholder
// tailnet is injected so plugins that require the field still run their real
// connectivity check (SSH reachability, cloud auth, etc.).
type probeReq struct {
	Network string `json:"network,omitempty"`
}

// handleProbeHost starts the host's platform plugin with the host's config +
// credentials and calls plugin.initialize — which each plugin implements as a
// cheap authenticated/connectivity check (AWS DescribeRegions, Azure list RGs,
// SSH `which <hypervisor>`, etc.). Success means the host is usable in a run.
func (s *Server) handleProbeHost(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	host, ok, err := s.Hosts.get(name)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, ProbeResult{Message: err.Error()})
		return
	}
	if !ok {
		writeJSON(w, http.StatusNotFound, ProbeResult{Message: "host not found"})
		return
	}

	var req probeReq
	_ = json.NewDecoder(r.Body).Decode(&req) // body optional

	m := findManifest(host.Platform)
	if m == nil {
		writeJSON(w, http.StatusOK, ProbeResult{Message: fmt.Sprintf("platform %q not found among installed plugins", host.Platform)})
		return
	}

	// Assemble the effective config + secret env for the probe.
	cfg := map[string]any{}
	for k, v := range host.Config {
		cfg[k] = v
	}
	extraEnv := make([]string, 0, len(host.Env)+1)
	for k, v := range host.Env {
		extraEnv = append(extraEnv, k+"="+v)
	}
	// Resolve a network to supply the tailnet + Tailscale key. Some plugins
	// (the SSH-hypervisor ones) require a Tailscale API key at initialize time
	// to be able to mint device keys, so a host probe needs a network. Use the
	// named network if given, else fall back to the first configured one.
	net, haveNet, nerr := s.resolveProbeNetwork(req.Network)
	if nerr != nil {
		writeJSON(w, http.StatusOK, ProbeResult{Message: nerr.Error()})
		return
	}
	if haveNet {
		if v, has := cfg["tailnet"]; !has || v == "" {
			cfg["tailnet"] = net.Tailnet
		}
		if net.APIKey != "" {
			extraEnv = append(extraEnv, "TAILSCALE_API_KEY="+net.APIKey)
		}
	}
	if v, has := cfg["tailnet"]; !has || v == "" {
		cfg["tailnet"] = "probe.example.ts.net"
	}

	ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
	defer cancel()

	client, err := pluginhost.Start(ctx, m, pluginhost.StartConfig{
		EnvAllowlist: m.Env,
		ExtraEnv:     extraEnv,
	})
	if err != nil {
		writeJSON(w, http.StatusOK, ProbeResult{Message: "failed to start plugin: " + err.Error()})
		return
	}
	defer func() { _ = client.Shutdown(context.Background()) }()

	err = client.Call(ctx, sdk.MethodInitialize, sdk.InitializeParams{
		RunID: "probe", Config: cfg, LogLevel: "warn",
	}, nil)
	if err != nil {
		writeJSON(w, http.StatusOK, ProbeResult{Message: err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, ProbeResult{OK: true,
		Message: fmt.Sprintf("%s credentials valid and endpoint reachable", host.Platform)})
}

// handleProbeNetwork validates a Network's Tailscale API key by listing the
// tailnet's devices — the same call the orchestrator uses to resolve VM IPs.
func (s *Server) handleProbeNetwork(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	net, ok, err := s.Networks.get(name)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, ProbeResult{Message: err.Error()})
		return
	}
	if !ok {
		writeJSON(w, http.StatusNotFound, ProbeResult{Message: "network not found"})
		return
	}
	if net.APIKey == "" {
		writeJSON(w, http.StatusOK, ProbeResult{Message: "no API key set for this network"})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	count, err := tailscaleDeviceCount(ctx, net.APIKey)
	if err != nil {
		writeJSON(w, http.StatusOK, ProbeResult{Message: err.Error()})
		return
	}
	tn := net.Tailnet
	if tn == "" {
		tn = "tailnet"
	}
	writeJSON(w, http.StatusOK, ProbeResult{OK: true,
		Message: fmt.Sprintf("Tailscale key valid — %s reachable (%d device%s)", tn, count, plural(count))})
}

// tailscaleDeviceCount lists the tailnet's devices to validate the API key.
func tailscaleDeviceCount(ctx context.Context, apiKey string) (int, error) {
	req, _ := http.NewRequestWithContext(ctx, "GET",
		"https://api.tailscale.com/api/v2/tailnet/-/devices", nil)
	req.SetBasicAuth(apiKey, "")
	req.Header.Set("Accept", "application/json")
	resp, err := (&http.Client{}).Do(req)
	if err != nil {
		return 0, fmt.Errorf("Tailscale API unreachable: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return 0, fmt.Errorf("Tailscale API rejected the key (HTTP %d) — check the key is valid and not expired", resp.StatusCode)
	}
	if resp.StatusCode >= 400 {
		return 0, fmt.Errorf("Tailscale API returned HTTP %d", resp.StatusCode)
	}
	var payload struct {
		Devices []struct {
			ID string `json:"id"`
		} `json:"devices"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return 0, fmt.Errorf("unexpected Tailscale API response: %v", err)
	}
	return len(payload.Devices), nil
}

// resolveProbeNetwork returns the network to use for a host probe: the named
// one if given, otherwise the first configured network (so SSH-hypervisor
// plugins that need a Tailscale key at initialize still probe). Returns
// (_, false, nil) when no network is configured.
func (s *Server) resolveProbeNetwork(name string) (Network, bool, error) {
	if name != "" {
		net, ok, err := s.Networks.get(name)
		if err != nil {
			return Network{}, false, err
		}
		if !ok {
			return Network{}, false, fmt.Errorf("network %q not found", name)
		}
		return net, true, nil
	}
	s.Networks.mu.Lock()
	m, err := s.Networks.loadLocked()
	s.Networks.mu.Unlock()
	if err != nil {
		return Network{}, false, err
	}
	if len(m) == 0 {
		return Network{}, false, nil
	}
	names := make([]string, 0, len(m))
	for k := range m {
		names = append(names, k)
	}
	sort.Strings(names)
	return m[names[0]], true, nil
}

// findManifest returns the installed plugin manifest with the given name.
func findManifest(name string) *pluginhost.Manifest {
	manifests, _ := pluginhost.DiscoverPlugins()
	// Deterministic pick if duplicates ever appear.
	sort.Slice(manifests, func(i, j int) bool { return manifests[i].Name < manifests[j].Name })
	for _, m := range manifests {
		if m.Name == name {
			return m
		}
	}
	return nil
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}
