package httpapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	"github.com/soctalk/launchpad/internal/orchestrator"
)

func (s *Server) handleListRuns(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.Mgr.List())
}

// RunRequest is the reference-based run spec the UI posts: it names hosts and a
// network rather than inlining any config or secrets. The server resolves it
// into the full orchestrator.Config plus per-target secret env (ExtraEnv), so
// credentials/keys never travel through the browser or persist in the config.
type RunRequest struct {
	RunID    string                     `json:"run_id"`
	Network  string                     `json:"network"`   // network name (overlay + tailnet + api key)
	MSSPHost string                     `json:"mssp_host"` // host name for the MSSP
	Tenants  []tenantPlacement          `json:"tenants"`
	Install  orchestrator.InstallConfig `json:"install"`
}

type tenantPlacement struct {
	Slug string `json:"slug"`
	Host string `json:"host"`
}

// handleStartRun composes a run from host/network references and starts it.
func (s *Server) handleStartRun(w http.ResponseWriter, r *http.Request) {
	var req RunRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	if req.Network == "" || req.MSSPHost == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "network and mssp_host are required")
		return
	}
	cfg, extraEnv, err := s.composeRun(req)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "compose_failed", err.Error())
		return
	}
	run, err := s.Mgr.Start(cfg, extraEnv)
	if err != nil {
		writeErr(w, http.StatusConflict, "start_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"run_id": run.ID})
}

// composeRun resolves host/network references into the run Config + per-target
// ExtraEnv. The tailnet comes from the network (never the host); secrets (ESXi
// creds from the host, Tailscale API key from the network) go into ExtraEnv.
func (s *Server) composeRun(req RunRequest) (orchestrator.Config, map[string][]string, error) {
	net, ok, err := s.Networks.get(req.Network)
	if err != nil || !ok {
		return orchestrator.Config{}, nil, fmt.Errorf("network %q not found", req.Network)
	}
	msspHost, ok, err := s.Hosts.get(req.MSSPHost)
	if err != nil || !ok {
		return orchestrator.Config{}, nil, fmt.Errorf("host %q not found", req.MSSPHost)
	}

	extraEnv := map[string][]string{}
	envSeen := map[string]bool{}
	// addEnv is keyed by composed target (platform@host) and is idempotent, so
	// it can be called once per VM without duplicating a host's env when several
	// VMs share the same host.
	addEnv := func(target string, h Host) {
		if envSeen[target] {
			return
		}
		envSeen[target] = true
		e := extraEnv[target]
		for k, v := range h.Env {
			e = append(e, k+"="+v)
		}
		if net.APIKey != "" {
			e = append(e, "TAILSCALE_API_KEY="+net.APIKey)
		}
		extraEnv[target] = e
	}
	// targetKey composes a host-unique plugin target. Two hosts on the same
	// platform get distinct keys, so each gets its own plugin subprocess and
	// its own credentials rather than colliding on the platform name.
	targetKey := func(h Host) string { return h.Platform + orchestrator.TargetSep + h.Name }
	withTailnet := func(cfg map[string]any) map[string]any {
		out := map[string]any{}
		for k, v := range cfg {
			out[k] = v
		}
		out["tailnet"] = net.Tailnet
		return out
	}

	msspTarget := targetKey(msspHost)
	addEnv(msspTarget, msspHost)

	tenants := make([]orchestrator.VMSpec, 0, len(req.Tenants))
	for _, t := range req.Tenants {
		if t.Slug == "" || t.Host == "" {
			return orchestrator.Config{}, nil, fmt.Errorf("each tenant needs a slug and a host")
		}
		th, ok, err := s.Hosts.get(t.Host)
		if err != nil || !ok {
			return orchestrator.Config{}, nil, fmt.Errorf("host %q not found", t.Host)
		}
		spec := orchestrator.VMSpec{
			Key: "tenant-" + t.Slug, Name: "soctalk-tenant-" + t.Slug,
			Role: "tenant", TenantSlug: t.Slug,
			Tags: map[string]string{"role": "tenant", "tenant_slug": t.Slug},
		}
		// Each tenant is pinned to its host's composed target and config. When
		// the target matches the MSSP's (same host) they share one subprocess;
		// when it differs they get their own, even on the same platform.
		spec.Target = targetKey(th)
		spec.PluginConfig = withTailnet(th.Config)
		addEnv(spec.Target, th)
		tenants = append(tenants, spec)
	}

	cfg := orchestrator.Config{
		RunID:        req.RunID,
		Target:       msspTarget,
		PluginConfig: withTailnet(msspHost.Config),
		SSHKeys:      toStrSlice(msspHost.Config["ssh_keys"]),
		MSSP:         orchestrator.VMSpec{Key: "mssp", Name: "soctalk-mssp", Role: "mssp", Tags: map[string]string{"role": "mssp"}},
		Tenants:      tenants,
		Install:      req.Install,
	}
	return cfg, extraEnv, nil
}

func toStrSlice(v any) []string {
	arr, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(arr))
	for _, x := range arr {
		if s, ok := x.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func (s *Server) handleGetRun(w http.ResponseWriter, r *http.Request) {
	run, ok := s.Mgr.Get(r.PathValue("id"))
	if !ok {
		writeErr(w, http.StatusNotFound, "not_found", "no such run")
		return
	}
	writeJSON(w, http.StatusOK, s.Mgr.SnapshotOf(run))
}

func (s *Server) handleGetEvents(w http.ResponseWriter, r *http.Request) {
	run, ok := s.Mgr.Get(r.PathValue("id"))
	if !ok {
		writeErr(w, http.StatusNotFound, "not_found", "no such run")
		return
	}
	since, _ := strconv.ParseInt(r.URL.Query().Get("since_seq"), 10, 64)
	writeJSON(w, http.StatusOK, run.Journal.Snapshot(since))
}

func (s *Server) handleCancel(w http.ResponseWriter, r *http.Request) {
	if err := s.Mgr.Cancel(r.PathValue("id")); err != nil {
		writeErr(w, http.StatusNotFound, "not_found", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleDown(w http.ResponseWriter, r *http.Request) {
	if err := s.Mgr.Down(r.PathValue("id")); err != nil {
		writeErr(w, http.StatusConflict, "down_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleResolveGate(w http.ResponseWriter, r *http.Request) {
	if err := s.Mgr.ResolveGate(r.PathValue("id"), r.PathValue("gid")); err != nil {
		writeErr(w, http.StatusNotFound, "not_found", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}
