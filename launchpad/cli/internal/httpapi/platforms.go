package httpapi

import (
	"context"
	"net/http"
	"sync"
	"time"

	"github.com/soctalk/launchpad/internal/pluginhost"
)

// Platform is a discovered virtualization plugin, self-described via its Hello
// frame (capabilities + JSON-schema config). The UI renders host-config forms
// from ConfigSchema, so adding a platform is a drop-in plugin — no UI change.
type Platform struct {
	Name         string         `json:"name"`
	Version      string         `json:"version"`
	Capabilities []string       `json:"capabilities"`
	ConfigSchema map[string]any `json:"config_schema,omitempty"`
	// CredentialEnv are the secret env vars this platform needs supplied per
	// host (its manifest env allow-list, minus the network-owned Tailscale key
	// and infra vars like HOME/SSH_AUTH_SOCK). The host editor prompts for these.
	CredentialEnv []string `json:"credential_env,omitempty"`
	Available     bool     `json:"available"` // handshake succeeded
	Error         string   `json:"error,omitempty"`
}

// credentialEnv filters a plugin's manifest env allow-list down to the secret
// credentials a host must supply (network + infra vars are handled elsewhere).
func credentialEnv(env []string) []string {
	skip := map[string]bool{
		"TAILSCALE_API_KEY": true, // network-owned
		"ESXI_URL":          true, // provided via config (esxi_url), not a secret
		"AWS_REGION":        true, // provided via config (region), not a secret
		"HOME":              true,
		"SSH_AUTH_SOCK":     true,
		"PATH":              true,
	}
	out := []string{}
	for _, e := range env {
		if !skip[e] {
			out = append(out, e)
		}
	}
	return out
}

// platformCache memoizes discovery — starting every plugin subprocess to read
// its Hello is too heavy to do per request.
type platformCache struct {
	mu   sync.Mutex
	at   time.Time
	data []Platform
}

var pcache platformCache

const platformCacheTTL = 30 * time.Second

// discoverPlatforms enumerates plugin manifests and, for each, briefly starts
// the subprocess to capture its Hello (capabilities + config schema), then
// shuts it down.
func discoverPlatforms(ctx context.Context) []Platform {
	pcache.mu.Lock()
	if time.Since(pcache.at) < platformCacheTTL && pcache.data != nil {
		out := pcache.data
		pcache.mu.Unlock()
		return out
	}
	pcache.mu.Unlock()

	manifests, _ := pluginhost.DiscoverPlugins()
	out := make([]Platform, 0, len(manifests))
	for _, m := range manifests {
		p := Platform{Name: m.Name, Version: m.Version, CredentialEnv: credentialEnv(m.Env)}
		sctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		client, err := pluginhost.Start(sctx, m, pluginhost.StartConfig{EnvAllowlist: m.Env})
		if err != nil {
			p.Error = err.Error()
			cancel()
			out = append(out, p)
			continue
		}
		p.Available = true
		p.Capabilities = client.Hello.Capabilities
		p.ConfigSchema = client.Hello.ConfigSchema
		if p.Version == "" {
			p.Version = client.Hello.PluginVersion
		}
		_ = client.Shutdown(sctx)
		cancel()
		out = append(out, p)
	}

	pcache.mu.Lock()
	pcache.at = time.Now()
	pcache.data = out
	pcache.mu.Unlock()
	return out
}

func (s *Server) handleListPlatforms(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, discoverPlatforms(r.Context()))
}
