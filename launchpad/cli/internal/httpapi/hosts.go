package httpapi

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"sync"
)

// Host is a named, saved configuration of a virtualization platform + its
// connection details and credentials — configured once, referenced by name
// when placing VMs. This is the "where" half of a run (the "what" is the
// scenario/topology; the overlay is the Network).
type Host struct {
	Name     string         `json:"name"`
	Platform string         `json:"platform"` // plugin name, e.g. qemu / vmware
	Config   map[string]any `json:"config"`   // non-secret plugin_config for that platform
	// Env are secret env vars injected into the plugin subprocess for this
	// host (e.g. ESXI_USERNAME/ESXI_PASSWORD) — never launchpad process env.
	// Redacted in list responses.
	Env map[string]string `json:"env,omitempty"`
}

// redacted returns a copy with secret env values masked for HTTP responses.
func (h Host) redacted() Host {
	if len(h.Env) > 0 {
		masked := make(map[string]string, len(h.Env))
		for k := range h.Env {
			masked[k] = secretPlaceholder
		}
		h.Env = masked
	}
	return h
}

// hostStore persists hosts to ~/.launchpad/hosts.json.
type hostStore struct {
	mu   sync.Mutex
	path string
}

func newHostStore(dir string) *hostStore {
	return &hostStore{path: filepath.Join(dir, "hosts.json")}
}

func (h *hostStore) load() (map[string]Host, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.loadLocked()
}

func (h *hostStore) loadLocked() (map[string]Host, error) {
	out := map[string]Host{}
	b, err := os.ReadFile(h.path)
	if err != nil {
		if os.IsNotExist(err) {
			return out, nil
		}
		return nil, err
	}
	_ = json.Unmarshal(b, &out)
	if out == nil {
		out = map[string]Host{}
	}
	return out, nil
}

func (h *hostStore) saveLocked(hosts map[string]Host) error {
	if err := os.MkdirAll(filepath.Dir(h.path), 0o755); err != nil {
		return err
	}
	tmp := h.path + ".tmp"
	b, _ := json.MarshalIndent(hosts, "", "  ")
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, h.path)
}

// get returns one host with real (unredacted) secrets — internal use only.
func (h *hostStore) get(name string) (Host, bool, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	hosts, err := h.loadLocked()
	if err != nil {
		return Host{}, false, err
	}
	hv, ok := hosts[name]
	return hv, ok, nil
}

func (h *hostStore) put(host Host) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	hosts, err := h.loadLocked()
	if err != nil {
		return err
	}
	// Preserve existing secret env values when the caller sends the redaction
	// placeholder (an edit that didn't re-enter the secret).
	if prev, ok := hosts[host.Name]; ok {
		for k, v := range host.Env {
			if v == secretPlaceholder {
				host.Env[k] = prev.Env[k]
			}
		}
	}
	hosts[host.Name] = host
	return h.saveLocked(hosts)
}

func (h *hostStore) delete(name string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	hosts, err := h.loadLocked()
	if err != nil {
		return err
	}
	delete(hosts, name)
	return h.saveLocked(hosts)
}

// --- HTTP handlers ---

func (s *Server) handleListHosts(w http.ResponseWriter, r *http.Request) {
	hosts, err := s.Hosts.load()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "hosts_load", err.Error())
		return
	}
	out := make([]Host, 0, len(hosts))
	for _, hv := range hosts {
		out = append(out, hv.redacted())
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handlePutHost(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	var host Host
	if err := json.NewDecoder(r.Body).Decode(&host); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_host", err.Error())
		return
	}
	host.Name = name
	if host.Platform == "" {
		writeErr(w, http.StatusBadRequest, "bad_host", "platform is required")
		return
	}
	if err := s.Hosts.put(host); err != nil {
		writeErr(w, http.StatusInternalServerError, "hosts_save", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, host.redacted())
}

func (s *Server) handleDeleteHost(w http.ResponseWriter, r *http.Request) {
	if err := s.Hosts.delete(r.PathValue("name")); err != nil {
		writeErr(w, http.StatusInternalServerError, "hosts_delete", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}
