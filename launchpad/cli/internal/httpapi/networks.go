package httpapi

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"sync"
)

// Network is the overlay VMs join for a run — a first-class resource so the
// tailnet + its API key live here (not as launchpad env vars), and a run binds
// to exactly one network. Every VM in a run joins the SAME network regardless
// of which host it runs on.
type Network struct {
	Name    string `json:"name"`
	Kind    string `json:"kind"`    // tailscale (room for netbird/zerotier/direct later)
	Tailnet string `json:"tailnet"` // e.g. tailxxxx.ts.net
	APIKey  string `json:"api_key"` // SECRET — redacted in list responses
}

// redacted returns a copy safe to serialize over HTTP (presence-only secret).
func (n Network) redacted() Network {
	if n.APIKey != "" {
		n.APIKey = secretPlaceholder
	}
	return n
}

const secretPlaceholder = "__set__"

type networkStore struct {
	mu   sync.Mutex
	path string
}

func newNetworkStore(dir string) *networkStore {
	return &networkStore{path: filepath.Join(dir, "networks.json")}
}

func (s *networkStore) loadLocked() (map[string]Network, error) {
	out := map[string]Network{}
	b, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return out, nil
		}
		return nil, err
	}
	_ = json.Unmarshal(b, &out)
	if out == nil {
		out = map[string]Network{}
	}
	return out, nil
}

func (s *networkStore) saveLocked(m map[string]Network) error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	b, _ := json.MarshalIndent(m, "", "  ")
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

// get returns one network with its real (unredacted) secret — for internal
// run composition only, never sent over HTTP.
func (s *networkStore) get(name string) (Network, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, err := s.loadLocked()
	if err != nil {
		return Network{}, false, err
	}
	n, ok := m[name]
	return n, ok, nil
}

func (s *networkStore) put(n Network) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, err := s.loadLocked()
	if err != nil {
		return err
	}
	// Preserve an existing key when the caller sends the redaction placeholder
	// (an edit that didn't change the secret).
	if n.APIKey == secretPlaceholder {
		if prev, ok := m[n.Name]; ok {
			n.APIKey = prev.APIKey
		} else {
			n.APIKey = ""
		}
	}
	m[n.Name] = n
	return s.saveLocked(m)
}

func (s *networkStore) delete(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, err := s.loadLocked()
	if err != nil {
		return err
	}
	delete(m, name)
	return s.saveLocked(m)
}

// --- HTTP handlers ---

func (s *Server) handleListNetworks(w http.ResponseWriter, r *http.Request) {
	s.Networks.mu.Lock()
	m, err := s.Networks.loadLocked()
	s.Networks.mu.Unlock()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "net_load", err.Error())
		return
	}
	out := make([]Network, 0, len(m))
	for _, n := range m {
		out = append(out, n.redacted())
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handlePutNetwork(w http.ResponseWriter, r *http.Request) {
	var n Network
	if err := json.NewDecoder(r.Body).Decode(&n); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_network", err.Error())
		return
	}
	n.Name = r.PathValue("name")
	if n.Kind == "" {
		n.Kind = "tailscale"
	}
	if err := s.Networks.put(n); err != nil {
		writeErr(w, http.StatusInternalServerError, "net_save", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, n.redacted())
}

func (s *Server) handleDeleteNetwork(w http.ResponseWriter, r *http.Request) {
	if err := s.Networks.delete(r.PathValue("name")); err != nil {
		writeErr(w, http.StatusInternalServerError, "net_delete", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}
