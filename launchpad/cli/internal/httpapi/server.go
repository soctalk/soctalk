// Package httpapi is the web surface of the launchpad: REST for mutations,
// WebSocket for the live event stream, and the embedded SvelteKit SPA.
// Loopback-only by design; every request carries a per-server token and the
// Origin header is checked against an allowlist (never CheckOrigin:true).
package httpapi

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"

	"github.com/soctalk/launchpad/internal/runmanager"
)

// Server wires the manager to HTTP.
type Server struct {
	Mgr      *runmanager.Manager
	Hosts    *hostStore
	Networks *networkStore
	Token    string
	Dev      bool // dev mode: no embedded SPA (Vite serves it)

	addr string
}

// New creates a server with a fresh random token. dir is the launchpad state
// dir (~/.launchpad) where hosts.json / networks.json live.
func New(mgr *runmanager.Manager, dir string, dev bool) *Server {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return &Server{Mgr: mgr, Hosts: newHostStore(dir), Networks: newNetworkStore(dir),
		Token: hex.EncodeToString(b), Dev: dev}
}

// Handler builds the full route table.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/runs", s.handleListRuns)
	mux.HandleFunc("POST /api/runs", s.handleStartRun)
	mux.HandleFunc("GET /api/runs/{id}", s.handleGetRun)
	mux.HandleFunc("GET /api/runs/{id}/events", s.handleGetEvents)
	mux.HandleFunc("GET /api/runs/{id}/ws", s.handleWS)
	mux.HandleFunc("POST /api/runs/{id}/cancel", s.handleCancel)
	mux.HandleFunc("POST /api/runs/{id}/down", s.handleDown)
	mux.HandleFunc("POST /api/runs/{id}/gates/{gid}", s.handleResolveGate)
	// Platforms (discovered plugins + config schema) and Hosts (saved target
	// configs) — the "where" model that replaces hard-coded preset cards.
	mux.HandleFunc("GET /api/platforms", s.handleListPlatforms)
	mux.HandleFunc("GET /api/hosts", s.handleListHosts)
	mux.HandleFunc("PUT /api/hosts/{name}", s.handlePutHost)
	mux.HandleFunc("DELETE /api/hosts/{name}", s.handleDeleteHost)
	mux.HandleFunc("POST /api/hosts/{name}/probe", s.handleProbeHost)
	mux.HandleFunc("GET /api/networks", s.handleListNetworks)
	mux.HandleFunc("PUT /api/networks/{name}", s.handlePutNetwork)
	mux.HandleFunc("DELETE /api/networks/{name}", s.handleDeleteNetwork)
	mux.HandleFunc("POST /api/networks/{name}/probe", s.handleProbeNetwork)
	if !s.Dev {
		mux.Handle("/", s.staticHandler())
	}
	return s.middleware(mux)
}

// ListenAndServe binds 127.0.0.1:port (0 = random) and serves until the
// process exits. Prints the tokenized URL on stdout for the caller.
func (s *Server) ListenAndServe(port int) error {
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return err
	}
	s.addr = ln.Addr().String()
	fmt.Printf("launchpad ui: http://%s/?t=%s\n", s.addr, s.Token)
	return http.Serve(ln, s.Handler())
}

// Addr returns the bound address (after ListenAndServe).
func (s *Server) Addr() string { return s.addr }
