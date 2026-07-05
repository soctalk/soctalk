package httpapi

import (
	"encoding/json"
	"net/http"
	"strings"
)

// middleware enforces token auth on /api/* and an Origin allowlist on
// state-changing + WS requests. Static assets are token-free (the SPA itself
// carries no secrets; the API it calls is what's protected).
func (s *Server) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") {
			if !s.tokenOK(r) {
				writeErr(w, http.StatusUnauthorized, "unauthorized", "missing or bad token")
				return
			}
			if !s.originOK(r) {
				writeErr(w, http.StatusForbidden, "bad_origin", "origin not allowed")
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) tokenOK(r *http.Request) bool {
	if r.Header.Get("X-Launchpad-Token") == s.Token {
		return true
	}
	return r.URL.Query().Get("t") == s.Token
}

// originOK rejects cross-site callers. Browsers always send Origin on
// cross-origin fetches and WS upgrades; same-origin GETs may omit it.
func (s *Server) originOK(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true // same-origin navigations / curl
	}
	for _, allowed := range []string{
		"http://" + r.Host,
		"http://localhost:5173", // Vite dev server
		"http://127.0.0.1:5173",
	} {
		if origin == allowed {
			return true
		}
	}
	return false
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, errCode, msg string) {
	writeJSON(w, code, map[string]any{
		"error": map[string]string{"code": errCode, "message": msg},
	})
}
