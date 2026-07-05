package httpapi

import (
	"embed"
	"io/fs"
	"net/http"
	"strings"
)

// frontend_build is populated by the Makefile (cp -R frontend/build →
// internal/httpapi/frontend_build) before `go build`. The all: prefix keeps
// _app/ (underscore-prefixed) files in the embed.
//
//go:embed all:frontend_build
var frontendFS embed.FS

// staticHandler serves the embedded SPA with an index.html fallback so
// client-side routes like /runs/abc survive a hard refresh.
func (s *Server) staticHandler() http.Handler {
	sub, err := fs.Sub(frontendFS, "frontend_build")
	if err != nil {
		return http.NotFoundHandler()
	}
	fileServer := http.FileServer(http.FS(sub))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := strings.TrimPrefix(r.URL.Path, "/")
		if p != "" {
			if _, err := fs.Stat(sub, p); err != nil {
				r.URL.Path = "/"
			}
		}
		fileServer.ServeHTTP(w, r)
	})
}
