package main

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
)

//go:embed templates/setup.html
var setupHTML string

//go:embed templates/success.html
var successHTML string

//go:embed static/style.css
var styleCSS string

type installRequest struct {
	Hostname     string `json:"hostname"`     // optional FQDN
	MSSPName     string `json:"mssp_name"`
	AdminEmail   string `json:"admin_email"`
	AdminPW      string `json:"admin_pw"`
	LLMProvider  string `json:"llm_provider"` // anthropic | openai
	LLMAPIKey    string `json:"llm_api_key"`
}

type installStatus struct {
	Phase    string    `json:"phase"`    // pending|running|success|error
	Message  string    `json:"message"`
	UIURL    string    `json:"ui_url,omitempty"`
	Error    string    `json:"error,omitempty"`
	Updated  time.Time `json:"updated"`
}

type serverState struct {
	token              string
	csrfKey            []byte
	rateLimit          *rateLimiter
	installCh          chan installRequest
	statusCh           chan installStatus
	wizardSentinelPath string
	valuesPath         string
	llmKeyPath         string
	startedAt          time.Time

	mu     sync.RWMutex
	status installStatus
}

func (s *serverState) handleRoot(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	// GET / shows EITHER the token-entry form (no soctalk_session cookie)
	// or the main config form (cookie present + valid). The browser
	// transitions between the two via POST /auth (token form submit).
	authenticated := s.checkAuthCookie(r)
	csrf := ""
	if authenticated {
		csrf = csrfToken(s.csrfKey, s.token)
		http.SetCookie(w, &http.Cookie{
			Name:     "soctalk_csrf",
			Value:    csrf,
			Path:     "/",
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteStrictMode,
		})
	}
	tmpl, err := template.New("setup").Parse(setupHTML)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_ = tmpl.Execute(w, map[string]any{
		"Authenticated": authenticated,
		"CSRF":          csrf,
		"Providers":     []string{"anthropic", "openai"},
	})
}

// handleAuth processes the token-entry form. On success, sets a session
// cookie bound to the wizard's token (HttpOnly + Secure + SameSite=Strict)
// and redirects to /. Rate-limited.
func (s *serverState) handleAuth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	ip := clientIP(r)
	ok, retry := s.rateLimit.allowAttempt(ip)
	if !ok {
		w.Header().Set("Retry-After", fmt.Sprintf("%d", int(retry.Seconds()+1)))
		http.Error(w, "rate limited", http.StatusTooManyRequests)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	presented := r.FormValue("token")
	if !tokenMatch(s.token, presented) {
		s.rateLimit.recordFailure(ip)
		http.Error(w, "invalid token", http.StatusUnauthorized)
		return
	}
	s.rateLimit.recordSuccess(ip)
	http.SetCookie(w, &http.Cookie{
		Name:     "soctalk_session",
		Value:    csrfToken(s.csrfKey, s.token), // value bound to wizard's key+token
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// checkAuthCookie verifies the soctalk_session cookie is the expected
// HMAC of the wizard's token. Constant-time compare.
func (s *serverState) checkAuthCookie(r *http.Request) bool {
	c, err := r.Cookie("soctalk_session")
	if err != nil {
		return false
	}
	return csrfMatch(s.csrfKey, s.token, c.Value)
}

func (s *serverState) handleStatic(w http.ResponseWriter, r *http.Request) {
	switch strings.TrimPrefix(r.URL.Path, "/static/") {
	case "style.css":
		w.Header().Set("Content-Type", "text/css")
		_, _ = w.Write([]byte(styleCSS))
	default:
		http.NotFound(w, r)
	}
}

func (s *serverState) handleSubmit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	ip := clientIP(r)
	ok, _ := s.rateLimit.allowAttempt(ip)
	if !ok {
		http.Error(w, "rate limited", http.StatusTooManyRequests)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	// Session must be valid (token-form was completed) AND CSRF must match.
	if !s.checkAuthCookie(r) {
		http.Error(w, "auth required", http.StatusUnauthorized)
		return
	}
	cookie, err := r.Cookie("soctalk_csrf")
	if err != nil || !csrfMatch(s.csrfKey, s.token, cookie.Value) || cookie.Value != r.FormValue("csrf") {
		http.Error(w, "csrf check failed", http.StatusForbidden)
		return
	}

	req := installRequest{
		Hostname:    strings.TrimSpace(r.FormValue("hostname")),
		MSSPName:    strings.TrimSpace(r.FormValue("mssp_name")),
		AdminEmail:  strings.TrimSpace(r.FormValue("admin_email")),
		AdminPW:     r.FormValue("admin_pw"),
		LLMProvider: r.FormValue("llm_provider"),
		LLMAPIKey:   strings.TrimSpace(r.FormValue("llm_api_key")),
	}
	if err := req.validate(); err != nil {
		http.Error(w, "validation: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Hand off to the install worker. Non-blocking — duplicate submit
	// while one is in flight is silently dropped.
	select {
	case s.installCh <- req:
	default:
		http.Error(w, "install already running", http.StatusConflict)
		return
	}

	s.rateLimit.recordSuccess(ip)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status": "accepted",
		"poll":   "/status",
	})
}

func (s *serverState) handleStatus(w http.ResponseWriter, r *http.Request) {
	if presented := r.URL.Query().Get("token"); !tokenMatch(s.token, presented) {
		http.Error(w, "invalid token", http.StatusUnauthorized)
		return
	}
	s.mu.RLock()
	st := s.status
	s.mu.RUnlock()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(st)
}

func (s *serverState) handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

func (s *serverState) updateStatus(phase, msg, ui, errStr string) {
	st := installStatus{
		Phase:   phase,
		Message: msg,
		UIURL:   ui,
		Error:   errStr,
		Updated: time.Now(),
	}
	s.mu.Lock()
	s.status = st
	s.mu.Unlock()
	log.Printf("status: %s — %s", phase, msg)
}

func (r installRequest) validate() error {
	if r.MSSPName == "" {
		return fmt.Errorf("mssp_name required")
	}
	if r.AdminEmail == "" || !strings.Contains(r.AdminEmail, "@") {
		return fmt.Errorf("admin_email looks invalid")
	}
	if len(r.AdminPW) < 12 {
		return fmt.Errorf("admin_pw must be at least 12 chars")
	}
	if r.LLMProvider != "anthropic" && r.LLMProvider != "openai" {
		return fmt.Errorf("llm_provider must be anthropic or openai")
	}
	if r.LLMAPIKey == "" {
		return fmt.Errorf("llm_api_key required")
	}
	return nil
}
