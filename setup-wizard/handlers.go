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
		"AuthError":     authErrorMessage(r.URL.Query().Get("err")),
	})
}

// authErrorMessage maps an ?err= code (set by handleAuth on a failed token
// submit) to a human-readable, recovery-oriented message rendered above the
// token form. Empty for no error.
func authErrorMessage(code string) string {
	switch code {
	case "invalid_token":
		return "That setup token was not recognized. The token changes every time the wizard restarts — re-copy the current one with:  sudo cat /var/log/soctalk-setup-token"
	case "rate_limited":
		return "Too many attempts in a short time. Wait about a minute, then try again."
	case "bad_form":
		return "The form could not be read. Please try again."
	default:
		return ""
	}
}

// handleAuth processes the token-entry form. On success, sets a session
// cookie bound to the wizard's token (HttpOnly + Secure + SameSite=Strict)
// and redirects to /. Rate-limited.
func (s *serverState) handleAuth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	// The token form is a plain POST->redirect (no JS), so on failure we
	// redirect back to "/" with an ?err= code that handleRoot renders as a
	// friendly inline message above the form — never a bare 401/429 page.
	ip := clientIP(r)
	ok, _ := s.rateLimit.allowAttempt(ip)
	if !ok {
		http.Redirect(w, r, "/?err=rate_limited", http.StatusSeeOther)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/?err=bad_form", http.StatusSeeOther)
		return
	}
	presented := r.FormValue("token")
	if !tokenMatch(s.token, presented) {
		s.rateLimit.recordFailure(ip)
		http.Redirect(w, r, "/?err=invalid_token", http.StatusSeeOther)
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
		writeJSONError(w, http.StatusTooManyRequests, "rate_limited",
			"Too many attempts in a short time.", "Wait about a minute, then submit again.")
		return
	}

	if err := r.ParseForm(); err != nil {
		writeJSONError(w, http.StatusBadRequest, "bad_request",
			"The form could not be read.", "Reload this page and try again.")
		return
	}
	// Session + CSRF must be valid. Both break the same way — the wizard
	// regenerates its token and CSRF key on every (re)start, so a page opened
	// before a restart submits stale cookies. Report that plainly with the
	// exact recovery steps instead of a bare 401/403.
	if !s.checkAuthCookie(r) {
		writeJSONError(w, http.StatusUnauthorized, "session_expired", sessionExpiredMsg, sessionExpiredRecovery)
		return
	}
	cookie, err := r.Cookie("soctalk_csrf")
	if err != nil || !csrfMatch(s.csrfKey, s.token, cookie.Value) || cookie.Value != r.FormValue("csrf") {
		writeJSONError(w, http.StatusForbidden, "session_expired", sessionExpiredMsg, sessionExpiredRecovery)
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
		writeJSONError(w, http.StatusBadRequest, "validation",
			err.Error(), "Correct that detail in the form and submit again.")
		return
	}

	// Hand off to the install worker. Non-blocking — duplicate submit
	// while one is in flight is silently dropped.
	select {
	case s.installCh <- req:
	default:
		writeJSONError(w, http.StatusConflict, "in_progress",
			"Setup was already submitted and is running.",
			"Watch the status below — no need to submit again.")
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
	// Authorize by the session cookie (so the in-page poller needs no token in
	// the DOM) OR an explicit ?token= (for SSH/curl checks).
	if !s.checkAuthCookie(r) && !tokenMatch(s.token, r.URL.Query().Get("token")) {
		writeJSONError(w, http.StatusUnauthorized, "session_expired", sessionExpiredMsg, sessionExpiredRecovery)
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

// The session/CSRF failure the operator most often hits: the wizard restarted
// (its unit is Restart=on-failure, first-boot may retry, or the VM rebooted),
// which regenerates the token + CSRF key, so a page opened earlier now carries
// stale cookies. Same message + recovery for the 401 (session) and 403 (CSRF)
// forms, since the cause and fix are identical.
const (
	sessionExpiredMsg      = "Your setup session expired — the wizard restarted since this page was opened."
	sessionExpiredRecovery = "Reload this page and re-enter the current setup token. The token changes each time the wizard restarts — get it with:  sudo cat /var/log/soctalk-setup-token"
)

// writeJSONError sends a structured, human-readable error the browser renders
// as message + recovery guidance (never a bare status-code page).
func writeJSONError(w http.ResponseWriter, status int, code, message, recovery string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":    code,
		"message":  message,
		"recovery": recovery,
	})
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
