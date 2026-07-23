package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func testState() *serverState {
	return &serverState{
		token:     "testtoken",
		csrfKey:   mustRandomBytes(32),
		rateLimit: newRateLimiter(),
	}
}

// The headline fix: an unauthenticated /submit must return a friendly,
// structured error with recovery guidance — NOT a bare 403 "csrf check failed".
func TestSubmitUnauthenticatedIsFriendly(t *testing.T) {
	s := testState()
	req := httptest.NewRequest(http.MethodPost, "/submit",
		strings.NewReader("mssp_name=x"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	s.handleSubmit(rec, req)

	if rec.Code != http.StatusUnauthorized && rec.Code != http.StatusForbidden {
		t.Fatalf("want 401/403, got %d", rec.Code)
	}
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("response not JSON (regression to bare http.Error): %q", rec.Body.String())
	}
	if body["error"] != "session_expired" {
		t.Errorf("error code = %q, want session_expired", body["error"])
	}
	if body["message"] == "" || body["recovery"] == "" {
		t.Errorf("message/recovery must be populated, got %+v", body)
	}
	if !strings.Contains(body["recovery"], "soctalk-setup-token") {
		t.Errorf("recovery must tell the user where to get the token, got %q", body["recovery"])
	}
}

// A validation failure is reported as structured JSON with recovery, not
// "validation: <err>" plain text.
func TestSubmitValidationIsFriendly(t *testing.T) {
	s := testState()
	// Authenticate so we reach validation.
	sess := csrfToken(s.csrfKey, s.token)
	form := url.Values{"csrf": {sess}, "mssp_name": {""}}
	req := httptest.NewRequest(http.MethodPost, "/submit", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "soctalk_session", Value: sess})
	req.AddCookie(&http.Cookie{Name: "soctalk_csrf", Value: sess})
	rec := httptest.NewRecorder()
	s.handleSubmit(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d (%s)", rec.Code, rec.Body.String())
	}
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("not JSON: %q", rec.Body.String())
	}
	if body["error"] != "validation" || body["recovery"] == "" {
		t.Errorf("want validation error + recovery, got %+v", body)
	}
}

// A failed token submit renders a friendly inline message above the form,
// not a bare 401 page.
func TestRootRendersAuthError(t *testing.T) {
	s := testState()
	req := httptest.NewRequest(http.MethodGet, "/?err=invalid_token", nil)
	rec := httptest.NewRecorder()
	s.handleRoot(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rec.Code)
	}
	html := rec.Body.String()
	if !strings.Contains(html, "not recognized") || !strings.Contains(html, "soctalk-setup-token") {
		t.Errorf("expected friendly invalid-token guidance in page, got:\n%s", html)
	}
}

// /status is authorizable by the session cookie (so the in-page poller needs no
// token), and rejects unauthenticated callers with structured JSON.
func TestStatusCookieAuthAndFriendlyReject(t *testing.T) {
	s := testState()
	s.updateStatus("running", "writing values file", "", "")

	// No auth -> friendly JSON 401.
	rec := httptest.NewRecorder()
	s.handleStatus(rec, httptest.NewRequest(http.MethodGet, "/status", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauth /status: want 401, got %d", rec.Code)
	}
	var body map[string]string
	if json.Unmarshal(rec.Body.Bytes(), &body) != nil || body["error"] != "session_expired" {
		t.Errorf("unauth /status not friendly JSON: %q", rec.Body.String())
	}

	// With the session cookie -> 200 + status JSON.
	req := httptest.NewRequest(http.MethodGet, "/status", nil)
	req.AddCookie(&http.Cookie{Name: "soctalk_session", Value: csrfToken(s.csrfKey, s.token)})
	rec2 := httptest.NewRecorder()
	s.handleStatus(rec2, req)
	if rec2.Code != http.StatusOK {
		t.Fatalf("cookie /status: want 200, got %d (%s)", rec2.Code, rec2.Body.String())
	}
	var st installStatus
	if err := json.Unmarshal(rec2.Body.Bytes(), &st); err != nil || st.Phase != "running" {
		t.Errorf("cookie /status body = %q", rec2.Body.String())
	}
}
