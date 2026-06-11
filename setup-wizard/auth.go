package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"net/http"
	"sync"
	"time"
)

// rateLimiter tracks failed-token attempts per source IP. After
// `maxFailures` failures in `failureWindow`, the IP is blocked for
// `blockDuration`. Successful attempts reset the counter.
type rateLimiter struct {
	mu        sync.Mutex
	attempts  map[string][]time.Time
	blocked   map[string]time.Time
}

const (
	rlMaxFailures   = 10
	rlFailureWindow = 1 * time.Hour
	rlBlockDuration = 1 * time.Hour
	rlMinInterval   = 30 * time.Second
)

func newRateLimiter() *rateLimiter {
	return &rateLimiter{
		attempts: make(map[string][]time.Time),
		blocked:  make(map[string]time.Time),
	}
}

// allowAttempt returns true if the IP is permitted to make an attempt
// now. It enforces both a minimum inter-attempt interval and a long-
// term failure budget. Successful attempts must call recordSuccess.
func (r *rateLimiter) allowAttempt(ip string) (ok bool, retryAfter time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()

	if until, blocked := r.blocked[ip]; blocked {
		if now.Before(until) {
			return false, until.Sub(now)
		}
		delete(r.blocked, ip)
	}

	// Drop attempts outside the window.
	cur := r.attempts[ip]
	cutoff := now.Add(-rlFailureWindow)
	pruned := cur[:0]
	for _, t := range cur {
		if t.After(cutoff) {
			pruned = append(pruned, t)
		}
	}
	r.attempts[ip] = pruned

	// Inter-attempt interval gate.
	if n := len(pruned); n > 0 {
		if since := now.Sub(pruned[n-1]); since < rlMinInterval {
			return false, rlMinInterval - since
		}
	}
	return true, 0
}

func (r *rateLimiter) recordFailure(ip string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.attempts[ip] = append(r.attempts[ip], time.Now())
	if len(r.attempts[ip]) >= rlMaxFailures {
		r.blocked[ip] = time.Now().Add(rlBlockDuration)
	}
}

func (r *rateLimiter) recordSuccess(ip string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.attempts, ip)
}

// csrfToken returns an HMAC of the session token using the server's
// CSRF key. The browser stores the cookie copy; the form embeds the
// same value; we compare on POST. This binds CSRF to the session, not
// per-request, which is fine for a single-page wizard.
func csrfToken(key []byte, sessionID string) string {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(sessionID))
	return hex.EncodeToString(h.Sum(nil))
}

func csrfMatch(key []byte, sessionID, presented string) bool {
	expected := csrfToken(key, sessionID)
	return subtle.ConstantTimeCompare([]byte(expected), []byte(presented)) == 1
}

// tokenMatch is constant-time comparison.
func tokenMatch(expected, presented string) bool {
	return subtle.ConstantTimeCompare([]byte(expected), []byte(presented)) == 1
}

// clientIP extracts the originating IP. We don't trust X-Forwarded-For
// because the wizard is meant for direct LAN access.
func clientIP(r *http.Request) string {
	addr := r.RemoteAddr
	for i := len(addr) - 1; i >= 0; i-- {
		if addr[i] == ':' {
			return addr[:i]
		}
	}
	return addr
}
