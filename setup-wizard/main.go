// Package main is the SocTalk first-boot setup wizard.
//
// Boots as a systemd unit before k3s starts (when no cloud-init values
// were supplied), exposes a single-page HTTPS form on :443 with a self-
// signed cert, collects the customer's install config, runs helm
// install, then writes a sentinel and disables itself.
//
// Auth: a 32-byte hex token generated at startup and printed to
// console + /var/log/soctalk-setup-token (0600 root) + /etc/issue.
// Required as ?token=<value> on first GET and as a hidden field on
// POST /submit. CSRF protection via signed cookie + form token.
// Rate-limited at 1 attempt per 30s per IP; 10 invalid token attempts
// trigger a 1h IP block.
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"
)

var (
	// :8443 deliberately. Codex v2: do not fight Traefik for :443.
	addr               = flag.String("addr", ":8443", "listen address")
	wizardSentinelPath = flag.String("wizard-sentinel", "/var/lib/soctalk-wizard.done", "sentinel the wizard writes after collecting config (installer waits for either this OR cloud-init's values.yaml)")
	installSentinel    = flag.String("install-sentinel", "/var/lib/soctalk-firstboot.done", "sentinel written by the installer (not the wizard) when helm install completes")
	valuesPath         = flag.String("values-out", "/etc/soctalk/values.yaml", "where to write generated helm values")
	llmKeyPath         = flag.String("llm-key-out", "/etc/soctalk/llm.key", "where to write LLM API key")
	tokenLogPath       = flag.String("token-log", "/var/log/soctalk-setup-token", "where to write the setup token for SSH retrieval")
	certDir            = flag.String("cert-dir", "/var/lib/soctalk-wizard", "where to keep self-signed cert + key")
)

func main() {
	flag.Parse()

	// Defense in depth: don't bind if any sentinel is present.
	// systemd's ConditionPathExists also gates this at unit level,
	// but a manual `systemctl start` shouldn't bypass it either.
	for _, p := range []string{*wizardSentinelPath, *installSentinel, *valuesPath} {
		if _, err := os.Stat(p); err == nil {
			log.Printf("found %s; nothing to do", p)
			os.Exit(0)
		}
	}

	// Generate 256-bit setup token.
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		log.Fatalf("rand: %v", err)
	}
	token := hex.EncodeToString(tokenBytes)

	// Persist + announce.
	if err := writeToken(token); err != nil {
		log.Fatalf("write token: %v", err)
	}

	// Generate self-signed cert.
	certFile, keyFile, err := ensureSelfSignedCert(*certDir)
	if err != nil {
		log.Fatalf("self-signed cert: %v", err)
	}

	// Server state shared with handlers.
	state := &serverState{
		token:              token,
		csrfKey:            mustRandomBytes(32),
		rateLimit:          newRateLimiter(),
		installCh:          make(chan installRequest, 1),
		statusCh:           make(chan installStatus, 16),
		wizardSentinelPath: *wizardSentinelPath,
		valuesPath:         *valuesPath,
		llmKeyPath:         *llmKeyPath,
		startedAt:          time.Now(),
	}

	// Start install worker goroutine. It receives installRequest from
	// /submit and writes status updates to statusCh which /status reads.
	go installWorker(state)

	// HTTP routes.
	mux := http.NewServeMux()
	mux.HandleFunc("/", state.handleRoot)
	mux.HandleFunc("/auth", state.handleAuth)
	mux.HandleFunc("/static/", state.handleStatic)
	mux.HandleFunc("/submit", state.handleSubmit)
	mux.HandleFunc("/status", state.handleStatus)
	mux.HandleFunc("/healthz", state.handleHealthz)

	srv := &http.Server{
		Addr:              *addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	// Graceful shutdown so the install worker can finish if mid-flight.
	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		<-sigCh
		log.Printf("shutdown requested")
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}()

	log.Printf("soctalk-setup-wizard listening on %s", *addr)
	log.Printf("setup URL: https://<box-ip>/?token=%s", token)
	if err := srv.ListenAndServeTLS(certFile, keyFile); err != nil && err != http.ErrServerClosed {
		log.Fatalf("listen: %v", err)
	}
}

func writeToken(token string) error {
	// /var/log/soctalk-setup-token (0600). Customer retrieves via SSH.
	if err := os.MkdirAll(filepath.Dir(*tokenLogPath), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(*tokenLogPath, []byte(token+"\n"), 0o600); err != nil {
		return err
	}
	// Print to stdout. systemd unit's StandardOutput=journal+console
	// puts this on /dev/console too (cloud serial console + tty1).
	// Token is NOT put in /etc/issue (codex: leak via screen captures,
	// motd, and conflicts with ProtectSystem=full).
	fmt.Printf("\n=====================================================================\n")
	fmt.Printf("  SocTalk first-boot setup wizard\n")
	fmt.Printf("  Open  https://<this-vm-ip>:8443/  in a browser\n")
	fmt.Printf("  Paste the setup token from %s when prompted\n", *tokenLogPath)
	fmt.Printf("  (retrieve with: ssh <vm> sudo cat %s)\n", *tokenLogPath)
	fmt.Printf("=====================================================================\n\n")
	return nil
}

func mustRandomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}
