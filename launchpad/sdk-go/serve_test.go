package sdk

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"strings"
	"sync"
	"testing"
	"time"
)

// Serve reads from r, dispatches, writes to w. Tests drive it by feeding
// scripted requests on r and asserting on the frames that come out on w.

// TestServe_HelloFirst verifies the plugin emits a hello notification before
// consuming any input.
func TestServe_HelloFirst(t *testing.T) {
	// Blocking reader so Serve waits after the hello is sent.
	pr, pw := io.Pipe()
	defer pw.Close()

	out := &safeBuf{}
	done := make(chan error, 1)
	go func() {
		done <- ServeIO(Plugin{
			Name:    "test",
			Version: "0.1.0",
			Initialize: func(ctx context.Context, params InitializeParams) (InitializeResult, error) {
				return InitializeResult{Ready: true}, nil
			},
		}, pr, out)
	}()

	// Wait briefly for hello to be written.
	if !waitFor(func() bool { return out.Len() > 0 }, 500*time.Millisecond) {
		t.Fatal("hello not emitted within 500ms")
	}
	frame := out.String()
	if !strings.Contains(frame, `"method":"plugin.hello"`) {
		t.Fatalf("first frame not hello: %q", frame)
	}
	if !strings.Contains(frame, `"protocol_version":"1"`) {
		t.Fatalf("hello missing protocol version: %q", frame)
	}

	// Close pr so Serve exits.
	pw.Close()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Serve returned error: %v", err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("Serve did not return after pipe closed")
	}
}

// TestServe_InitializeRoundtrip drives an initialize request and checks the response.
func TestServe_InitializeRoundtrip(t *testing.T) {
	in, sendReq := newScriptedReader()
	out := &safeBuf{}

	go func() {
		_ = ServeIO(Plugin{
			Name:    "test",
			Version: "0.1.0",
			Initialize: func(ctx context.Context, params InitializeParams) (InitializeResult, error) {
				if params.RunID != "run-123" {
					t.Errorf("run_id: got %q, want run-123", params.RunID)
				}
				return InitializeResult{Ready: true}, nil
			},
		}, in, out)
	}()

	// Send an initialize request with id=1.
	sendReq(`{"jsonrpc":"2.0","id":1,"method":"plugin.initialize","params":{"run_id":"run-123","config":{},"log_level":"info"}}`)

	// Wait for two frames: hello notification, then initialize response.
	if !waitFor(func() bool { return strings.Count(out.String(), "\n") >= 2 }, 1*time.Second) {
		t.Fatalf("expected 2 frames within 1s, got: %q", out.String())
	}
	frames := strings.Split(strings.TrimRight(out.String(), "\n"), "\n")
	if len(frames) < 2 {
		t.Fatalf("expected 2 frames, got %d", len(frames))
	}
	// Frame 0 is hello (checked above). Frame 1 should be the initialize response.
	var env Envelope
	if err := json.Unmarshal([]byte(frames[1]), &env); err != nil {
		t.Fatalf("parse response: %v", err)
	}
	if env.ID == nil || *env.ID != 1 {
		t.Fatalf("response id: got %v, want 1", env.ID)
	}
	if env.Error != nil {
		t.Fatalf("unexpected error: %+v", env.Error)
	}
	var result InitializeResult
	if err := ParseResult(&env, &result); err != nil {
		t.Fatal(err)
	}
	if !result.Ready {
		t.Fatal("initialize result: Ready=false")
	}
}

// TestServe_ShutdownStopsLoop verifies plugin.shutdown ends the Serve loop.
func TestServe_ShutdownStopsLoop(t *testing.T) {
	in, sendReq := newScriptedReader()
	out := &safeBuf{}
	done := make(chan error, 1)
	go func() {
		done <- ServeIO(Plugin{
			Name:    "test",
			Version: "0.1.0",
			Initialize: func(ctx context.Context, params InitializeParams) (InitializeResult, error) {
				return InitializeResult{Ready: true}, nil
			},
		}, in, out)
	}()

	sendReq(`{"jsonrpc":"2.0","id":42,"method":"plugin.shutdown"}`)

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Serve returned error: %v", err)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("Serve did not return after shutdown")
	}
	if !strings.Contains(out.String(), `"id":42`) {
		t.Fatalf("shutdown response missing: %q", out.String())
	}
}

// TestServe_UnknownMethodReturnsMethodNotFound sanity-checks the dispatch table.
func TestServe_UnknownMethodReturnsMethodNotFound(t *testing.T) {
	in, sendReq := newScriptedReader()
	out := &safeBuf{}
	go func() {
		_ = ServeIO(Plugin{
			Name:    "test",
			Version: "0.1.0",
			Initialize: func(ctx context.Context, params InitializeParams) (InitializeResult, error) {
				return InitializeResult{Ready: true}, nil
			},
		}, in, out)
	}()

	sendReq(`{"jsonrpc":"2.0","id":7,"method":"vm.plan","params":{}}`)

	if !waitFor(func() bool { return strings.Contains(out.String(), `"id":7`) }, 500*time.Millisecond) {
		t.Fatalf("no response for id=7: %q", out.String())
	}
	// Find the frame with id=7 and check it errored with method_not_found.
	for _, line := range strings.Split(out.String(), "\n") {
		if !strings.Contains(line, `"id":7`) {
			continue
		}
		var env Envelope
		if err := json.Unmarshal([]byte(line), &env); err != nil {
			t.Fatalf("parse: %v", err)
		}
		if env.Error == nil {
			t.Fatalf("expected error for unimplemented vm.plan: %v", env)
		}
		if env.Error.Code != ErrMethodNotFound {
			t.Fatalf("code: got %d, want %d", env.Error.Code, ErrMethodNotFound)
		}
		return
	}
	t.Fatalf("id=7 response not found in output: %q", out.String())
}

// TestErrfBuildsPluginError verifies the ergonomic helper.
func TestErrfBuildsPluginError(t *testing.T) {
	e := Errf(CatAuth, "hetzner.credentials.missing", "token is empty (env=%s)", "HCLOUD_TOKEN")
	if e.Category != CatAuth {
		t.Fatalf("category: got %s, want %s", e.Category, CatAuth)
	}
	if e.Msg != "token is empty (env=HCLOUD_TOKEN)" {
		t.Fatalf("msg: got %q", e.Msg)
	}
	if e.Error() != e.Msg {
		t.Fatal("Error() should return Msg")
	}
}

// ------------------------------------------------------------------
// Test helpers
// ------------------------------------------------------------------

// scriptedReader lets tests inject request frames into Serve's stdin.
func newScriptedReader() (io.Reader, func(string)) {
	pr, pw := io.Pipe()
	send := func(line string) {
		go func() {
			_, _ = pw.Write([]byte(line + "\n"))
		}()
	}
	return pr, send
}

// safeBuf is a thread-safe bytes.Buffer replacement — Serve writes from its
// goroutine while the test reads from its own.
type safeBuf struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *safeBuf) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}
func (b *safeBuf) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}
func (b *safeBuf) Len() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Len()
}

func waitFor(cond func() bool, budget time.Duration) bool {
	deadline := time.Now().Add(budget)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return cond()
}
