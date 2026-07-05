package pluginstore

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func sha(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

type memSource struct {
	index, sig []byte
	files      map[string][]byte
}

func (m *memSource) Index(ctx context.Context) ([]byte, []byte, error) { return m.index, m.sig, nil }
func (m *memSource) Fetch(ctx context.Context, url string) ([]byte, error) {
	b, ok := m.files[url]
	if !ok {
		return nil, os.ErrNotExist
	}
	return b, nil
}

// build a signed index whose single "qemu" plugin targets the host platform,
// plus a "winonly" plugin that only has a windows artifact.
func buildSource(t *testing.T, priv ed25519.PrivateKey, qemuBin []byte, expires time.Time) *memSource {
	t.Helper()
	goos, goarch := runtime.GOOS, runtime.GOARCH
	files := map[string][]byte{
		"https://x/qemu":    qemuBin,
		"https://x/winonly": []byte("win"),
	}
	idx := Index{
		SchemaVersion: 1, LaunchpadVersion: "0.2.0", ProtocolVersion: "1", Expires: expires,
		Plugins: []IndexPlugin{
			{
				Name: "qemu", Version: "0.2.0", Protocol: "1", Substrate: "local",
				Env: []string{"SSH_AUTH_SOCK", "HOME"},
				Artifacts: []Artifact{
					{OS: goos, Arch: goarch, URL: "https://x/qemu", SHA256: sha(qemuBin), Size: int64(len(qemuBin))},
				},
			},
			{
				Name: "winonly", Version: "0.2.0", Protocol: "1",
				Artifacts: []Artifact{
					{OS: "windows", Arch: "amd64", URL: "https://x/winonly", SHA256: sha([]byte("win"))},
				},
			},
		},
	}
	idxBytes, _ := json.Marshal(idx)
	return &memSource{index: idxBytes, sig: ed25519.Sign(priv, idxBytes), files: files}
}

func newStore(t *testing.T) *Store { return Open(t.TempDir()) }

func TestSyncHappyPathAndVerifyBeforeSkip(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	bin := []byte("#!/bin/true\nqemu-plugin-v2")
	src := buildSource(t, priv, bin, time.Now().Add(time.Hour))
	s := newStore(t)
	opts := Options{Source: src, Pub: pub, GOOS: runtime.GOOS, GOARCH: runtime.GOARCH}

	rep, err := s.Sync(context.Background(), opts)
	if err != nil {
		t.Fatalf("sync: %v", err)
	}
	if len(rep.Installed) != 1 || rep.Installed[0] != "qemu" {
		t.Fatalf("installed = %v, want [qemu]", rep.Installed)
	}
	if len(rep.NoArtifact) != 1 || rep.NoArtifact[0] != "winonly" {
		t.Fatalf("no-artifact = %v, want [winonly] (must not fail the run)", rep.NoArtifact)
	}
	// binary, manifest, and cached index landed
	binPath := filepath.Join(s.Dir(), "qemu", "plugin"+exeSuffix(runtime.GOOS))
	if got, _ := os.ReadFile(binPath); string(got) != string(bin) {
		t.Fatalf("installed binary content mismatch")
	}
	if _, err := os.Stat(filepath.Join(s.Dir(), "qemu", "plugin.yaml")); err != nil {
		t.Fatalf("plugin.yaml missing: %v", err)
	}
	if _, err := s.CachedIndex(); err != nil {
		t.Fatalf("cached index missing: %v", err)
	}

	// second sync: on-disk SHA matches the index → skip, not reinstall
	rep2, err := s.Sync(context.Background(), opts)
	if err != nil {
		t.Fatalf("sync 2: %v", err)
	}
	if len(rep2.Skipped) != 1 || rep2.Skipped[0] != "qemu" {
		t.Fatalf("skipped = %v, want [qemu]", rep2.Skipped)
	}

	// tamper the installed binary → verify-before-skip must trigger a reinstall
	if err := os.WriteFile(binPath, []byte("tampered"), 0o755); err != nil {
		t.Fatal(err)
	}
	rep3, err := s.Sync(context.Background(), opts)
	if err != nil {
		t.Fatalf("sync 3: %v", err)
	}
	if len(rep3.Installed) != 1 {
		t.Fatalf("tampered binary not reinstalled: %v", rep3)
	}
	if got, _ := os.ReadFile(binPath); string(got) != string(bin) {
		t.Fatalf("reinstall did not restore the signed binary")
	}
}

func TestSyncRejectsBadSignature(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	src := buildSource(t, priv, []byte("bin"), time.Now().Add(time.Hour))
	src.index = append(src.index, ' ') // mutate signed bytes → signature invalid
	s := newStore(t)
	_, err := s.Sync(context.Background(), Options{Source: src, Pub: pub, GOOS: runtime.GOOS, GOARCH: runtime.GOARCH})
	if err == nil {
		t.Fatal("expected signature verification failure, got nil")
	}
	if _, statErr := os.Stat(filepath.Join(s.Dir(), "qemu")); statErr == nil {
		t.Fatal("plugin installed despite bad signature")
	}
}

func TestSyncRejectsTamperedArtifact(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	src := buildSource(t, priv, []byte("bin"), time.Now().Add(time.Hour))
	src.files["https://x/qemu"] = []byte("swapped-payload") // sha no longer matches index
	s := newStore(t)
	rep, err := s.Sync(context.Background(), Options{Source: src, Pub: pub, GOOS: runtime.GOOS, GOARCH: runtime.GOARCH})
	if err == nil {
		t.Fatal("expected failure from checksum mismatch")
	}
	if _, ok := rep.Failed["qemu"]; !ok {
		t.Fatalf("qemu should be in Failed, got %+v", rep)
	}
	if _, statErr := os.Stat(filepath.Join(s.Dir(), "qemu", "plugin"+exeSuffix(runtime.GOOS))); statErr == nil {
		t.Fatal("tampered artifact was installed")
	}
}

func TestSyncRejectsExpiredIndex(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	src := buildSource(t, priv, []byte("bin"), time.Now().Add(-time.Hour)) // already expired
	s := newStore(t)
	_, err := s.Sync(context.Background(), Options{Source: src, Pub: pub, GOOS: runtime.GOOS, GOARCH: runtime.GOARCH})
	if err == nil {
		t.Fatal("expected expired-index rejection")
	}
}

func TestSyncRejectsWrongKey(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	src := buildSource(t, priv, []byte("bin"), time.Now().Add(time.Hour))
	s := newStore(t)
	_, err := s.Sync(context.Background(), Options{Source: src, Pub: otherPub, GOOS: runtime.GOOS, GOARCH: runtime.GOARCH})
	if err == nil {
		t.Fatal("expected verification failure with the wrong public key")
	}
}
