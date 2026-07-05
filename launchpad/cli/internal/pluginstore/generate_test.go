package pluginstore

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/soctalk/launchpad/internal/pluginhost"
)

// Full pipeline: build a real plugin binary on disk, generate + sign the index
// over it, sync from that signed index, and confirm the installed plugin loads
// through the normal manifest loader with the env policy that was signed.
func TestGenerateSignSyncE2E(t *testing.T) {
	build := t.TempDir()
	qemuPath := filepath.Join(build, "qemu_bin")
	binContent := []byte("QEMU-PLUGIN-BINARY-v0.2.0")
	if err := os.WriteFile(qemuPath, binContent, 0o755); err != nil {
		t.Fatal(err)
	}

	specs := []PluginSpec{{
		Name: "qemu", Version: "0.2.0", Protocol: "1", Substrate: "local",
		Env: []string{"SSH_AUTH_SOCK", "HOME"}, License: "MIT",
		Artifacts: []ArtifactBuild{
			{OS: runtime.GOOS, Arch: runtime.GOARCH, URL: "https://x/qemu", Path: qemuPath},
		},
	}}

	idx, err := BuildIndex("0.2.0", "1", time.Now().Add(time.Hour), specs)
	if err != nil {
		t.Fatalf("build index: %v", err)
	}
	idxBytes, err := MarshalIndex(idx)
	if err != nil {
		t.Fatal(err)
	}
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	sig := Sign(idxBytes, priv)

	src := &memSource{index: idxBytes, sig: sig, files: map[string][]byte{"https://x/qemu": binContent}}
	s := newStore(t)
	rep, err := s.Sync(context.Background(), Options{Source: src, Pub: pub, GOOS: runtime.GOOS, GOARCH: runtime.GOARCH})
	if err != nil {
		t.Fatalf("sync: %v", err)
	}
	if len(rep.Installed) != 1 {
		t.Fatalf("installed = %v, want [qemu]", rep.Installed)
	}

	// The installed plugin must load through the normal loader with the signed
	// env allow-list and checksum intact.
	m, err := pluginhost.LoadManifest(filepath.Join(s.Dir(), "qemu"))
	if err != nil {
		t.Fatalf("load installed manifest: %v", err)
	}
	if len(m.Env) != 2 || m.Env[0] != "SSH_AUTH_SOCK" || m.Env[1] != "HOME" {
		t.Errorf("installed env policy = %v, want [SSH_AUTH_SOCK HOME]", m.Env)
	}
	if err := m.VerifyChecksum(); err != nil {
		t.Errorf("installed binary fails its own checksum: %v", err)
	}
}
