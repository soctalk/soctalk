package pluginstore

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/soctalk/launchpad/internal/pluginhost"
)

// VerifySpawn must accept a clean managed plugin and reject a tampered binary,
// a tampered env policy, and an unsigned dev plugin without opt-in.
func TestVerifySpawn(t *testing.T) {
	xdg := t.TempDir()
	t.Setenv("XDG_DATA_HOME", xdg)
	t.Setenv("HOME", t.TempDir())
	t.Setenv("LAUNCHPAD_ALLOW_UNSIGNED", "")
	t.Setenv("LAUNCHPAD_DEV", "")
	storeDir := pluginhost.ManagedPluginDir()

	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	t.Setenv("LAUNCHPAD_PUBKEY", hex.EncodeToString(pub))

	bin := []byte("QEMU-PLUGIN-BINARY")
	srcBin := filepath.Join(t.TempDir(), "q")
	if err := os.WriteFile(srcBin, bin, 0o755); err != nil {
		t.Fatal(err)
	}
	specs := []PluginSpec{{
		Name: "qemu", Version: "0.2.0", Env: []string{"HOME", "SSH_AUTH_SOCK"},
		Artifacts: []ArtifactBuild{{OS: runtime.GOOS, Arch: runtime.GOARCH, URL: "https://x/q", Path: srcBin}},
	}}
	idx, _ := BuildIndex("0.2.0", "1", time.Now().Add(time.Hour), specs)
	idxBytes, _ := MarshalIndex(idx)
	src := &memSource{index: idxBytes, sig: Sign(idxBytes, priv), files: map[string][]byte{"https://x/q": bin}}

	s := Open(storeDir)
	if _, err := s.Sync(context.Background(), Options{Source: src, Pub: pub, GOOS: runtime.GOOS, GOARCH: runtime.GOARCH}); err != nil {
		t.Fatalf("sync: %v", err)
	}

	m, err := pluginhost.LoadManifest(filepath.Join(storeDir, "qemu"))
	if err != nil {
		t.Fatalf("load manifest: %v", err)
	}
	m.Provenance = pluginhost.ProvenanceManaged

	if err := VerifySpawn(m); err != nil {
		t.Fatalf("clean managed plugin rejected: %v", err)
	}

	// tampered binary
	if err := os.WriteFile(m.AbsExecutable(), []byte("EVIL"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := VerifySpawn(m); err == nil {
		t.Fatal("tampered binary passed spawn verification")
	}
	if err := os.WriteFile(m.AbsExecutable(), bin, 0o755); err != nil {
		t.Fatal(err)
	}

	// tampered env policy (simulated plugin.yaml edit adding a secret)
	m.Env = append(m.Env, "AWS_SECRET_ACCESS_KEY")
	if err := VerifySpawn(m); err == nil {
		t.Fatal("tampered env policy passed spawn verification")
	}

	// unsigned dev plugin: rejected without opt-in, allowed with it
	dev := &pluginhost.Manifest{Name: "x", Provenance: pluginhost.ProvenanceDev}
	if err := VerifySpawn(dev); err == nil {
		t.Fatal("dev plugin spawned without --allow-unsigned")
	}
	t.Setenv("LAUNCHPAD_ALLOW_UNSIGNED", "1")
	if err := VerifySpawn(dev); err != nil {
		t.Fatalf("dev plugin rejected even with opt-in: %v", err)
	}
}
