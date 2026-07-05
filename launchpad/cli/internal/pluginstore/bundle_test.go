package pluginstore

import (
	"archive/tar"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func writeTar(t *testing.T, path string, hdrs []*tar.Header, bodies [][]byte) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	tw := tar.NewWriter(f)
	for i, h := range hdrs {
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if len(bodies) > i && len(bodies[i]) > 0 {
			if _, err := tw.Write(bodies[i]); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestExtractBundleRejectsTraversal(t *testing.T) {
	tarPath := filepath.Join(t.TempDir(), "evil.tar")
	body := []byte("owned")
	writeTar(t, tarPath,
		[]*tar.Header{{Name: "../evil.txt", Typeflag: tar.TypeReg, Size: int64(len(body)), Mode: 0o644}},
		[][]byte{body})
	dest := t.TempDir()
	if err := ExtractBundle(tarPath, dest); err == nil {
		t.Fatal("expected traversal rejection, got nil")
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(dest), "evil.txt")); err == nil {
		t.Fatal("traversal wrote a file outside dest")
	}
}

func TestExtractBundleRejectsSymlink(t *testing.T) {
	tarPath := filepath.Join(t.TempDir(), "link.tar")
	writeTar(t, tarPath,
		[]*tar.Header{{Name: "link", Typeflag: tar.TypeSymlink, Linkname: "/etc/passwd", Mode: 0o777}},
		[][]byte{nil})
	if err := ExtractBundle(tarPath, t.TempDir()); err == nil {
		t.Fatal("expected symlink entry to be rejected")
	}
}

func TestExtractBundleRejectsAbsolutePath(t *testing.T) {
	tarPath := filepath.Join(t.TempDir(), "abs.tar")
	body := []byte("x")
	writeTar(t, tarPath,
		[]*tar.Header{{Name: "/etc/cron.d/evil", Typeflag: tar.TypeReg, Size: int64(len(body)), Mode: 0o644}},
		[][]byte{body})
	if err := ExtractBundle(tarPath, t.TempDir()); err == nil {
		t.Fatal("expected absolute-path entry to be rejected")
	}
}

// Offline install: build + sign an index, drop it plus the artifact into a
// bundle dir, and sync from that DirSource. Verifies the offline path shares
// the same signature verification as online.
func TestBundleDirSourceSyncE2E(t *testing.T) {
	bundle := t.TempDir()
	binContent := []byte("QEMU-OFFLINE")
	srcBin := filepath.Join(t.TempDir(), "qemu_src")
	if err := os.WriteFile(srcBin, binContent, 0o755); err != nil {
		t.Fatal(err)
	}
	specs := []PluginSpec{{
		Name: "qemu", Version: "0.2.0", Env: []string{"HOME"},
		Artifacts: []ArtifactBuild{{OS: runtime.GOOS, Arch: runtime.GOARCH, URL: "https://x/qemu_bin", Path: srcBin}},
	}}
	idx, err := BuildIndex("0.2.0", "1", time.Now().Add(time.Hour), specs)
	if err != nil {
		t.Fatal(err)
	}
	idxBytes, _ := MarshalIndex(idx)
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	sig := Sign(idxBytes, priv)

	// lay out the bundle: index.json, index.json.sig, and the artifact by base name
	if err := os.WriteFile(filepath.Join(bundle, "index.json"), idxBytes, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bundle, "index.json.sig"), sig, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bundle, "qemu_bin"), binContent, 0o644); err != nil {
		t.Fatal(err)
	}

	s := newStore(t)
	rep, err := s.Sync(context.Background(), Options{
		Source: DirSource{Dir: bundle}, Pub: pub, GOOS: runtime.GOOS, GOARCH: runtime.GOARCH,
	})
	if err != nil {
		t.Fatalf("offline sync: %v", err)
	}
	if len(rep.Installed) != 1 || rep.Installed[0] != "qemu" {
		t.Fatalf("installed = %v, want [qemu]", rep.Installed)
	}
}
