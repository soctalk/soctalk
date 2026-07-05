package pluginstore

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	yaml "gopkg.in/yaml.v3"
)

// Store manages a directory of verified plugins.
type Store struct {
	dir string
}

// Open returns a Store rooted at dir (the managed plugin directory).
func Open(dir string) *Store { return &Store{dir: dir} }

// Dir returns the store's root directory.
func (s *Store) Dir() string { return s.dir }

// Options configures a Sync.
type Options struct {
	Source Source
	Pub    ed25519.PublicKey
	Now    time.Time
	GOOS   string
	GOARCH string
}

// Report summarizes a Sync run.
type Report struct {
	Installed  []string
	Skipped    []string
	NoArtifact []string
	Failed     map[string]string
}

// writtenManifest mirrors pluginhost.Manifest's serialized fields. Written from
// the verified index entry so the on-disk plugin.yaml is always derived from
// signed data.
type writtenManifest struct {
	Name       string   `yaml:"name"`
	Version    string   `yaml:"version"`
	Protocol   string   `yaml:"protocol"`
	Executable string   `yaml:"executable"`
	SHA256     string   `yaml:"sha256"`
	License    string   `yaml:"license,omitempty"`
	Homepage   string   `yaml:"homepage,omitempty"`
	Env        []string `yaml:"env,omitempty"`
}

// Sync fetches and verifies the index, then installs every plugin that has an
// artifact for the target platform, skipping any already present with a binary
// whose SHA-256 matches the signed index (verify-before-skip: the filesystem is
// checked against the index, never a self-reported metadata file). The verified
// index is cached to the store for spawn-time verification.
func (s *Store) Sync(ctx context.Context, opts Options) (*Report, error) {
	goos, goarch := opts.GOOS, opts.GOARCH
	if goos == "" || goarch == "" {
		return nil, fmt.Errorf("GOOS/GOARCH required")
	}
	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}

	if err := os.MkdirAll(s.dir, 0o755); err != nil {
		return nil, fmt.Errorf("create store dir: %w", err)
	}
	unlock, err := s.lock()
	if err != nil {
		return nil, err
	}
	defer unlock()

	idxBytes, sig, err := opts.Source.Index(ctx)
	if err != nil {
		return nil, err
	}
	idx, err := ParseAndVerify(idxBytes, sig, opts.Pub, now)
	if err != nil {
		return nil, err
	}

	rep := &Report{Failed: map[string]string{}}
	for _, p := range idx.Plugins {
		art := p.ArtifactFor(goos, goarch)
		if art == nil {
			rep.NoArtifact = append(rep.NoArtifact, p.Name)
			continue
		}
		binName := "plugin" + exeSuffix(goos)
		// Skip only when the binary AND the signed manifest on disk both match
		// the index: a matching binary with a missing/stale plugin.yaml (or a
		// metadata-only change shipping the same bytes) must still reinstall.
		if pluginCurrent(filepath.Join(s.dir, p.Name), binName, p, art) {
			rep.Skipped = append(rep.Skipped, p.Name)
			continue
		}
		if err := s.install(ctx, opts.Source, p, art, binName); err != nil {
			rep.Failed[p.Name] = err.Error()
			continue
		}
		rep.Installed = append(rep.Installed, p.Name)
	}

	// Cache the verified index and its signature for later spawn-time
	// verification. Written only after a successful verify above.
	if err := writeFileAtomic(filepath.Join(s.dir, cachedIndexName), idxBytes, 0o644); err != nil {
		return rep, fmt.Errorf("cache index: %w", err)
	}
	if err := writeFileAtomic(filepath.Join(s.dir, cachedSigName), sig, 0o644); err != nil {
		return rep, fmt.Errorf("cache index signature: %w", err)
	}
	if len(rep.Failed) > 0 {
		return rep, fmt.Errorf("%d plugin(s) failed to install", len(rep.Failed))
	}
	return rep, nil
}

// install downloads one artifact, verifies its checksum, stages the whole
// plugin directory, and publishes it atomically so discovery never sees a new
// binary paired with an old manifest.
func (s *Store) install(ctx context.Context, src Source, p IndexPlugin, art *Artifact, binName string) error {
	data, err := src.Fetch(ctx, art.URL)
	if err != nil {
		return fmt.Errorf("download: %w", err)
	}
	if err := verifySHA256(data, art.SHA256); err != nil {
		return err
	}

	staging := filepath.Join(s.dir, fmt.Sprintf(".staging-%s-%d", p.Name, time.Now().UnixNano()))
	if err := os.MkdirAll(staging, 0o755); err != nil {
		return err
	}
	defer os.RemoveAll(staging) // no-op after a successful rename

	if err := writeFileAtomic(filepath.Join(staging, binName), data, 0o755); err != nil {
		return err
	}
	mf := writtenManifest{
		Name: p.Name, Version: p.Version, Protocol: firstNonEmpty(p.Protocol, "1"),
		Executable: "./" + binName, SHA256: art.SHA256,
		License: p.License, Homepage: p.Homepage, Env: p.Env,
	}
	y, err := yaml.Marshal(mf)
	if err != nil {
		return err
	}
	if err := writeFileAtomic(filepath.Join(staging, "plugin.yaml"), y, 0o644); err != nil {
		return err
	}
	if err := fsyncDir(staging); err != nil {
		return err
	}

	final := filepath.Join(s.dir, p.Name)
	// Dot-prefixed so a leftover (after a crash mid-swap) is ignored by
	// discovery rather than treated as a plugin.
	old := filepath.Join(s.dir, "."+p.Name+".old")
	_ = os.RemoveAll(old)
	if _, err := os.Stat(final); err == nil {
		if err := os.Rename(final, old); err != nil {
			return fmt.Errorf("swap out old plugin: %w", err)
		}
	}
	if err := os.Rename(staging, final); err != nil {
		_ = os.Rename(old, final) // roll back
		return fmt.Errorf("publish plugin: %w", err)
	}
	_ = os.RemoveAll(old)
	return fsyncDir(s.dir)
}

const (
	cachedIndexName = ".index.json"
	cachedSigName   = ".index.sig"
)

// lock acquires a best-effort exclusive lock on the store via an O_EXCL
// lockfile, so two processes do not sync concurrently. A stale lock older than
// 15 minutes (e.g. from a crashed process) is reclaimed.
func (s *Store) lock() (func(), error) {
	path := filepath.Join(s.dir, ".sync.lock")
	if fi, err := os.Stat(path); err == nil && time.Since(fi.ModTime()) > 15*time.Minute {
		_ = os.Remove(path)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
	if err != nil {
		if os.IsExist(err) {
			return nil, fmt.Errorf("another sync is in progress (%s); retry or remove it if stale", path)
		}
		return nil, err
	}
	_, _ = fmt.Fprintf(f, "%d\n", os.Getpid())
	_ = f.Close()
	return func() { _ = os.Remove(path) }, nil
}

func exeSuffix(goos string) string {
	if goos == "windows" {
		return ".exe"
	}
	return ""
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// writeFileAtomic writes to a temp file in the same dir and renames it into
// place, so a reader never observes a partial file.
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpName, perm); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

func fsyncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	// Directory fsync is not supported on all platforms; ignore that error.
	if err := d.Sync(); err != nil && !os.IsNotExist(err) {
		return nil
	}
	return nil
}

func firstNonEmpty(vs ...string) string {
	for _, v := range vs {
		if v != "" {
			return v
		}
	}
	return ""
}

// CachedIndex returns the last verified index bytes cached in the store, if any.
func (s *Store) CachedIndex() ([]byte, error) {
	return os.ReadFile(filepath.Join(s.dir, cachedIndexName))
}

// cachedIndexAndSig returns the cached index bytes and detached signature.
func (s *Store) cachedIndexAndSig() (index, sig []byte, err error) {
	index, err = os.ReadFile(filepath.Join(s.dir, cachedIndexName))
	if err != nil {
		return nil, nil, err
	}
	sig, err = os.ReadFile(filepath.Join(s.dir, cachedSigName))
	if err != nil {
		return nil, nil, err
	}
	return index, sig, nil
}
