// Package pluginhost is the launchpad-side of the plugin protocol: manifest
// loading, subprocess spawning, JSON-RPC client, and correlation of
// progress/log notifications back to the in-flight operation.
package pluginhost

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	yaml "gopkg.in/yaml.v3"
)

// Provenance records where a manifest was discovered, which bounds how far it
// is trusted. Managed plugins come from the launchpad-managed store, populated
// only by a signature-verified Sync. Dev plugins come from
// $LAUNCHPAD_PLUGIN_DIR and are unsigned: usable for local development but not
// trusted for secret-bearing flows unless the operator opts in (AllowUnsigned).
type Provenance string

const (
	ProvenanceManaged Provenance = "managed"
	ProvenanceDev     Provenance = "dev"
)

// Manifest describes a discovered plugin on disk.
type Manifest struct {
	Name       string `yaml:"name"`
	Version    string `yaml:"version"`
	Protocol   string `yaml:"protocol"`
	Executable string `yaml:"executable"`
	SHA256     string `yaml:"sha256,omitempty"`
	License    string `yaml:"license,omitempty"`
	Homepage   string `yaml:"homepage,omitempty"`

	// Env is the parent-env allow-list forwarded to the subprocess. Declared
	// here (not derived from Hello) because exec env is fixed at spawn time.
	Env []string `yaml:"env,omitempty"`

	// Directory the manifest was loaded from. Not serialized.
	Dir string `yaml:"-"`

	// Provenance is set by DiscoverPlugins from the root it was found under.
	// Not serialized: trust is decided by the source, never self-declared.
	Provenance Provenance `yaml:"-"`
}

// AllowUnsigned reports whether unsigned (dev) plugins may be trusted for
// secret-bearing flows. Off by default; enabled with LAUNCHPAD_ALLOW_UNSIGNED=1
// (the `--allow-unsigned` flag sets this) or LAUNCHPAD_DEV=1.
func AllowUnsigned() bool {
	return os.Getenv("LAUNCHPAD_ALLOW_UNSIGNED") == "1" || os.Getenv("LAUNCHPAD_DEV") == "1"
}

// Trusted returns the subset of manifests permitted for secret-bearing flows
// (provisioning, the UI, host probes). Managed plugins always qualify; dev
// plugins qualify only when AllowUnsigned() is set.
func Trusted(ms []*Manifest) []*Manifest {
	allow := AllowUnsigned()
	out := make([]*Manifest, 0, len(ms))
	for _, m := range ms {
		if m.Provenance == ProvenanceManaged || allow {
			out = append(out, m)
		}
	}
	return out
}

// AbsExecutable returns the absolute path to the plugin binary, joining
// the manifest's Dir with its Executable field. The result is canonicalized.
func (m *Manifest) AbsExecutable() string {
	p := m.Executable
	if !filepath.IsAbs(p) {
		p = filepath.Join(m.Dir, p)
	}
	if resolved, err := filepath.Abs(p); err == nil {
		return resolved
	}
	return p
}

// LoadManifest reads a plugin.yaml from the given directory.
func LoadManifest(dir string) (*Manifest, error) {
	path := filepath.Join(dir, "plugin.yaml")
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	m := &Manifest{Dir: dir}
	if err := yaml.Unmarshal(b, m); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if m.Name == "" || m.Version == "" || m.Executable == "" {
		return nil, fmt.Errorf("%s: name, version, executable required", path)
	}
	if m.Protocol == "" {
		m.Protocol = "1"
	}
	return m, nil
}

// VerifyChecksum recomputes the sha256 of the executable and compares it
// against the manifest's declared value. Returns nil if the manifest
// declares no sha256 (the operator opted out of local-integrity check).
func (m *Manifest) VerifyChecksum() error {
	if m.SHA256 == "" {
		return nil
	}
	f, err := os.Open(m.AbsExecutable())
	if err != nil {
		return fmt.Errorf("open plugin binary: %w", err)
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return fmt.Errorf("hash: %w", err)
	}
	got := hex.EncodeToString(h.Sum(nil))
	if got != m.SHA256 {
		return fmt.Errorf("checksum mismatch: manifest=%s, actual=%s", m.SHA256, got)
	}
	return nil
}

// DiscoverPlugins walks the well-known plugin directories and returns every
// manifest it can load, tagged with its Provenance. Directories that don't
// exist are silently skipped.
//
// Managed roots are searched before the dev root ($LAUNCHPAD_PLUGIN_DIR), so a
// managed plugin wins a name collision and a dev plugin can never silently
// shadow it. When AllowUnsigned() is set the dev root is searched first, so a
// developer can deliberately override a managed plugin with a local build.
// First match wins on duplicate names.
func DiscoverPlugins() ([]*Manifest, []error) {
	var out []*Manifest
	var errs []error
	seen := map[string]bool{}
	for _, root := range pluginSearchDirs() {
		entries, err := os.ReadDir(root.path)
		if err != nil {
			continue
		}
		for _, e := range entries {
			// Skip non-dirs and hidden entries: the managed store keeps its
			// cached index (.index.json) and transient .staging-*/.old dirs
			// alongside plugins, and a leftover .staging dir sorts before the
			// real plugin and must never shadow it.
			if !e.IsDir() || strings.HasPrefix(e.Name(), ".") {
				continue
			}
			dir := filepath.Join(root.path, e.Name())
			m, err := LoadManifest(dir)
			if err != nil {
				errs = append(errs, err)
				continue
			}
			if seen[m.Name] {
				continue
			}
			seen[m.Name] = true
			m.Provenance = root.prov
			out = append(out, m)
		}
	}
	return out, errs
}

type searchDir struct {
	path string
	prov Provenance
}

// pluginSearchDirs returns the plugin roots in precedence order (see
// DiscoverPlugins). Managed roots first by default; dev root first when
// unsigned plugins are explicitly allowed.
func pluginSearchDirs() []searchDir {
	var managed []searchDir
	if runtime.GOOS == "windows" {
		if v := os.Getenv("APPDATA"); v != "" {
			managed = append(managed, searchDir{filepath.Join(v, "launchpad", "plugins"), ProvenanceManaged})
		}
	} else {
		if v := os.Getenv("XDG_DATA_HOME"); v != "" {
			managed = append(managed, searchDir{filepath.Join(v, "launchpad", "plugins"), ProvenanceManaged})
		}
		if home := os.Getenv("HOME"); home != "" {
			managed = append(managed, searchDir{filepath.Join(home, ".launchpad", "plugins"), ProvenanceManaged})
			managed = append(managed, searchDir{filepath.Join(home, ".local", "share", "launchpad", "plugins"), ProvenanceManaged})
		}
	}
	var dev []searchDir
	if extra := os.Getenv("LAUNCHPAD_PLUGIN_DIR"); extra != "" {
		for _, p := range filepath.SplitList(extra) {
			if p != "" {
				dev = append(dev, searchDir{p, ProvenanceDev})
			}
		}
	}
	if AllowUnsigned() {
		return append(dev, managed...)
	}
	return append(managed, dev...)
}

// ManagedPluginDir returns the directory where verified plugins are installed
// and from which they are discovered as ProvenanceManaged.
func ManagedPluginDir() string {
	if runtime.GOOS == "windows" {
		if v := os.Getenv("APPDATA"); v != "" {
			return filepath.Join(v, "launchpad", "plugins")
		}
	}
	if v := os.Getenv("XDG_DATA_HOME"); v != "" {
		return filepath.Join(v, "launchpad", "plugins")
	}
	if home := os.Getenv("HOME"); home != "" {
		return filepath.Join(home, ".launchpad", "plugins")
	}
	return filepath.Join(os.TempDir(), "launchpad", "plugins")
}
