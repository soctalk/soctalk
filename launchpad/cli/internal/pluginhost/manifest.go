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

	yaml "gopkg.in/yaml.v3"
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
// manifest it can load. Directories that don't exist are silently skipped.
//
// Search order (first match wins on duplicate names):
//  1. $LAUNCHPAD_PLUGIN_DIR (colon-separated, for test/dev)
//  2. $XDG_DATA_HOME/launchpad/plugins
//  3. $HOME/.launchpad/plugins
//  4. $HOME/.local/share/launchpad/plugins (Linux XDG fallback)
//  5. %APPDATA%\launchpad\plugins (Windows)
func DiscoverPlugins() ([]*Manifest, []error) {
	var out []*Manifest
	var errs []error
	seen := map[string]bool{}
	for _, root := range pluginSearchDirs() {
		entries, err := os.ReadDir(root)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			dir := filepath.Join(root, e.Name())
			m, err := LoadManifest(dir)
			if err != nil {
				errs = append(errs, err)
				continue
			}
			if seen[m.Name] {
				continue
			}
			seen[m.Name] = true
			out = append(out, m)
		}
	}
	return out, errs
}

func pluginSearchDirs() []string {
	var dirs []string
	if extra := os.Getenv("LAUNCHPAD_PLUGIN_DIR"); extra != "" {
		for _, p := range filepath.SplitList(extra) {
			if p != "" {
				dirs = append(dirs, p)
			}
		}
	}
	if runtime.GOOS == "windows" {
		if v := os.Getenv("APPDATA"); v != "" {
			dirs = append(dirs, filepath.Join(v, "launchpad", "plugins"))
		}
	} else {
		if v := os.Getenv("XDG_DATA_HOME"); v != "" {
			dirs = append(dirs, filepath.Join(v, "launchpad", "plugins"))
		}
		if home := os.Getenv("HOME"); home != "" {
			dirs = append(dirs, filepath.Join(home, ".launchpad", "plugins"))
			dirs = append(dirs, filepath.Join(home, ".local", "share", "launchpad", "plugins"))
		}
	}
	return dirs
}
