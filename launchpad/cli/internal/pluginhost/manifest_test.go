package pluginhost

import (
	"os"
	"path/filepath"
	"testing"
)

func writePlugin(t *testing.T, root, name string) {
	t.Helper()
	dir := filepath.Join(root, name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	content := "name: " + name + "\nversion: 0.1.0\nprotocol: \"1\"\nexecutable: ./plugin\n"
	if err := os.WriteFile(filepath.Join(dir, "plugin.yaml"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func byName(ms []*Manifest) map[string]*Manifest {
	out := map[string]*Manifest{}
	for _, m := range ms {
		out[m.Name] = m
	}
	return out
}

// A dev plugin must never silently shadow a managed one, and dev plugins must
// not leak into the trusted set without an explicit opt-in.
func TestDiscoverProvenanceAndShadowing(t *testing.T) {
	home := t.TempDir()
	managedRoot := filepath.Join(home, ".launchpad", "plugins")
	devRoot := t.TempDir()

	t.Setenv("HOME", home)
	t.Setenv("XDG_DATA_HOME", "")
	t.Setenv("LAUNCHPAD_PLUGIN_DIR", devRoot)
	t.Setenv("LAUNCHPAD_ALLOW_UNSIGNED", "")
	t.Setenv("LAUNCHPAD_DEV", "")

	writePlugin(t, managedRoot, "qemu") // managed
	writePlugin(t, devRoot, "qemu")     // dev tries to shadow
	writePlugin(t, devRoot, "mock")     // dev-only

	ms, errs := DiscoverPlugins()
	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	got := byName(ms)
	if got["qemu"] == nil || got["qemu"].Provenance != ProvenanceManaged {
		t.Errorf("qemu provenance = %v, want managed (dev must not shadow)", got["qemu"])
	}
	if got["mock"] == nil || got["mock"].Provenance != ProvenanceDev {
		t.Errorf("mock provenance = %v, want dev", got["mock"])
	}

	for _, m := range Trusted(ms) {
		if m.Provenance == ProvenanceDev {
			t.Errorf("dev plugin %q leaked into Trusted() without opt-in", m.Name)
		}
	}
	if n := len(Trusted(ms)); n != 1 {
		t.Errorf("Trusted() = %d plugins, want 1 (managed qemu only)", n)
	}
}

// With unsigned plugins explicitly allowed, a dev build overrides the managed
// plugin and every plugin becomes trusted.
func TestDiscoverAllowUnsigned(t *testing.T) {
	home := t.TempDir()
	managedRoot := filepath.Join(home, ".launchpad", "plugins")
	devRoot := t.TempDir()

	t.Setenv("HOME", home)
	t.Setenv("XDG_DATA_HOME", "")
	t.Setenv("LAUNCHPAD_PLUGIN_DIR", devRoot)
	t.Setenv("LAUNCHPAD_ALLOW_UNSIGNED", "1")
	t.Setenv("LAUNCHPAD_DEV", "")

	writePlugin(t, managedRoot, "qemu")
	writePlugin(t, devRoot, "qemu")

	ms, _ := DiscoverPlugins()
	got := byName(ms)
	if got["qemu"] == nil || got["qemu"].Provenance != ProvenanceDev {
		t.Errorf("with allow-unsigned, qemu provenance = %v, want dev (override)", got["qemu"])
	}
	if len(Trusted(ms)) != len(ms) {
		t.Errorf("with allow-unsigned, all %d plugins should be trusted, got %d", len(ms), len(Trusted(ms)))
	}
}
