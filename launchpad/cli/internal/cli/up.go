// Package cli holds the concrete implementations of the top-level
// launchpad subcommands. Kept separate from cmd/ so we can unit-test them.
package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	yaml "gopkg.in/yaml.v3"

	"github.com/soctalk/launchpad/internal/orchestrator"
	"github.com/soctalk/launchpad/internal/pluginhost"
)

// UpOptions is what the CLI parses out of flags.
type UpOptions struct {
	ConfigPath string
	StatePath  string
	Headless   bool // true → JSON events on stdout, commands on stdin
	AutoResolveGates bool // true → auto-resolve every gate (for scripted smoke tests)
}

// Up is the entry point for `launchpad up`.
func Up(opts UpOptions) error {
	// Load config.
	cfg, err := loadConfig(opts.ConfigPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	// Resolve every plugin the run needs (top-level default + per-VM overrides).
	manifests, err := resolveTargets(cfg)
	if err != nil {
		return fmt.Errorf("resolve plugin: %w", err)
	}

	// Default state path.
	if opts.StatePath == "" {
		opts.StatePath = filepath.Join(defaultStateDir(), cfg.RunID+".json")
	}
	state, err := orchestrator.LoadOrInit(opts.StatePath, cfg.RunID, cfg.Target)
	if err != nil {
		return fmt.Errorf("state: %w", err)
	}

	// Set up signals so ctrl-c cleanly propagates cancellation.
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	orch := orchestrator.New(cfg, manifests, state)

	if opts.Headless {
		return runHeadless(ctx, orch, opts)
	}
	return runTUI(ctx, orch, opts)
}

func loadConfig(path string) (orchestrator.Config, error) {
	if path == "" {
		return orchestrator.Config{}, fmt.Errorf("--config path required")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return orchestrator.Config{}, err
	}
	var cfg orchestrator.Config
	// Accept both YAML and JSON since we haven't decided which we prefer.
	if strings.HasSuffix(path, ".yaml") || strings.HasSuffix(path, ".yml") {
		if err := yaml.Unmarshal(b, &cfg); err != nil {
			return cfg, err
		}
	} else {
		if err := json.Unmarshal(b, &cfg); err != nil {
			return cfg, err
		}
	}
	if cfg.Target == "" {
		return cfg, fmt.Errorf("target is required in config")
	}
	// Default run_id here (not later in orchestrator.New) so the derived state
	// path and `launchpad down` agree on the run id. Without this, a config
	// omitting run_id provisions under a generated id but tears down under "".
	if cfg.RunID == "" {
		cfg.RunID = fmt.Sprintf("run-%d", time.Now().Unix())
	}
	if cfg.MSSP.Key == "" {
		cfg.MSSP.Key = "mssp"
	}
	if cfg.MSSP.Role == "" {
		cfg.MSSP.Role = "mssp"
	}
	return cfg, nil
}

func resolveManifest(nameOrPath string) (*pluginhost.Manifest, error) {
	if strings.ContainsRune(nameOrPath, '/') || strings.ContainsRune(nameOrPath, '.') {
		return pluginhost.LoadManifest(nameOrPath)
	}
	// A target may be a composed "platform@host" key; the plugin is selected by
	// the platform half.
	name := orchestrator.PlatformOfTarget(nameOrPath)
	manifests, _ := pluginhost.DiscoverPlugins()
	for _, m := range manifests {
		if m.Name == name {
			return m, nil
		}
	}
	return nil, fmt.Errorf("plugin %q not found (check %s)", name, "launchpad plugin list")
}

// resolveTargets discovers manifests for every target the config references —
// the top-level Config.Target plus any per-VM Target override. Returns a
// map keyed by target name.
func resolveTargets(cfg orchestrator.Config) (map[string]*pluginhost.Manifest, error) {
	seen := map[string]struct{}{}
	if cfg.Target != "" {
		seen[cfg.Target] = struct{}{}
	}
	if t := cfg.MSSP.Target; t != "" {
		seen[t] = struct{}{}
	}
	for _, tn := range cfg.Tenants {
		if t := tn.Target; t != "" {
			seen[t] = struct{}{}
		}
	}
	if len(seen) == 0 {
		return nil, fmt.Errorf("no target specified (set config.target or a per-VM target)")
	}
	out := map[string]*pluginhost.Manifest{}
	for name := range seen {
		m, err := resolveManifest(name)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		out[name] = m
	}
	return out, nil
}

func defaultStateDir() string {
	if v := os.Getenv("XDG_STATE_HOME"); v != "" {
		return filepath.Join(v, "launchpad", "runs")
	}
	if home := os.Getenv("HOME"); home != "" {
		return filepath.Join(home, ".launchpad", "runs")
	}
	return filepath.Join(os.TempDir(), "launchpad", "runs")
}
