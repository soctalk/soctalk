package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/soctalk/launchpad/internal/orchestrator"
)

// DownOptions is what the CLI parses out of flags for `launchpad down`.
type DownOptions struct {
	ConfigPath string
	StatePath  string
	Headless   bool
	KeepState  bool
}

// Down tears down every VM the state file has recorded, in reverse order
// (tenants first, MSSP last), by calling the target plugin's vm.destroy.
// The plugin is expected to be idempotent — running `down` twice must not
// error on the second run.
func Down(opts DownOptions) error {
	cfg, err := loadConfig(opts.ConfigPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	manifests, err := resolveTargets(cfg)
	if err != nil {
		return fmt.Errorf("resolve plugin: %w", err)
	}
	if opts.StatePath == "" {
		opts.StatePath = filepath.Join(defaultStateDir(), cfg.RunID+".json")
	}
	state, err := orchestrator.LoadOrInit(opts.StatePath, cfg.RunID, cfg.Target)
	if err != nil {
		return fmt.Errorf("state: %w", err)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// Reverse teardown order: tenants (in reverse config order) first, then MSSP.
	order := make([]orchestrator.VMSpec, 0, len(cfg.Tenants)+1)
	for i := len(cfg.Tenants) - 1; i >= 0; i-- {
		order = append(order, cfg.Tenants[i])
	}
	order = append(order, cfg.MSSP)

	dctx := &orchestrator.DownContext{
		Cfg:       cfg,
		Manifests: manifests,
		State:     state,
		Order:     order,
	}
	events := make(chan orchestrator.Event, 128)
	errCh := make(chan error, 1)
	go func() {
		errCh <- dctx.Run(ctx, events) // closes events on return
	}()

	// Drain events. Headless → JSON on stdout; otherwise plain lines.
	enc := json.NewEncoder(os.Stdout)
	for ev := range events {
		if opts.Headless {
			_ = enc.Encode(ev)
			continue
		}
		fmt.Printf("[%s] %s %s %s\n", ev.Ev, ev.VMKey, ev.Step, ev.Message)
	}

	runErr := <-errCh
	if runErr != nil {
		fmt.Fprintln(os.Stderr, "down error:", runErr)
	}
	// Only discard state when every VM was actually torn down. On a partial
	// teardown the state is the operator's only handle for a retry.
	if runErr == nil && !opts.KeepState {
		if err := os.Remove(opts.StatePath); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("remove state file: %w", err)
		}
	}
	return runErr
}
