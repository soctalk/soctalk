package orchestrator

// Teardown flow: reads the state file, calls vm.destroy on each known VM in
// reverse-provision order (tenants first, MSSP last). Idempotent — if the
// plugin says "already gone" (Destroyed=false), that's a success.
//
// Multi-plugin: each VM's effective target picks which plugin subprocess
// handles its destroy. Clients are lazily started per target and reused.

import (
	"context"
	"fmt"
	"strings"
	"time"

	sdk "github.com/soctalk/launchpad-sdk-go"

	"github.com/soctalk/launchpad/internal/pluginhost"
)

// DownContext is what CLI passes to the orchestrator to drive a teardown.
type DownContext struct {
	Cfg       Config
	Manifests map[string]*pluginhost.Manifest // keyed by target name
	State     *State
	Order     []VMSpec // reverse-teardown order (tenants first, MSSP last)
	// ExtraEnv are per-target secret env vars (host creds, network API key)
	// needed to reach providers during teardown (e.g. ESXi destroy).
	ExtraEnv map[string][]string
}

// Run tears down every VM in Order. Sends progress on the events channel;
// closes it when done.
func (d *DownContext) Run(ctx context.Context, events chan<- Event) error {
	defer close(events)
	emit := func(ev Event) {
		if ev.Time.IsZero() {
			ev.Time = time.Now().UTC()
		}
		select {
		case events <- ev:
		default:
		}
	}

	emit(Event{Ev: EvPhase, Phase: "tearing_down"})

	notifications := make(chan *sdk.Envelope, 32)
	go func() {
		for env := range notifications {
			switch env.Method {
			case sdk.MethodProgress:
				var p sdk.ProgressParams
				_ = sdk.ParseParams(env, &p)
				emit(Event{Ev: EvVMProgress, VMKey: p.VMKey, Step: p.Step, Percent: p.Percent, Message: p.Message})
			case sdk.MethodLog:
				var p sdk.LogParams
				_ = sdk.ParseParams(env, &p)
				emit(Event{Ev: EvVMLog, VMKey: p.VMKey, Level: p.Level, Message: p.Message})
			}
		}
	}()

	// Lazily-created clients, one per target in use.
	clients := map[string]*pluginhost.Client{}
	defer func() {
		sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		for _, c := range clients {
			_ = c.Shutdown(sctx)
		}
	}()

	clientFor := func(target string, cfg map[string]any) (*pluginhost.Client, error) {
		if c, ok := clients[target]; ok {
			return c, nil
		}
		m, ok := d.Manifests[target]
		if !ok {
			return nil, fmt.Errorf("no manifest resolved for target %q", target)
		}
		c, err := pluginhost.Start(ctx, m, pluginhost.StartConfig{
			Notifications: notifications,
			EnvAllowlist:  m.Env,
			ExtraEnv:      d.ExtraEnv[target],
		})
		if err != nil {
			return nil, err
		}
		emit(Event{Ev: EvPluginReady, Fields: map[string]any{
			"plugin": c.Manifest.Name, "version": c.Manifest.Version,
			"capabilities": c.Hello.Capabilities, "target": target,
		}})
		initCtx, initCancel := context.WithTimeout(ctx, 60*time.Second)
		if err := c.Call(initCtx, sdk.MethodInitialize, sdk.InitializeParams{
			RunID: d.Cfg.RunID, Config: cfg, LogLevel: "info",
		}, nil); err != nil {
			// Non-fatal: some plugins can destroy from selector alone.
			emit(Event{Ev: EvVMLog, Level: "warn",
				Message: fmt.Sprintf("plugin.initialize [%s] warned: %v (continuing)", target, err)})
		}
		initCancel()
		clients[target] = c
		return c, nil
	}

	// Iterate destroy targets. Prefer state (has vm_id + target); fall back
	// to config keys / defaults when state is empty (crash before SetVM).
	// A VM we could not reach or destroy is recorded here so teardown reports
	// failure instead of completing — otherwise the caller removes state while
	// the provider resource keeps running.
	var failed []string
	for _, s := range d.Order {
		effTarget := s.EffectiveTarget(d.Cfg.Target)
		effCfg := s.EffectivePluginConfig(d.Cfg.PluginConfig)
		st, hasState := d.State.GetVM(s.Key)
		vmID := ""
		if hasState {
			vmID = st.VMID
			if st.Target != "" {
				effTarget = st.Target
			}
		}
		client, err := clientFor(effTarget, effCfg)
		if err != nil {
			emit(Event{Ev: EvVMLog, VMKey: s.Key, Level: "error",
				Message: fmt.Sprintf("no client for target %q: %v (cannot destroy)", effTarget, err)})
			failed = append(failed, fmt.Sprintf("%s: no client for %q: %v", s.Key, effTarget, err))
			continue
		}
		emit(Event{Ev: EvVMProgress, VMKey: s.Key, Step: "destroy", Percent: 10,
			Message: fmt.Sprintf("destroying %s via %s (id=%s)", s.Key, effTarget, vmID)})

		dctx, cancel := context.WithTimeout(ctx, 15*time.Minute)
		var dr sdk.VMDestroyResult
		err = client.Call(dctx, sdk.MethodVMDestroy, sdk.VMDestroyParams{
			RunID: d.Cfg.RunID, VMKey: s.Key, VMID: vmID,
			Selector: map[string]string{"run_id": d.Cfg.RunID, "vm_key": s.Key},
		}, &dr)
		cancel()
		if err != nil {
			emit(Event{Ev: EvVMLog, VMKey: s.Key, Level: "error",
				Message: fmt.Sprintf("vm.destroy failed: %v", err)})
			failed = append(failed, fmt.Sprintf("%s: %v", s.Key, err))
			continue
		}
		msg := "not found (already gone)"
		if dr.Destroyed {
			msg = "destroyed"
		}
		emit(Event{Ev: EvVMProgress, VMKey: s.Key, Step: "destroy", Percent: 100, Message: msg})
	}

	if len(failed) > 0 {
		msg := fmt.Sprintf("teardown incomplete: %d of %d VM(s) not destroyed (%s); state kept for retry",
			len(failed), len(d.Order), strings.Join(failed, "; "))
		emit(Event{Ev: EvError, Error: &EventError{
			Category: "provider", Code: "teardown.incomplete", Message: msg,
		}})
		emit(Event{Ev: EvPhase, Phase: PhaseFailed})
		return fmt.Errorf("%s", msg)
	}

	emit(Event{Ev: EvPhase, Phase: "torn_down"})
	emit(Event{Ev: EvComplete})
	return nil
}
