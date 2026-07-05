package orchestrator

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	sdk "github.com/soctalk/launchpad-sdk-go"

	"github.com/soctalk/launchpad/internal/pluginhost"
)

// Orchestrator drives the pilot flow. Events flow to Events(); external
// callers push commands via Commands().
//
// Multi-plugin: a single Config.Target defines the run's default hypervisor,
// but individual VMs (MSSP or any tenant) may override with their own
// Target + PluginConfig. The orchestrator lazily starts one plugin
// subprocess per distinct target and keeps them alive for the whole run.
type Orchestrator struct {
	cfg      Config
	manifests map[string]*pluginhost.Manifest // resolved by target name
	// extraEnv holds secret env vars to inject into each target's plugin
	// subprocess (keyed by target name): ESXi creds from the host, the
	// Tailscale API key from the network. Kept out of Config so secrets never
	// land in the persisted run config.
	extraEnv map[string][]string

	events   chan Event
	commands chan Command

	// gates is populated when a manual gate is open; the resolver sends on
	// the channel when the operator marks it done.
	gatesMu sync.Mutex
	gates   map[string]chan struct{}

	// state file — persisted on every event. See state.go.
	state *State

	// runtime-only: subprocess clients, one per plugin target in use.
	clientsMu sync.Mutex
	clients   map[string]*pluginhost.Client
}

// New wires an orchestrator around a config + one or more resolved plugin
// manifests, keyed by target name. Callers pass manifests for every target
// referenced in cfg (top-level Target + any per-VM Target overrides).
func New(cfg Config, manifests map[string]*pluginhost.Manifest, state *State) *Orchestrator {
	return NewWithEnv(cfg, manifests, state, nil)
}

// NewWithEnv is New plus per-target secret env injection (see Orchestrator.extraEnv).
func NewWithEnv(cfg Config, manifests map[string]*pluginhost.Manifest, state *State, extraEnv map[string][]string) *Orchestrator {
	if cfg.RunID == "" {
		cfg.RunID = fmt.Sprintf("run-%d", time.Now().Unix())
	}
	return &Orchestrator{
		cfg:       cfg,
		manifests: manifests,
		extraEnv:  extraEnv,
		events:    make(chan Event, 256),
		commands:  make(chan Command, 32),
		gates:     map[string]chan struct{}{},
		state:     state,
		clients:   map[string]*pluginhost.Client{},
	}
}

// Events returns the event stream. Consumers (TUI + drive) drain it.
func (o *Orchestrator) Events() <-chan Event { return o.events }

// Commands returns the command channel. External inputs push here.
func (o *Orchestrator) Commands() chan<- Command { return o.commands }

// Run executes the full flow. Returns nil on success, non-nil on failure.
func (o *Orchestrator) Run(ctx context.Context) error {
	defer close(o.events)

	// Kick off the command dispatcher.
	go o.dispatchCommands(ctx)

	o.emit(Event{Ev: EvPhase, Phase: PhaseInitializing})

	// Cleanup: shut down every plugin subprocess we spawned during the run.
	defer func() {
		sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		o.clientsMu.Lock()
		for _, c := range o.clients {
			_ = c.Shutdown(sctx)
		}
		o.clientsMu.Unlock()
	}()

	// Phase 1: planning (dry-run every VM). Also implicitly warms plugin
	// clients so any config error surfaces before we start provisioning.
	o.emit(Event{Ev: EvPhase, Phase: PhasePlanning})
	if err := o.planAll(ctx); err != nil {
		o.fail("planning: " + err.Error())
		return err
	}

	// Phase 2: provisioning MSSP first, then tenants.
	o.emit(Event{Ev: EvPhase, Phase: PhaseProvisioning})
	if err := o.createVM(ctx, o.cfg.MSSP); err != nil {
		o.fail(fmt.Sprintf("create %s: %v", o.cfg.MSSP.Key, err))
		return err
	}

	// Manual gate — Tailscale ACL paste. Operator confirms then continues.
	if err := o.openGate(ctx,
		"tailscale_acl_pasted",
		"Paste the Tailscale ACL stanza into your admin UI and confirm.",
		"acls: [ ... ]  // (this is where the stanza goes)"); err != nil {
		return err
	}

	for _, t := range o.cfg.Tenants {
		if err := o.createVM(ctx, t); err != nil {
			o.fail(fmt.Sprintf("create %s: %v", t.Key, err))
			return err
		}
	}

	// Phase 3: installing. SSH into each VM (via tailnet MagicDNS) and run
	// the public SocTalk installer; then issue an agent bootstrap on MSSP
	// and install soctalk-cloud-agent on each tenant.
	o.emit(Event{Ev: EvPhase, Phase: PhaseInstalling})
	if err := o.runInstall(ctx); err != nil {
		o.fail("install: " + err.Error())
		return err
	}

	o.emit(Event{Ev: EvPhase, Phase: PhaseComplete})
	o.emit(Event{Ev: EvComplete})
	return nil
}

func (o *Orchestrator) planAll(ctx context.Context) error {
	all := append([]VMSpec{o.cfg.MSSP}, o.cfg.Tenants...)
	for _, s := range all {
		client, err := o.clientFor(ctx, s)
		if err != nil {
			return fmt.Errorf("%s: %w", s.Key, err)
		}
		pctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		var res sdk.VMPlanResult
		err = client.Call(pctx, sdk.MethodVMPlan, sdk.VMPlanParams{Spec: toSDKSpec(o.cfg, s)}, &res)
		cancel()
		if err != nil {
			return err
		}
		o.emit(Event{Ev: EvVMPlan, VMKey: s.Key, Message: res.Summary})
	}
	return nil
}

// clientFor lazily spawns (or reuses) the plugin subprocess for a VM's
// effective target. Each target gets one long-lived client; multiple VMs
// with the same target share it.
func (o *Orchestrator) clientFor(ctx context.Context, s VMSpec) (*pluginhost.Client, error) {
	target := s.EffectiveTarget(o.cfg.Target)
	if target == "" {
		return nil, fmt.Errorf("no target for VM %q (neither vm-level nor config-level)", s.Key)
	}
	o.clientsMu.Lock()
	if c, ok := o.clients[target]; ok {
		o.clientsMu.Unlock()
		return c, nil
	}
	o.clientsMu.Unlock()

	m, ok := o.manifests[target]
	if !ok {
		return nil, fmt.Errorf("plugin manifest for target %q not resolved", target)
	}
	notifications := make(chan *sdk.Envelope, 128)
	go o.relayNotifications(notifications)
	client, err := pluginhost.Start(ctx, m, pluginhost.StartConfig{
		Notifications: notifications,
		EnvAllowlist:  m.Env,
		ExtraEnv:      o.extraEnv[target], // secret creds/keys from host+network
	})
	if err != nil {
		return nil, fmt.Errorf("start plugin %q: %w", target, err)
	}
	o.emit(Event{Ev: EvPluginReady, Fields: map[string]any{
		"plugin":       client.Manifest.Name,
		"version":      client.Manifest.Version,
		"capabilities": client.Hello.Capabilities,
		"target":       target,
	}})

	// Initialize with the effective plugin_config for this target. If any
	// VM referencing this target has a per-VM PluginConfig, we use the
	// FIRST one we see (VMs sharing a target must share config; different
	// configs require different target names).
	pluginCfg := s.EffectivePluginConfig(o.cfg.PluginConfig)
	initCtx, initCancel := context.WithTimeout(ctx, 60*time.Second)
	err = client.Call(initCtx, sdk.MethodInitialize, sdk.InitializeParams{
		RunID: o.cfg.RunID, Config: pluginCfg, LogLevel: "info",
	}, nil)
	initCancel()
	if err != nil {
		return nil, fmt.Errorf("plugin.initialize [%s]: %w", target, err)
	}
	o.clientsMu.Lock()
	o.clients[target] = client
	o.clientsMu.Unlock()
	return client, nil
}

func (o *Orchestrator) createVM(ctx context.Context, s VMSpec) error {
	client, err := o.clientFor(ctx, s)
	if err != nil {
		return err
	}
	if existing, ok := o.state.GetVM(s.Key); ok && existing.VMID != "" {
		// Validate before trusting state: the VM may have been destroyed out
		// of band, or be running with a revoked tailnet device (unreachable).
		ictx, icancel := context.WithTimeout(ctx, 90*time.Second)
		var ir sdk.VMInspectResult
		ierr := client.Call(ictx, sdk.MethodVMInspect, sdk.VMInspectParams{
			RunID: o.cfg.RunID, VMKey: s.Key, VMID: existing.VMID,
		}, &ir)
		icancel()
		if ierr == nil && ir.Exists && ir.State == "running" && ir.IPv4 != "" {
			existing.IPv4 = ir.IPv4
			o.state.SetVM(s.Key, existing)
			o.emit(Event{Ev: EvVMLog, VMKey: s.Key, Level: "info",
				Message: fmt.Sprintf("resuming: VM already provisioned and reachable (id=%s, ip=%s)", existing.VMID, ir.IPv4)})
			o.emit(Event{Ev: EvVMReady, VMKey: s.Key, IPv4: existing.IPv4, SSHUser: existing.SSHUser, SSHPort: existing.SSHPort})
			return nil
		}
		o.emit(Event{Ev: EvVMLog, VMKey: s.Key, Level: "warn",
			Message: fmt.Sprintf("stale state for %s (inspect err=%v exists=%v state=%q ip=%q) — destroying leftovers and re-provisioning",
				s.Key, ierr, ir.Exists, ir.State, ir.IPv4)})
		dctx, dcancel := context.WithTimeout(ctx, 10*time.Minute)
		var dr sdk.VMDestroyResult
		_ = client.Call(dctx, sdk.MethodVMDestroy, sdk.VMDestroyParams{
			RunID: o.cfg.RunID, VMKey: s.Key, VMID: existing.VMID,
			Selector: map[string]string{"run_id": o.cfg.RunID, "vm_key": s.Key},
		}, &dr)
		dcancel()
		o.state.DeleteVM(s.Key)
	}
	cctx, cancel := context.WithTimeout(ctx, 60*time.Minute)
	defer cancel()
	var res sdk.VMCreateResult
	err = client.Call(cctx, sdk.MethodVMCreate, sdk.VMCreateParams{Spec: toSDKSpec(o.cfg, s)}, &res)
	if err != nil {
		return err
	}
	o.state.SetVM(s.Key, StateVM{
		VMID: res.VMID, IPv4: res.IPv4, IPv6: res.IPv6, SSHUser: res.SSHUser, SSHPort: res.SSHPort,
		Target: s.EffectiveTarget(o.cfg.Target),
	})
	// Provisioned, but not necessarily reachable yet — for qemu/vmware the
	// address is only discovered during wait_ready, so hold the vm_ready event
	// until then (a premature vm_ready with an empty IP misleads UI/headless
	// consumers).
	o.emit(Event{Ev: EvVMProgress, VMKey: s.Key, Step: "create", Percent: 100,
		Message: fmt.Sprintf("provisioned (id=%s); waiting for readiness", res.VMID)})

	// Wait for readiness.
	wctx, wcancel := context.WithTimeout(ctx, 30*time.Minute)
	defer wcancel()
	var wres sdk.VMWaitReadyResult
	err = client.Call(wctx, sdk.MethodVMWaitReady, sdk.VMWaitReadyParams{
		RunID: o.cfg.RunID, VMKey: s.Key, VMID: res.VMID, AwaitCloudInit: true,
	}, &wres)
	if err != nil {
		return err
	}
	// If the plugin resolved the address only during readiness (Tailscale
	// devices, DHCP-assigned VMs), fold it into state so `up` resume and
	// `down` can print / dial the real address without re-querying.
	ready, _ := o.state.GetVM(s.Key)
	if wres.IPv4 != "" {
		ready.IPv4 = wres.IPv4
	}
	if wres.IPv6 != "" {
		ready.IPv6 = wres.IPv6
	}
	o.state.SetVM(s.Key, ready)
	// Authoritative vm_ready: emitted only once the VM is reachable, with the
	// final address.
	o.emit(Event{Ev: EvVMReady, VMKey: s.Key, IPv4: ready.IPv4, IPv6: ready.IPv6,
		SSHUser: ready.SSHUser, SSHPort: ready.SSHPort})
	return nil
}

// openGate emits a gate_open event and blocks until the operator resolves it
// (via CmdResolveGate) or the context is cancelled. If the state already
// records the gate as resolved (resumed run) it returns immediately.
func (o *Orchestrator) openGate(ctx context.Context, id, instructions, copyText string) error {
	if o.state.GateResolved[id] {
		o.emit(Event{Ev: EvGateResolved, GateID: id})
		return nil
	}
	ch := make(chan struct{})
	o.gatesMu.Lock()
	o.gates[id] = ch
	o.gatesMu.Unlock()
	o.emit(Event{Ev: EvGateOpen, GateID: id, Instructions: instructions, CopyText: copyText})
	select {
	case <-ch:
		o.state.MarkGateResolved(id)
		o.emit(Event{Ev: EvGateResolved, GateID: id})
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (o *Orchestrator) dispatchCommands(ctx context.Context) {
	for {
		select {
		case cmd := <-o.commands:
			switch cmd.Cmd {
			case CmdResolveGate:
				o.gatesMu.Lock()
				if ch, ok := o.gates[cmd.GateID]; ok {
					close(ch)
					delete(o.gates, cmd.GateID)
				}
				o.gatesMu.Unlock()
			case CmdCancel:
				// Cancel is context-driven higher up; we just ignore here.
			}
		case <-ctx.Done():
			return
		}
	}
}

// relayNotifications forwards plugin-emitted progress/log frames as events.
func (o *Orchestrator) relayNotifications(ch <-chan *sdk.Envelope) {
	for env := range ch {
		switch env.Method {
		case sdk.MethodProgress:
			var p sdk.ProgressParams
			_ = sdk.ParseParams(env, &p)
			o.emit(Event{
				Ev: EvVMProgress, VMKey: p.VMKey, Step: p.Step,
				Percent: p.Percent, Message: p.Message,
			})
		case sdk.MethodLog:
			var p sdk.LogParams
			_ = sdk.ParseParams(env, &p)
			o.emit(Event{
				Ev: EvVMLog, VMKey: p.VMKey, Level: p.Level,
				Message: p.Message, Fields: p.Fields,
			})
		}
	}
}

func (o *Orchestrator) emit(ev Event) {
	if ev.Time.IsZero() {
		ev.Time = time.Now().UTC()
	}
	if o.state != nil {
		o.state.RecordEvent(ev)
	}
	select {
	case o.events <- ev:
	default:
		// Consumer isn't draining; drop rather than block orchestration.
	}
}

func (o *Orchestrator) fail(msg string) {
	o.emit(Event{Ev: EvError, Error: &EventError{
		Category: "internal", Code: "orchestrator.failed", Message: msg,
	}})
	o.emit(Event{Ev: EvPhase, Phase: PhaseFailed})
}

// ErrCancelled is returned when the orchestrator is cancelled.
var ErrCancelled = errors.New("orchestration cancelled")

// toSDKSpec builds the plugin-facing VMSpec. Role and TenantSlug are
// first-class launchpad fields but plugins only see the tags map, so fold
// them in (without clobbering an explicit tag) — otherwise a config that
// sets role/tenant_slug without duplicating them into tags gets the wrong
// Tailscale tag (e.g. tag:lp-tenant-acme instead of tag:tenant-acme).
func toSDKSpec(cfg Config, s VMSpec) sdk.VMSpec {
	tags := map[string]string{}
	for k, v := range s.Tags {
		tags[k] = v
	}
	if s.Role != "" && tags["role"] == "" {
		tags["role"] = s.Role
	}
	if s.TenantSlug != "" && tags["tenant_slug"] == "" {
		tags["tenant_slug"] = s.TenantSlug
	}
	return sdk.VMSpec{
		RunID:            cfg.RunID,
		VMKey:            s.Key,
		Name:             s.Name,
		Region:           s.Region,
		Image:            s.Image,
		SizeHint:         s.SizeHint,
		SSHKeys:          cfg.SSHKeys,
		Tags:             tags,
		IdempotencyToken: cfg.RunID + "/" + s.Key,
	}
}
