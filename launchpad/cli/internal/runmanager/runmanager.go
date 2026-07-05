// Package runmanager owns run lifecycle for the HTTP/UI layer: it starts
// orchestrations, pumps their events into per-run journals, tracks status,
// and exposes cancel / gate-resolve / teardown. One Manager per process;
// runs are in-process (single-writer model — see PLAN_V2 "Process model").
package runmanager

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/soctalk/launchpad/internal/eventjournal"
	"github.com/soctalk/launchpad/internal/orchestrator"
	"github.com/soctalk/launchpad/internal/pluginhost"
)

// Status is the coarse run state exposed to clients.
type Status string

const (
	StatusRunning     Status = "running"
	StatusComplete    Status = "complete"
	StatusFailed      Status = "failed"
	StatusCancelling  Status = "cancelling"
	StatusCancelled   Status = "cancelled"
	StatusTearingDown Status = "tearing_down"
	StatusTornDown    Status = "torn_down"
)

// Run is one orchestration owned by this process.
type Run struct {
	ID        string
	Cfg       orchestrator.Config
	Journal   *eventjournal.Journal
	StartedAt time.Time
	// extraEnv is the per-target secret env this run was started with (host
	// creds + network API key). Held in memory so teardown can reach the same
	// providers; never persisted.
	extraEnv map[string][]string

	mu      sync.Mutex
	status  Status
	err     string
	endedAt time.Time
	cancel  context.CancelFunc
	orch    *orchestrator.Orchestrator
	state   *orchestrator.State

	// open gates by id → instructions (for snapshot; resolve goes via orch).
	gates map[string]string
}

// Snapshot is the JSON-friendly view of a run.
type Snapshot struct {
	ID        string               `json:"id"`
	Status    Status               `json:"status"`
	Error     string               `json:"error,omitempty"`
	Phase     string               `json:"phase"`
	StartedAt time.Time            `json:"started_at"`
	EndedAt   *time.Time           `json:"ended_at,omitempty"`
	LastSeq   int64                `json:"last_seq"`
	VMs       []VMSnapshot         `json:"vms"`
	Gates     []GateSnapshot       `json:"gates"`
	Config    orchestrator.Config  `json:"config"`
}

type VMSnapshot struct {
	Key      string `json:"key"`
	Role     string `json:"role"`
	Name     string `json:"name"`
	IPv4     string `json:"ipv4,omitempty"`
	SSHUser  string `json:"ssh_user,omitempty"`
	Hostname string `json:"hostname,omitempty"` // lp-<key>.<tailnet>
	URL      string `json:"url,omitempty"`      // MSSP UI URL when known
}

type GateSnapshot struct {
	ID           string `json:"id"`
	Instructions string `json:"instructions"`
}

// Manager tracks all runs in this process.
type Manager struct {
	dir string // ~/.launchpad/runs

	mu   sync.Mutex
	runs map[string]*Run
	// phase per run derived from events (kept out of Run.mu to avoid loops)
	phases map[string]string
}

func New(dir string) *Manager {
	return &Manager{dir: dir, runs: map[string]*Run{}, phases: map[string]string{}}
}

// Start launches a new run. The config must already be validated. Gates are
// NOT auto-resolved — the UI resolves them via ResolveGate. extraEnv carries
// per-target secret env (host creds, network API key) injected into plugin
// subprocesses — kept separate from cfg so secrets never persist to disk.
func (m *Manager) Start(cfg orchestrator.Config, extraEnv map[string][]string) (*Run, error) {
	if cfg.RunID == "" {
		cfg.RunID = fmt.Sprintf("run-%d", time.Now().Unix())
	}
	// Lock order is always m.mu → (release) → r.mu; never nested, because
	// the event pump acquires r.mu then m.mu and nesting here would deadlock.
	m.mu.Lock()
	existing := m.runs[cfg.RunID]
	m.mu.Unlock()
	if existing != nil {
		existing.mu.Lock()
		st := existing.status
		existing.mu.Unlock()
		if st == StatusRunning || st == StatusCancelling || st == StatusTearingDown {
			return nil, fmt.Errorf("run %q is already %s", cfg.RunID, st)
		}
	}

	manifests, err := resolveTargets(cfg)
	if err != nil {
		return nil, err
	}
	statePath := filepath.Join(m.dir, cfg.RunID+".json")
	state, err := orchestrator.LoadOrInit(statePath, cfg.RunID, cfg.Target)
	if err != nil {
		return nil, err
	}
	journal, err := eventjournal.Open(filepath.Join(m.dir, cfg.RunID+".events.jsonl"))
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancel(context.Background())
	orch := orchestrator.NewWithEnv(cfg, manifests, state, extraEnv)
	run := &Run{
		ID: cfg.RunID, Cfg: cfg, Journal: journal, StartedAt: time.Now().UTC(),
		extraEnv: extraEnv,
		status:   StatusRunning, cancel: cancel, orch: orch, state: state,
		gates:    map[string]string{},
	}
	m.mu.Lock()
	m.runs[cfg.RunID] = run
	m.mu.Unlock()

	// Event pump: journal + status/gate tracking.
	go func() {
		for ev := range orch.Events() {
			journal.Append(ev)
			run.mu.Lock()
			switch ev.Ev {
			case orchestrator.EvGateOpen:
				run.gates[ev.GateID] = ev.Instructions
			case orchestrator.EvGateResolved:
				delete(run.gates, ev.GateID)
			case orchestrator.EvPhase:
				m.mu.Lock()
				m.phases[run.ID] = string(ev.Phase)
				m.mu.Unlock()
			}
			run.mu.Unlock()
		}
	}()

	// Runner.
	go func() {
		err := orch.Run(ctx)
		run.mu.Lock()
		run.endedAt = time.Now().UTC()
		switch {
		case err == nil:
			run.status = StatusComplete
		case ctx.Err() != nil && run.status == StatusCancelling:
			run.status = StatusCancelled
			run.err = "cancelled by user"
		default:
			run.status = StatusFailed
			run.err = err.Error()
		}
		run.mu.Unlock()
	}()
	return run, nil
}

// Get returns a run by id.
func (m *Manager) Get(id string) (*Run, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.runs[id]
	return r, ok
}

// List returns snapshots of every run, newest first.
func (m *Manager) List() []Snapshot {
	m.mu.Lock()
	runs := make([]*Run, 0, len(m.runs))
	for _, r := range m.runs {
		runs = append(runs, r)
	}
	m.mu.Unlock()
	out := make([]Snapshot, 0, len(runs))
	for _, r := range runs {
		out = append(out, m.SnapshotOf(r))
	}
	// newest first
	for i := 0; i < len(out); i++ {
		for k := i + 1; k < len(out); k++ {
			if out[k].StartedAt.After(out[i].StartedAt) {
				out[i], out[k] = out[k], out[i]
			}
		}
	}
	return out
}

// SnapshotOf builds the client view of a run.
func (m *Manager) SnapshotOf(r *Run) Snapshot {
	r.mu.Lock()
	snap := Snapshot{
		ID: r.ID, Status: r.status, Error: r.err,
		StartedAt: r.StartedAt, LastSeq: r.Journal.LastSeq(),
		Config: redactConfig(r.Cfg),
	}
	if !r.endedAt.IsZero() {
		t := r.endedAt
		snap.EndedAt = &t
	}
	for id, instr := range r.gates {
		snap.Gates = append(snap.Gates, GateSnapshot{ID: id, Instructions: instr})
	}
	r.mu.Unlock()

	m.mu.Lock()
	snap.Phase = m.phases[r.ID]
	m.mu.Unlock()

	tailnet := tailnetOf(r.Cfg)
	specs := append([]orchestrator.VMSpec{r.Cfg.MSSP}, r.Cfg.Tenants...)
	for _, s := range specs {
		vm := VMSnapshot{Key: s.Key, Role: s.Role, Name: s.Name}
		if st, ok := r.state.GetVM(s.Key); ok {
			vm.IPv4 = st.IPv4
			vm.SSHUser = st.SSHUser
		}
		if tailnet != "" {
			vm.Hostname = "lp-" + s.Key + "." + tailnet
			if s.Role == "mssp" {
				vm.URL = "https://" + vm.Hostname + "/"
			}
		}
		snap.VMs = append(snap.VMs, vm)
	}
	return snap
}

// ResolveGate marks a gate done (from the UI).
func (m *Manager) ResolveGate(runID, gateID string) error {
	r, ok := m.Get(runID)
	if !ok {
		return fmt.Errorf("run %q not found", runID)
	}
	r.orch.Commands() <- orchestrator.Command{Cmd: orchestrator.CmdResolveGate, GateID: gateID}
	return nil
}

// Cancel aborts an in-flight run. Idempotent.
func (m *Manager) Cancel(runID string) error {
	r, ok := m.Get(runID)
	if !ok {
		return fmt.Errorf("run %q not found", runID)
	}
	r.mu.Lock()
	if r.status == StatusRunning {
		r.status = StatusCancelling
		r.cancel()
	}
	r.mu.Unlock()
	return nil
}

// Down tears down a run's VMs (reverse order), streaming into its journal.
func (m *Manager) Down(runID string) error {
	r, ok := m.Get(runID)
	if !ok {
		return fmt.Errorf("run %q not found", runID)
	}
	r.mu.Lock()
	if r.status == StatusRunning || r.status == StatusCancelling || r.status == StatusTearingDown {
		st := r.status
		r.mu.Unlock()
		return fmt.Errorf("run is %s; cancel first", st)
	}
	r.status = StatusTearingDown
	r.mu.Unlock()

	manifests, err := resolveTargets(r.Cfg)
	if err != nil {
		return err
	}
	// Reverse-provision order: tenants first, MSSP last.
	order := make([]orchestrator.VMSpec, 0, len(r.Cfg.Tenants)+1)
	for i := len(r.Cfg.Tenants) - 1; i >= 0; i-- {
		order = append(order, r.Cfg.Tenants[i])
	}
	order = append(order, r.Cfg.MSSP)

	events := make(chan orchestrator.Event, 256)
	errCh := make(chan error, 1)
	d := &orchestrator.DownContext{Cfg: r.Cfg, Manifests: manifests, State: r.state, Order: order, ExtraEnv: r.extraEnv}
	go func() {
		errCh <- d.Run(context.Background(), events) // closes events on return
	}()
	go func() {
		for ev := range events {
			r.Journal.Append(ev)
		}
		err := <-errCh
		r.mu.Lock()
		// A partial teardown must not read as torn down: the run stays failed
		// so the UI keeps offering a retry and the state file is preserved.
		if err != nil {
			r.status = StatusFailed
			r.err = err.Error()
		} else {
			r.status = StatusTornDown
		}
		r.endedAt = time.Now().UTC()
		r.mu.Unlock()
	}()
	return nil
}

// redactConfig strips user-supplied secrets from the config echo.
func redactConfig(cfg orchestrator.Config) orchestrator.Config {
	if cfg.Install.LLMAPIKey != "" {
		cfg.Install.LLMAPIKey = "[redacted]"
	}
	return cfg
}

// tailnetOf digs the tailnet name out of the effective plugin config.
func tailnetOf(cfg orchestrator.Config) string {
	if v, ok := cfg.PluginConfig["tailnet"].(string); ok {
		return v
	}
	if v, ok := cfg.MSSP.PluginConfig["tailnet"].(string); ok {
		return v
	}
	return ""
}

// resolveTargets mirrors internal/cli.resolveTargets (kept separate to avoid
// an import cycle through the command layer).
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
		return nil, fmt.Errorf("no target specified")
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
	return nil, fmt.Errorf("plugin %q not found", name)
}
