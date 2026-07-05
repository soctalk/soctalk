package orchestrator

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// State is the persistent record of what the orchestrator has done. Written
// on every event so a killed launchpad can resume.
type State struct {
	mu      sync.Mutex
	path    string
	RunID   string             `json:"run_id"`
	Target  string             `json:"target"`
	VMs     map[string]StateVM `json:"vms"`
	Events  []Event            `json:"events"`
	// GateResolved tracks manual gates already confirmed, so a resumed
	// run doesn't re-prompt.
	GateResolved map[string]bool `json:"gate_resolved"`
}

type StateVM struct {
	VMID    string `json:"vm_id"`
	IPv4    string `json:"ipv4"`
	IPv6    string `json:"ipv6"`
	SSHUser string `json:"ssh_user"`
	SSHPort int    `json:"ssh_port"`
	// Target is the plugin name that owns this VM. Needed for `launchpad
	// down` to route destroys to the right plugin when the run mixes
	// hypervisors.
	Target string `json:"target,omitempty"`
}

// LoadOrInit reads state from path, or creates an empty state file if none.
func LoadOrInit(path, runID, target string) (*State, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	b, err := os.ReadFile(path)
	if err == nil {
		s := &State{path: path}
		if err := json.Unmarshal(b, s); err != nil {
			return nil, fmt.Errorf("parse state %s: %w", path, err)
		}
		s.path = path
		if s.VMs == nil {
			s.VMs = map[string]StateVM{}
		}
		if s.GateResolved == nil {
			s.GateResolved = map[string]bool{}
		}
		return s, nil
	}
	if !os.IsNotExist(err) {
		return nil, err
	}
	return &State{
		path:         path,
		RunID:        runID,
		Target:       target,
		VMs:          map[string]StateVM{},
		GateResolved: map[string]bool{},
	}, nil
}

func (s *State) SetVM(key string, vm StateVM) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.VMs[key] = vm
	_ = s.saveLocked()
}

// DeleteVM drops a VM from state — used when resume validation finds the
// recorded VM gone or unreachable and the orchestrator re-provisions.
func (s *State) DeleteVM(key string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.VMs, key)
	_ = s.saveLocked()
}

func (s *State) GetVM(key string) (StateVM, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	vm, ok := s.VMs[key]
	return vm, ok
}

func (s *State) RecordEvent(ev Event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Events = append(s.Events, ev)
	// Cap the event log so state files don't grow unbounded.
	if len(s.Events) > 2000 {
		s.Events = s.Events[len(s.Events)-2000:]
	}
	_ = s.saveLocked()
}

func (s *State) MarkGateResolved(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.GateResolved[id] = true
	_ = s.saveLocked()
}

// saveLocked is the on-disk write path. Callers must hold s.mu.
func (s *State) saveLocked() error {
	tmp := s.path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if err := json.NewEncoder(f).Encode(s); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}
