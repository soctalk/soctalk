package orchestrator

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadOrInit_FreshState(t *testing.T) {
	dir := t.TempDir()
	s, err := LoadOrInit(filepath.Join(dir, "run.json"), "run-1", "mock")
	if err != nil {
		t.Fatal(err)
	}
	if s.RunID != "run-1" || s.Target != "mock" {
		t.Fatalf("expected run-1/mock, got %+v", s)
	}
	if s.VMs == nil || s.GateResolved == nil {
		t.Fatal("maps should be initialized")
	}
}

func TestSetVMPersists(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "run.json")
	s, err := LoadOrInit(path, "run-1", "mock")
	if err != nil {
		t.Fatal(err)
	}
	s.SetVM("mssp", StateVM{VMID: "vm-1", IPv4: "10.0.0.1", SSHUser: "ops", SSHPort: 22})

	// Reload and confirm.
	s2, err := LoadOrInit(path, "run-1", "mock")
	if err != nil {
		t.Fatal(err)
	}
	got, ok := s2.GetVM("mssp")
	if !ok || got.VMID != "vm-1" || got.IPv4 != "10.0.0.1" {
		t.Fatalf("state not persisted: %+v", got)
	}
}

func TestMarkGateResolvedPersists(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "run.json")
	s, _ := LoadOrInit(path, "run-1", "mock")
	s.MarkGateResolved("tailscale_acl_pasted")

	s2, _ := LoadOrInit(path, "run-1", "mock")
	if !s2.GateResolved["tailscale_acl_pasted"] {
		t.Fatal("gate_resolved not persisted")
	}
}

func TestStateEventCapacity(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "run.json")
	s, _ := LoadOrInit(path, "run-1", "mock")
	for i := 0; i < 2500; i++ {
		s.RecordEvent(Event{Ev: EvVMLog, Message: "x"})
	}
	if len(s.Events) != 2000 {
		t.Fatalf("expected event ring at 2000, got %d", len(s.Events))
	}
}

func TestStateAtomicRename(t *testing.T) {
	// Confirm we don't leave a .tmp file after a normal save.
	dir := t.TempDir()
	path := filepath.Join(dir, "run.json")
	s, _ := LoadOrInit(path, "run-1", "mock")
	s.SetVM("mssp", StateVM{VMID: "vm-1"})
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".tmp" {
			t.Fatalf("stale .tmp left: %s", e.Name())
		}
	}
	// Also confirm the JSON is decodable.
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var out State
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("state json invalid: %v", err)
	}
}
