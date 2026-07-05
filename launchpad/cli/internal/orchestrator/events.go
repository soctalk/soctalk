package orchestrator

import "time"

// Event is the union type published by the orchestrator. Every state
// transition becomes an event; the TUI and the headless driver subscribe.
//
// Wire encoding is stable JSON: one Event per line, {"ev": "...", ...}.
type Event struct {
	// Ev is the discriminator. Callers should switch on it.
	Ev   EventKind `json:"ev"`
	Time time.Time `json:"time"`

	// The remaining fields are populated for specific event kinds.
	Phase   PhaseName   `json:"phase,omitempty"`
	VMKey   string      `json:"vm_key,omitempty"`
	Step    string      `json:"step,omitempty"`
	Percent float64     `json:"percent,omitempty"`
	Message string      `json:"message,omitempty"`
	Level   string      `json:"level,omitempty"`
	Fields  map[string]any `json:"fields,omitempty"`

	// GateOpen fields.
	GateID       string `json:"gate_id,omitempty"`
	Instructions string `json:"instructions,omitempty"`
	CopyText     string `json:"copy_text,omitempty"`

	// VMReady fields.
	IPv4    string `json:"ipv4,omitempty"`
	IPv6    string `json:"ipv6,omitempty"`
	SSHUser string `json:"ssh_user,omitempty"`
	SSHPort int    `json:"ssh_port,omitempty"`

	// Error fields.
	Error *EventError `json:"error,omitempty"`
}

// EventError mirrors the plugin error shape for consumers that don't
// want to import the SDK types.
type EventError struct {
	Category string `json:"category"`
	Code     string `json:"code"`
	Message  string `json:"message"`
	Hint     string `json:"hint,omitempty"`
}

// EventKind is the discriminator for Event.Ev.
type EventKind string

const (
	EvPhase         EventKind = "phase"
	EvPluginReady   EventKind = "plugin_ready"
	EvVMPlan        EventKind = "vm_plan"
	EvVMProgress    EventKind = "vm_progress"
	EvVMReady       EventKind = "vm_ready"
	EvVMLog         EventKind = "vm_log"
	EvGateOpen      EventKind = "gate_open"
	EvGateResolved  EventKind = "gate_resolved"
	EvError         EventKind = "error"
	EvComplete      EventKind = "complete"
)

// PhaseName is a coarse orchestration phase for progress display.
type PhaseName string

const (
	PhaseInitializing PhaseName = "initializing"
	PhasePlanning     PhaseName = "planning"
	PhaseProvisioning PhaseName = "provisioning"
	PhaseInstalling   PhaseName = "installing"
	PhaseComplete     PhaseName = "complete"
	PhaseFailed       PhaseName = "failed"
)

// Command is what the driver / TUI sends back to the orchestrator. Same JSON
// framing: one Command per line, {"cmd": "..."}.
type Command struct {
	Cmd    CommandKind `json:"cmd"`
	GateID string      `json:"gate_id,omitempty"`
	// Additional per-command fields as needed.
}

type CommandKind string

const (
	CmdResolveGate CommandKind = "resolve_gate"
	CmdCancel      CommandKind = "cancel"
)
