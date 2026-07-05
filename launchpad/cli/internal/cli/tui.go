package cli

// Bubble Tea TUI for `launchpad up`. Reads the same events runHeadless emits
// and renders:
//   - Per-VM step + percent progress bar
//   - Rolling last-N log lines
//   - Manual-gate prompt (blocks until operator hits enter)
//
// Keeps state minimal on purpose — nothing that isn't in an Event lives here.

import (
	"context"
	"fmt"
	"sort"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/soctalk/launchpad/internal/orchestrator"
)

const logRingCap = 12

type vmStatus struct {
	step    string
	pct     float64
	message string
}

type tuiModel struct {
	orch       *orchestrator.Orchestrator
	cancel     context.CancelFunc
	autoGates  bool
	phase      string
	vms        map[string]*vmStatus
	log        []string
	gateOpen   *orchestrator.Event // non-nil while a gate is awaiting confirmation
	err        string
	complete   bool
	completeAt string
}

type eventMsg orchestrator.Event
type doneMsg struct{ err error }

// waitEvent returns a Cmd that pulls one event from the orchestrator's channel
// and delivers it as a tea message.
func waitEvent(events <-chan orchestrator.Event) tea.Cmd {
	return func() tea.Msg {
		ev, ok := <-events
		if !ok {
			return doneMsg{}
		}
		return eventMsg(ev)
	}
}

func newTUIModel(orch *orchestrator.Orchestrator, cancel context.CancelFunc, autoGates bool) tuiModel {
	return tuiModel{
		orch:      orch,
		cancel:    cancel,
		autoGates: autoGates,
		vms:       map[string]*vmStatus{},
	}
}

func (m tuiModel) Init() tea.Cmd {
	return waitEvent(m.orch.Events())
}

func (m tuiModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {

	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "q":
			if m.cancel != nil {
				m.cancel()
			}
			return m, tea.Quit
		case "enter":
			if m.gateOpen != nil {
				m.orch.Commands() <- orchestrator.Command{Cmd: orchestrator.CmdResolveGate, GateID: m.gateOpen.GateID}
				m.gateOpen = nil
			}
			return m, nil
		}

	case eventMsg:
		ev := orchestrator.Event(msg)
		switch ev.Ev {
		case orchestrator.EvPhase:
			m.phase = string(ev.Phase)
		case orchestrator.EvVMProgress:
			vm := m.vms[ev.VMKey]
			if vm == nil {
				vm = &vmStatus{}
				m.vms[ev.VMKey] = vm
			}
			vm.step = ev.Step
			vm.pct = ev.Percent
			vm.message = ev.Message
		case orchestrator.EvVMReady:
			vm := m.vms[ev.VMKey]
			if vm == nil {
				vm = &vmStatus{}
				m.vms[ev.VMKey] = vm
			}
			vm.step = "ready"
			vm.pct = 100
			if ev.IPv4 != "" {
				vm.message = "ready — " + ev.IPv4
			}
		case orchestrator.EvVMLog:
			m.pushLog(fmt.Sprintf("[%s] %s", ev.VMKey, ev.Message))
		case orchestrator.EvGateOpen:
			if m.autoGates {
				m.orch.Commands() <- orchestrator.Command{Cmd: orchestrator.CmdResolveGate, GateID: ev.GateID}
			} else {
				ev := ev
				m.gateOpen = &ev
			}
		case orchestrator.EvGateResolved:
			m.pushLog("gate resolved: " + ev.GateID)
		case orchestrator.EvError:
			if ev.Error != nil {
				m.err = ev.Error.Message
			}
		case orchestrator.EvComplete:
			m.complete = true
			m.completeAt = ev.Time.Format("15:04:05")
		}
		return m, waitEvent(m.orch.Events())

	case doneMsg:
		return m, tea.Quit
	}

	return m, nil
}

func (m *tuiModel) pushLog(line string) {
	m.log = append(m.log, line)
	if len(m.log) > logRingCap {
		m.log = m.log[len(m.log)-logRingCap:]
	}
}

var (
	styleTitle   = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("212"))
	stylePhase   = lipgloss.NewStyle().Foreground(lipgloss.Color("214"))
	styleGood    = lipgloss.NewStyle().Foreground(lipgloss.Color("40"))
	styleBad     = lipgloss.NewStyle().Foreground(lipgloss.Color("196")).Bold(true)
	styleDim     = lipgloss.NewStyle().Foreground(lipgloss.Color("240"))
	styleGate    = lipgloss.NewStyle().Foreground(lipgloss.Color("226")).Bold(true)
	styleVMLine  = lipgloss.NewStyle().Foreground(lipgloss.Color("117"))
	stylePercent = lipgloss.NewStyle().Foreground(lipgloss.Color("42"))
)

func progressBar(pct float64) string {
	width := 24
	filled := int((pct / 100.0) * float64(width))
	if filled < 0 {
		filled = 0
	}
	if filled > width {
		filled = width
	}
	return "[" + strings.Repeat("█", filled) + strings.Repeat("░", width-filled) + "]"
}

func (m tuiModel) View() string {
	var b strings.Builder
	b.WriteString(styleTitle.Render("launchpad up"))
	b.WriteString("  ")
	b.WriteString(stylePhase.Render("phase=" + m.phase))
	b.WriteString("\n\n")

	// Deterministic VM order.
	keys := make([]string, 0, len(m.vms))
	for k := range m.vms {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		v := m.vms[k]
		pctStr := stylePercent.Render(fmt.Sprintf("%3.0f%%", v.pct))
		line := fmt.Sprintf("  %s  %s  %s  %s",
			styleVMLine.Render(padRight(k, 18)),
			progressBar(v.pct), pctStr,
			padRight(v.step, 12))
		if v.message != "" {
			line += "  " + styleDim.Render(v.message)
		}
		b.WriteString(line + "\n")
	}
	b.WriteString("\n")

	// Log tail.
	if len(m.log) > 0 {
		b.WriteString(styleDim.Render("recent log:") + "\n")
		for _, l := range m.log {
			if len(l) > 200 {
				l = l[:200] + "…"
			}
			b.WriteString("  " + styleDim.Render(l) + "\n")
		}
		b.WriteString("\n")
	}

	// Gate prompt.
	if m.gateOpen != nil {
		b.WriteString(styleGate.Render("gate: " + m.gateOpen.GateID) + "\n")
		b.WriteString("  " + m.gateOpen.Instructions + "\n")
		if m.gateOpen.CopyText != "" {
			b.WriteString(styleDim.Render("  copy:") + " " + m.gateOpen.CopyText + "\n")
		}
		b.WriteString(styleGate.Render("  press enter to confirm") + "\n\n")
	}

	// Terminal state.
	if m.err != "" {
		b.WriteString(styleBad.Render("error: "+m.err) + "\n")
	} else if m.complete {
		b.WriteString(styleGood.Render("complete at "+m.completeAt) + "\n")
	}
	b.WriteString(styleDim.Render("(q to quit)"))
	return b.String()
}

func padRight(s string, n int) string {
	if len(s) >= n {
		return s
	}
	return s + strings.Repeat(" ", n-len(s))
}

// runTUI orchestrates the Bubble Tea program alongside orch.Run.
func runTUI(ctx context.Context, orch *orchestrator.Orchestrator, opts UpOptions) error {
	rctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Kick off Run in the background; its events drain through orch.Events().
	runErr := make(chan error, 1)
	go func() { runErr <- orch.Run(rctx) }()

	model := newTUIModel(orch, cancel, opts.AutoResolveGates)
	prog := tea.NewProgram(model)
	if _, err := prog.Run(); err != nil {
		return err
	}
	return <-runErr
}
