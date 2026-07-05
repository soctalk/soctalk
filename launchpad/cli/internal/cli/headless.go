package cli

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/soctalk/launchpad/internal/orchestrator"
)

// runHeadless drives the orchestrator with:
//   - events emitted as one JSON object per line on stdout
//   - commands read from stdin, one JSON object per line
//   - logs (unstructured) on stderr
//
// Same code path that a TUI wraps, plus the JSON I/O contract. This is what
// makes automated end-to-end tests possible from a bash script.
func runHeadless(ctx context.Context, orch *orchestrator.Orchestrator, opts UpOptions) error {
	// Emit events to stdout.
	eventsDone := make(chan error, 1)
	go func() {
		enc := json.NewEncoder(os.Stdout)
		for ev := range orch.Events() {
			if err := enc.Encode(&ev); err != nil {
				eventsDone <- err
				return
			}
			// Auto-resolve gates in --auto-resolve-gates mode.
			if opts.AutoResolveGates && ev.Ev == orchestrator.EvGateOpen {
				orch.Commands() <- orchestrator.Command{
					Cmd: orchestrator.CmdResolveGate, GateID: ev.GateID,
				}
			}
			// If a phase reports failure, exit fast.
			if ev.Ev == orchestrator.EvPhase && ev.Phase == orchestrator.PhaseFailed {
				eventsDone <- fmt.Errorf("orchestration failed")
				return
			}
		}
		eventsDone <- nil
	}()

	// Read commands from stdin.
	go func() {
		sc := bufio.NewScanner(os.Stdin)
		for sc.Scan() {
			line := sc.Bytes()
			if len(line) == 0 {
				continue
			}
			var cmd orchestrator.Command
			if err := json.Unmarshal(line, &cmd); err != nil {
				fmt.Fprintln(os.Stderr, "launchpad: bad command:", err)
				continue
			}
			select {
			case orch.Commands() <- cmd:
			case <-ctx.Done():
				return
			}
		}
	}()

	if err := orch.Run(ctx); err != nil {
		<-eventsDone
		return err
	}
	return <-eventsDone
}
