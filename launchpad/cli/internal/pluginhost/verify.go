package pluginhost

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	sdk "github.com/soctalk/launchpad-sdk-go"
)

// VerifyOptions controls the compliance suite.
type VerifyOptions struct {
	// RunID + VMKey used for the synthetic VM operations. Deterministic so
	// idempotency checks work.
	RunID string
	VMKey string
}

// VerifyReport summarizes the compliance run.
type VerifyReport struct {
	Plugin  string
	Version string
	Checks  []VerifyCheck
}

// VerifyCheck is one line item in the report.
type VerifyCheck struct {
	Name    string
	Passed  bool
	Message string
}

// AllPassed returns true iff every check succeeded.
func (r *VerifyReport) AllPassed() bool {
	for _, c := range r.Checks {
		if !c.Passed {
			return false
		}
	}
	return true
}

// String renders a human-readable report.
func (r *VerifyReport) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "Plugin: %s @ %s\n\n", r.Plugin, r.Version)
	for _, c := range r.Checks {
		mark := "✓"
		if !c.Passed {
			mark = "✗"
		}
		fmt.Fprintf(&b, "  %s  %s", mark, c.Name)
		if c.Message != "" {
			fmt.Fprintf(&b, " — %s", c.Message)
		}
		b.WriteByte('\n')
	}
	if r.AllPassed() {
		b.WriteString("\nAll checks passed.\n")
	} else {
		b.WriteString("\nOne or more checks failed.\n")
	}
	return b.String()
}

// Verify spawns the plugin and exercises the protocol surface. It does not
// require real credentials; plugins should return a validation error in
// Initialize if creds are missing, which Verify records as an informational
// item rather than a failure.
func Verify(ctx context.Context, m *Manifest, opts VerifyOptions) (*VerifyReport, error) {
	if opts.RunID == "" {
		opts.RunID = "verify-run"
	}
	if opts.VMKey == "" {
		opts.VMKey = "verify-vm"
	}

	report := &VerifyReport{Plugin: m.Name, Version: m.Version}
	add := func(name string, ok bool, msg string) {
		report.Checks = append(report.Checks, VerifyCheck{Name: name, Passed: ok, Message: msg})
	}

	if err := m.VerifyChecksum(); err != nil {
		add("manifest.checksum", false, err.Error())
	} else if m.SHA256 == "" {
		add("manifest.checksum", true, "not declared (skipped)")
	} else {
		add("manifest.checksum", true, "match")
	}

	// Spawn.
	notifications := make(chan *sdk.Envelope, 32)
	client, err := Start(ctx, m, StartConfig{
		HelloTimeout:  10 * time.Second,
		Notifications: notifications,
		EnvAllowlist:  m.Env,
	})
	if err != nil {
		add("handshake.hello", false, err.Error())
		return report, nil
	}
	add("handshake.hello", true, fmt.Sprintf("protocol=%s caps=%v", client.Hello.ProtocolVersion, client.Hello.Capabilities))

	// Drain notifications in the background.
	go func() {
		for range notifications {
			// Compliance suite doesn't consume notifications; drop.
		}
	}()

	defer func() {
		sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = client.Shutdown(sctx)
	}()

	// Initialize.
	ictx, cancel := context.WithTimeout(ctx, 30*time.Second)
	var initResult sdk.InitializeResult
	err = client.Call(ictx, sdk.MethodInitialize, sdk.InitializeParams{
		RunID:    opts.RunID,
		Config:   map[string]any{},
		LogLevel: "warn",
		DryRun:   true,
	}, &initResult)
	cancel()
	if err != nil {
		var rpc *RPCError
		if errors.As(err, &rpc) && rpc.Data != nil && (rpc.Data.Category == sdk.CatAuth || rpc.Data.Category == sdk.CatValidation) {
			add("plugin.initialize", true, "auth error (expected without real credentials): "+rpc.Msg)
		} else {
			add("plugin.initialize", false, err.Error())
			return report, nil
		}
	} else if !initResult.Ready {
		add("plugin.initialize", false, "returned ready=false")
	} else {
		add("plugin.initialize", true, "ready=true")
	}

	// vm.plan (if declared).
	if hasCap(client.Hello.Capabilities, sdk.MethodVMPlan) {
		pctx, pcancel := context.WithTimeout(ctx, 30*time.Second)
		var planRes sdk.VMPlanResult
		err := client.Call(pctx, sdk.MethodVMPlan, sdk.VMPlanParams{Spec: sdk.VMSpec{
			RunID: opts.RunID, VMKey: opts.VMKey, Name: "verify", Region: "verify", Image: "verify", SizeHint: "verify",
		}}, &planRes)
		pcancel()
		if err != nil {
			var rpc *RPCError
			if errors.As(err, &rpc) && rpc.Data != nil && (rpc.Data.Category == sdk.CatAuth || rpc.Data.Category == sdk.CatValidation) {
				add("vm.plan", true, "config/auth error (expected without real credentials)")
			} else {
				add("vm.plan", false, err.Error())
			}
		} else {
			add("vm.plan", true, planRes.Summary)
		}
	} else {
		add("vm.plan", true, "not declared in capabilities (skipped)")
	}

	// vm.destroy against a non-existent VM should return Destroyed=false
	// without erroring (idempotency check).
	if hasCap(client.Hello.Capabilities, sdk.MethodVMDestroy) {
		dctx, dcancel := context.WithTimeout(ctx, 30*time.Second)
		var destroyRes sdk.VMDestroyResult
		err := client.Call(dctx, sdk.MethodVMDestroy, sdk.VMDestroyParams{
			RunID: opts.RunID, VMKey: "verify-nonexistent",
		}, &destroyRes)
		dcancel()
		if err != nil {
			var rpc *RPCError
			if errors.As(err, &rpc) && rpc.Data != nil && (rpc.Data.Category == sdk.CatAuth || rpc.Data.Category == sdk.CatValidation) {
				add("vm.destroy.idempotent", true, "config/auth error (expected without real credentials)")
			} else {
				add("vm.destroy.idempotent", false, err.Error())
			}
		} else if destroyRes.Destroyed {
			add("vm.destroy.idempotent", false, "returned Destroyed=true for non-existent VM (should be false)")
		} else {
			add("vm.destroy.idempotent", true, "returned Destroyed=false")
		}
	} else {
		add("vm.destroy.idempotent", true, "not declared in capabilities (skipped)")
	}

	return report, nil
}

func hasCap(caps []string, want string) bool {
	for _, c := range caps {
		if c == want {
			return true
		}
	}
	return false
}
