// launchpad-plugin-mock is a reference/test plugin. It always succeeds and
// never touches a network. Launchpad uses it in its own integration tests
// and third-party plugin authors can point `launchpad plugin verify` at it
// as a green-CI benchmark.
package main

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"os"
	"time"

	sdk "github.com/soctalk/launchpad-sdk-go"
)

const (
	name    = "mock"
	version = "0.1.0"
)

// In-memory registry of "provisioned" VMs, keyed by run_id + vm_key.
// Serialized by the SDK's one-in-flight-per-subprocess guarantee.
var registry = map[string]sdk.VMCreateResult{}

func regKey(runID, vmKey string) string { return runID + "/" + vmKey }

// deterministicIP fakes a stable IPv4 for a given (run_id, vm_key).
func deterministicIP(runID, vmKey string) string {
	h := sha1.Sum([]byte(regKey(runID, vmKey)))
	return fmt.Sprintf("10.%d.%d.%d", h[0]%254+1, h[1], h[2])
}

func main() {
	err := sdk.Serve(sdk.Plugin{
		Name:    name,
		Version: version,

		// Mock declares no allowed env vars: it needs nothing from the operator.
		// The ConfigSchema is intentionally permissive.
		ConfigSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"delay_ms": map[string]any{"type": "integer", "minimum": 0},
			},
			"additionalProperties": false,
		},

		Initialize: func(ctx context.Context, p sdk.InitializeParams) (sdk.InitializeResult, error) {
			return sdk.InitializeResult{Ready: true}, nil
		},

		Plan: func(ctx context.Context, p sdk.VMPlanParams, emit sdk.Emitter) (sdk.VMPlanResult, error) {
			emit.Progress("planning", 100, "mock plan")
			return sdk.VMPlanResult{
				Summary:              fmt.Sprintf("mock: %s in %s", p.Spec.SizeHint, p.Spec.Region),
				EstimatedCostUSD:     0,
				EstimatedDurationSec: 1,
			}, nil
		},

		Create: func(ctx context.Context, p sdk.VMCreateParams, emit sdk.Emitter) (sdk.VMCreateResult, error) {
			key := regKey(p.Spec.RunID, p.Spec.VMKey)
			if existing, ok := registry[key]; ok {
				emit.Log("info", "idempotent hit — returning existing VM", map[string]any{"vm_id": existing.VMID})
				return existing, nil
			}
			emit.Progress("create", 25, "allocating VM")
			time.Sleep(20 * time.Millisecond)
			emit.Progress("create", 75, "booting VM")
			time.Sleep(20 * time.Millisecond)
			id := "mock-vm-" + hex.EncodeToString(sha1FirstBytes(key, 4))
			res := sdk.VMCreateResult{
				VMID:    id,
				IPv4:    deterministicIP(p.Spec.RunID, p.Spec.VMKey),
				SSHUser: "ubuntu",
				SSHPort: 22,
				Metadata: map[string]string{
					"provider": "mock",
					"region":   p.Spec.Region,
				},
			}
			registry[key] = res
			emit.Progress("create", 100, "VM ready")
			return res, nil
		},

		WaitReady: func(ctx context.Context, p sdk.VMWaitReadyParams, emit sdk.Emitter) (sdk.VMWaitReadyResult, error) {
			emit.Progress("wait_ready", 100, "mock always-ready")
			return sdk.VMWaitReadyResult{Ready: true}, nil
		},

		Destroy: func(ctx context.Context, p sdk.VMDestroyParams, emit sdk.Emitter) (sdk.VMDestroyResult, error) {
			key := regKey(p.RunID, p.VMKey)
			if _, ok := registry[key]; !ok {
				return sdk.VMDestroyResult{Destroyed: false}, nil
			}
			delete(registry, key)
			return sdk.VMDestroyResult{Destroyed: true}, nil
		},

		Inspect: func(ctx context.Context, p sdk.VMInspectParams, emit sdk.Emitter) (sdk.VMInspectResult, error) {
			key := regKey(p.RunID, p.VMKey)
			existing, ok := registry[key]
			if !ok {
				return sdk.VMInspectResult{Exists: false}, nil
			}
			return sdk.VMInspectResult{
				Exists:   true,
				VMID:     existing.VMID,
				State:    "running",
				IPv4:     existing.IPv4,
				SSHUser:  existing.SSHUser,
				Metadata: existing.Metadata,
			}, nil
		},
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "mock plugin: ", err)
		os.Exit(1)
	}
}

func sha1FirstBytes(s string, n int) []byte {
	h := sha1.Sum([]byte(s))
	return h[:n]
}
