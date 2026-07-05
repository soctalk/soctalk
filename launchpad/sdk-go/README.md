# launchpad-sdk-go

Go SDK for writing SocTalk Launchpad plugins.

## What is a Launchpad plugin?

A subprocess Launchpad spawns to provision a VM on a specific target (Hetzner, Proxmox, Docker, ESXi, …). Plugins speak **line-delimited JSON-RPC 2.0** on stdin/stdout. This SDK hides the wire protocol behind a normal Go interface.

## Quick start

```go
package main

import (
    "context"
    "fmt"
    "os"

    sdk "github.com/soctalk/launchpad-sdk-go"
)

func main() {
    err := sdk.Serve(sdk.Plugin{
        Name:    "myprovider",
        Version: "0.1.0",

        AllowedEnvVars: []string{"MYPROVIDER_TOKEN"},
        ConfigSchema: map[string]any{
            "type": "object",
            "properties": map[string]any{
                "region": map[string]any{"type": "string"},
            },
        },

        Initialize: func(ctx context.Context, p sdk.InitializeParams) (sdk.InitializeResult, error) {
            if os.Getenv("MYPROVIDER_TOKEN") == "" {
                return sdk.InitializeResult{}, sdk.Errf(sdk.CatAuth,
                    "myprovider.credentials.missing",
                    "MYPROVIDER_TOKEN is not set")
            }
            return sdk.InitializeResult{Ready: true}, nil
        },

        Create: func(ctx context.Context, p sdk.VMCreateParams, emit sdk.Emitter) (sdk.VMCreateResult, error) {
            emit.Progress("provisioning", 10, "requesting VM")
            // ... call provider API ...
            emit.Progress("provisioning", 90, "VM is booting")
            return sdk.VMCreateResult{
                VMID:    "vm-abc123",
                IPv4:    "203.0.113.42",
                SSHUser: "ubuntu",
            }, nil
        },

        Destroy: func(ctx context.Context, p sdk.VMDestroyParams, emit sdk.Emitter) (sdk.VMDestroyResult, error) {
            // ... provider destroy call ...
            return sdk.VMDestroyResult{Destroyed: true}, nil
        },
    })
    if err != nil {
        fmt.Fprintln(os.Stderr, err)
        os.Exit(1)
    }
}
```

## Protocol at a glance

```
1. Plugin starts. SDK immediately emits plugin.hello notification.
2. Launchpad sends plugin.initialize request; SDK dispatches to your Initialize handler.
3. Launchpad sends vm.plan / vm.create / vm.wait_ready / vm.destroy / vm.inspect requests.
4. Launchpad sends plugin.shutdown; SDK calls your Shutdown handler (if provided), replies, and Serve returns.
```

## Rules for plugins

- **stdout is protocol only.** Any non-JSON write breaks the parent. Use `emit.Log(...)` for structured messages the operator should see; use stderr sparingly for developer-only unstructured output.
- **Max message size is 4 MiB.** Larger messages fail loudly.
- **One request in-flight per subprocess.** Launchpad may spawn N subprocesses for concurrency; plugins do not need to be internally concurrent.
- **Idempotency is your responsibility.** Every mutating call carries `run_id` + `vm_key`. Reuse existing resources when the same key is seen again.
- **Return typed errors via `sdk.Errf(...)`** so launchpad can classify + surface hints in the TUI.

## Testing your plugin

```bash
# Launch plugin manually + feed it a JSON-RPC session.
echo '{"jsonrpc":"2.0","id":1,"method":"plugin.initialize","params":{"run_id":"x","config":{},"log_level":"info"}}' | ./plugin
```

Or use the launchpad's built-in compliance harness:

```bash
launchpad plugin verify /path/to/plugin
```

## Status

v1 of the protocol. See [../launchpad-workspace/plugin-plan.md](../launchpad-workspace/plugin-plan.md) for the design doc.
