# launchpad

Automates the SocTalk MSSP-pilot rollout: provisions the MSSP + tenant VMs, joins them to a Tailscale tailnet, installs SocTalk, and reports done.

Runs anywhere the operator's laptop can (Mac, Linux, Windows), idempotent + resumable, plugin-based so it works on Hetzner, Proxmox, VMware ESXi, Docker (local dev), and anything else someone writes an adapter for.

## Quick start

```bash
# List discovered plugins.
launchpad plugin list

# Run a compliance suite against a plugin.
launchpad plugin verify hetzner

# Run a full pilot rollout (see docs/config.md for the config shape).
launchpad up --config pilot.yaml
```

## Architecture

- **Core** (`cmd/launchpad`, `internal/orchestrator`) — state machine that walks the pilot phases. Emits every state transition as a JSON event on an internal channel.
- **Plugins** — separate subprocesses that speak JSON-RPC 2.0 on stdio. VM provisioners live here (Hetzner, Proxmox, Docker, ESXi, …). Any language works.
- **TUI** (Bubble Tea, coming soon) — subscribes to the event channel, shows progress + gates + logs. `launchpad up` (default) uses it.
- **Headless mode** (`launchpad up --headless`) — emits events as line-delimited JSON on stdout, reads commands from stdin. Used for automated end-to-end testing from bash + `jq`.

## Plugin protocol

See `internal/pluginhost/` (Go core) and the [SDK README](../launchpad-sdk-go/README.md).

- Line-delimited JSON-RPC 2.0 on stdio.
- Plugin speaks first with a `plugin.hello` notification; launchpad then sends `plugin.initialize`.
- Requests: `vm.plan`, `vm.create`, `vm.wait_ready`, `vm.destroy`, `vm.inspect`, `plugin.shutdown`.
- Notifications: `progress` (with `op_id` + `vm_key` correlation), `log`.
- Clean child env (allow-listed pass-through), 5s graceful shutdown → SIGTERM → SIGKILL.

## Testing

The event stream is the test surface. Sample bash-driven assertion:

```bash
launchpad up --config e2e.yaml --state /tmp/s.json --headless --auto-resolve-gates \
  | tee events.jsonl | grep -q '"ev":"complete"'
jq -r 'select(.ev=="vm_ready") | .vm_key' events.jsonl | sort
```

That was verified end-to-end during initial development with the `mock` plugin (3 VMs, one manual gate, idempotent resume).

## Status

M1 (SDK + core + mock plugin + verify) — done.
M2 (Hetzner plugin) — plugin implemented and passes compliance; needs live-cluster smoke.
M3 (Proxmox + Docker plugins) — Docker fully working against a local Docker daemon; Proxmox scaffold speaks the API and passes compliance but needs live-cluster smoke.
M4 (Python SDK) — done, cross-language interop demonstrated (Python plugin passes Go launchpad's compliance suite).

Bubble Tea TUI + `launchpad drive` subcommand for interactive testing are the next chunk.
