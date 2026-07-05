# SocTalk Launchpad — plugin system plan (for codex review)

## Product context

Launchpad is a Bubble Tea TUI (single Go binary) that automates the SocTalk MSSP pilot rollout for evaluators. It provisions the MSSP VM + N tenant VMs on the operator's chosen virtualization platform, joins them to a Tailscale tailnet, and installs SocTalk end-to-end. Idempotent, resumable, env-var configured, Docker-friendly.

Everything below is the *plugin* subsystem: how launchpad talks to per-platform VM providers (Hetzner, Proxmox, Docker, later AWS/GCP/Azure/ESXi).

## Non-goals

- No sandboxing (plugins run with caller's privileges).
- No plugin signing / provenance in v1.
- No dynamic download-from-registry install (`launchpad plugin install` deferred).
- No streaming multi-VM ops per plugin (v1 is one method in-flight per plugin subprocess).

## Transport: JSON-RPC 2.0 over stdio (line-delimited)

- stdin: launchpad → plugin
- stdout: plugin → launchpad (RPC results + notifications, JSON only)
- stderr: unstructured log stream (rendered as plugin log tab in TUI)
- Line-delimited JSON, one message per line
- Chosen over gRPC to avoid protobuf codegen barrier — plugins can be written in any language with a JSON parser + read/write line loop

## Handshake

**Phase 1 — plugin.hello (bidirectional):**
```json
{
  "protocol_version": "1",
  "plugin_name": "hetzner",
  "plugin_version": "0.3.1",
  "capabilities": ["vm.plan", "vm.create", "vm.wait_ready", "vm.destroy"],
  "schema": { ... JSON schema for this plugin's config ... }
}
```

**Phase 2 — plugin.initialize (launchpad → plugin):**
- Payload: plugin config (validated against schema) + run context (run id, log verbosity, dry-run flag)
- Plugin does credential probe and returns `ok` or `{error, hint}`
- Fail fast: 5 s handshake timeout, 30 s initialize timeout

## RPC surface (v1 — VM provider plugins only)

| Method | Direction | Purpose |
|---|---|---|
| `vm.plan` | LP → plugin | Dry-run: describe what will be created, validate creds |
| `vm.create` | LP → plugin | Provision VM. Blocking. Emits `progress` notifications. Returns `{vm_id, ipv4, ipv6, ssh_user}` |
| `vm.wait_ready` | LP → plugin | Wait until SSH accepts + cloud-init done |
| `vm.destroy` | LP → plugin | Reverse of create. Idempotent |
| `progress` | plugin → LP | Notification: `{step, percent, message}` |
| `log` | plugin → LP | Notification: `{level, msg, fields}` |

Cloud-init flows through `vm.create` params (`user_data` field). Plugins are dumb pass-through; SocTalk-specific config stays in launchpad core.

## Discovery

Plugin binary + manifest at:
```
$XDG_DATA_HOME/soctalk-launchpad/plugins/<name>/plugin[.exe]
~/.soctalk-launchpad/plugins/<name>/plugin[.exe]    ← macOS/Linux fallback
```

Manifest (`<name>/plugin.yaml`):
```yaml
name: hetzner
version: 0.3.1
protocol: "1"
executable: ./plugin
sha256: <sha of binary; verified before launch>
license: MIT
homepage: https://github.com/soctalk/launchpad-plugin-hetzner
```

v1: manual install (drop binary in dir). v2: `launchpad plugin install github.com/...`.

## Lifecycle

1. Launch — fresh subprocess per run (not persistent). Working dir = plugin dir. Env vars filtered per plugin's declared allow-list.
2. Handshake (5 s timeout).
3. Initialize (30 s timeout).
4. Method dispatch — one method in-flight per plugin subprocess.
5. Teardown — `shutdown` notification, 5 s grace, then SIGKILL.

## Error model

```json
{
  "code": "credentials.missing_env_var",
  "message": "Hetzner API token is empty",
  "hint": "Set HCLOUD_TOKEN or add to your launchpad config",
  "docs_url": "https://.../plugin-hetzner#credentials",
  "retryable": false
}
```

Namespaced string codes (owned by each plugin). `hint` → TUI error card. `retryable` → offer retry button.

## Security (v1)

- No sandbox. Plugin runs with caller's privileges (Terraform-style).
- **Env var filtering:** launchpad passes only env vars in the plugin's declared schema allow-list. Prevents cross-plugin secret leakage (Hetzner plugin can't see `AWS_SECRET_ACCESS_KEY`).
- Plugin binary checksum verification from `plugin.yaml` before spawn.
- Plugins can make network calls to anywhere (user directive: no restrictions).

## Repo structure

```
github.com/soctalk/launchpad                 ← core, TUI, state, orchestration
github.com/soctalk/launchpad-sdk-go          ← Go plugin SDK
github.com/soctalk/launchpad-sdk-py          ← Python plugin SDK
github.com/soctalk/launchpad-plugin-mock     ← reference/test plugin
github.com/soctalk/launchpad-plugin-hetzner  ← first-party
github.com/soctalk/launchpad-plugin-proxmox  ← first-party
github.com/soctalk/launchpad-plugin-docker   ← first-party (local dev/test)
```

SDKs are hand-rolled (per user directive: "simplest as long as we do not compromise scaling"). No Buf/protobuf. Just JSON-RPC transport + handshake + schema validation helpers.

## Testing

- `launchpad plugin verify <name>` — compliance suite: handshake, all methods with sample inputs, error paths, shutdown timing. Ships in launchpad core so third-party authors have a green-CI target.
- `launchpad-plugin-mock` — always-succeeds reference plugin, used for launchpad's own integration tests without real cloud creds.

## Delivery

- Each plugin: single static binary (Go) or wheel + entry point (Python).
- Distributed as GitHub Release assets on the plugin's repo.
- Cross-compile matrix: linux/amd64, linux/arm64, darwin/amd64, darwin/arm64, windows/amd64.

## Milestones

- **M1** (~2 wks equivalent, will compress this session): `launchpad-sdk-go` + `launchpad-plugin-mock` + `launchpad` core with plugin loader + `plugin verify` command.
- **M2** (~1 wk): `launchpad-plugin-hetzner` — real Hetzner Cloud API. `launchpad up --target hetzner` smoke.
- **M3** (~1 wk): `launchpad-plugin-proxmox` + `launchpad-plugin-docker`. Multi-target orchestration.
- **M4** (~1 wk): `launchpad-sdk-py` reference implementation + `launchpad plugin install` from GH releases.

## Codex — what I want you to check

1. **JSON-RPC over stdio vs alternatives** — is line-delimited JSON-RPC 2.0 the right pick, or should I look at NDJSON without RPC framing, or something else? For LSP context, this works; are there gotchas for a VM-provisioning plugin surface (long-running methods, progress notifications)?
2. **Handshake protocol** — do we need a `shutdown` method or is closing stdin sufficient? Any concerns about the two-phase (hello + initialize) split vs collapsing to one message?
3. **Timeout numbers** — 5 s handshake / 30 s init / per-method timeouts for `vm.create`. Are these sane or overtight? What should `vm.create` timeout be?
4. **Env-var filtering as security boundary** — is it actually meaningful given plugins can `os.environ` any variable the launchpad process has (Go's os.Setenv scope is process-wide)? Do I need a fork-with-clean-env approach?
5. **Error model** — namespaced strings for codes vs a well-defined enum. Is `retryable: bool` too coarse — should it be `retry_after_ms` or a category?
6. **Concurrency** — one method in-flight per plugin subprocess. Is that going to bite us when a launchpad run orchestrates 3 concurrent VM creates on the same plugin? Do we need N subprocesses or in-plugin concurrency?
7. **Discovery** — filesystem convention + plugin.yaml. Anything obviously wrong?
8. **The RPC method set for v1** — is `vm.plan / create / wait_ready / destroy` the right decomposition, or should I collapse `wait_ready` into `create`?

Constraints from the operator:
- Simplest possible SDK design that won't compromise scaling
- Plugins can do anything (no network sandbox)
- No signing
- Naming: `launchpad` (not soctalk-launchpad)

Reply with a punch list of concrete concerns + concrete fixes. Under 800 words.
