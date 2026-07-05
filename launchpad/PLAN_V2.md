# Launchpad V2 — End-to-End Implementation Plan

> Scope: push launchpad from CLI-only tool to full web-UI-driven setup orchestrator.
> This plan supersedes `plan.md` (which described the plugin subsystem — now implemented).
> Companion design doc: `/tmp/launchpad-ui-design.md` (submitted to codex for review; findings folded in below).
> Second review pass (in-session, verified against code) folded in: process model, conditions protocol, secrets boundary, endpoint gaps.

## Table of contents

- [Executive summary](#executive-summary)
- [Target architecture at MVP](#target-architecture-at-mvp)
- [Reference implementations](#reference-implementations)
- [Phase 0 — Clear the deck](#phase-0--clear-the-deck-1-day)
- [Phase 1 — Engine foundations](#phase-1--engine-foundations-57-days)
- [Phase 2 — Gate protocol v2](#phase-2--gate-protocol-v2-35-days)
- [Phase 3 — HTTP + WS server](#phase-3--http--ws-server-35-days)
- [Phase 4 — Frontend scaffolding + shared plumbing](#phase-4--frontend-scaffolding--shared-plumbing-23-days)
- [Phase 5 — Core screens](#phase-5--core-screens-57-days)
- [Phase 6 — Polish + post-MVP](#phase-6--polish--post-mvp-ongoing)
- [Cross-cutting non-negotiables](#cross-cutting-non-negotiables)
- [Test strategy](#test-strategy)
- [Codex review gates](#codex-review-gates)
- [Risks and mitigations](#risks-and-mitigations)
- [Timeline](#timeline)
- [Out of scope for MVP](#out-of-scope-for-mvp-explicit)

## Executive summary

Six phases, MVP in ~4–6 calendar weeks of focused work. The engine (runs, events, gates) becomes first-class before any UI work — per codex's headline finding on the design doc. The UI adopts SvelteKit + Skeleton (matching SocTalk), embedded in the Go binary (matching Semaphore's shipping model), with UX patterns lifted from Rancher (list/detail/edit universality, structured Conditions view, form/YAML toggle, Run Explorer). Everything reuses the existing Go orchestrator + plugin subprocess model — plugins never learn the UI exists.

Four codex reviews gate the phases:

1. End of Phase 1 — engine foundations, before SDK touch.
2. End of Phase 2 — protocol v2, before HTTP investment.
3. End of Phase 3 — API freeze, before UI investment.
4. End of Phase 5 — full E2E, before declaring MVP.

## Target architecture at MVP

```
launchpad binary  (~35 MB, single artifact, no runtime deps)
cli/
├── cmd/launchpad/main.go   (existing single entrypoint; verbs dispatch below)
└── internal
    ├── cli/               (existing verb handlers: up.go, down.go, tui.go, headless.go
    │                       + NEW: replay.go, cancel.go, env.go, ui.go — same pattern)
    ├── orchestrator/      (existing; config.go stays here, gains Compose — there is
    │                       no separate internal/config package today and we do not
    │                       extract one in this plan)
    ├── pluginhost/        (existing, extended for plugin-originated RPC)
    ├── envstore/          NEW: env.json / scenarios / runs on disk
    ├── runmanager/        NEW: per-run lifecycle + concurrency
    ├── eventjournal/      NEW: append-only events.jsonl + broadcaster
    ├── gatebus/           NEW: structured gate prompt/answer bus
    ├── conditions/        NEW: derive per-VM condition tables from condition.update
    │                       events (see Phase 2a — conditions are protocol-level, not
    │                       regex-scraped from log messages)
    ├── secretsref/        NEW: split public config from secret material
    └── httpapi/           NEW: REST + WS + static-embed + auth token
frontend/               NEW: SvelteKit SPA, //go:embed'd
├── src/routes/         (SPA routes: /, /runs/[id], /hosts, /scenarios, /env)
├── src/lib/            (stores, WS client, shared components)
└── build/              (adapter-static output — copied to internal/httpapi/frontend_build)
plugins/                (existing: qemu, vmware, ... + NEW: mock — CI-only target that
                         simulates provisioning with configurable timings/failures)
```

### Process model (single-writer for MVP)

RunManager, gatebus, and the event broadcaster are in-process objects, so a run is
**owned by the process that started it**. Rules:

- A run started by `launchpad ui` is fully manageable from the UI (cancel, gates, down).
- A run started by CLI `up` is visible to a concurrently-running UI **read-only**
  (the UI tails `runs/<id>/events.jsonl` from disk) — the UI cannot answer its gates
  or cancel it, and says so in the run header ("owned by CLI process, read-only").
- Ownership is recorded in `runs/<id>/.lock` (flock + owner pid + mode); a second
  process sees the lock and opens read-only.
- **Phase 6 upgrade path**: server-delegating CLI — `up` checks for a live server
  (`~/.launchpad/server.json` pidfile+port) and, if present, becomes a thin HTTP
  client of it, streaming events to the terminal. That restores full parity without
  changing the HTTP API.

## Reference implementations

Studied in-depth; each contributes specific patterns:

- **[Semaphore UI](https://github.com/semaphoreui/semaphore)** — single Go binary + embedded SPA + WS event fan-out. Steal: shipping model, WS keepalive constants (20s/108s/120s/512B/256), session-aware socket wrapper, auth middleware chain for both REST and WS.
- **[Rancher](https://github.com/rancher/rancher)** — 10 years of hard-earned UI/UX patterns for infra provisioning. Steal: universal list/detail/edit pattern, structured Conditions view, form-and-YAML toggle (with subset discipline), Run Explorer scoped nav, consistent action affordances.
- **[Ludus](https://github.com/badsectorlabs/ludus)** — closest domain match (cyber-range VM lab orchestrator). Steal: config-first + UI-companion posture, vocabulary (ranges, snapshots, testing mode).
- **[Woodpecker CI](https://github.com/woodpecker-ci/woodpecker)** — pipeline visualization. Steal: phase-timeline visual language, live log streaming UX.

Explicit anti-patterns from these tools:

- Semaphore's `CheckOrigin: return true` → we ship strict Origin allowlist from MVP.
- Rancher's "stuck in Provisioning without why" → every wait state must have a specific, actionable message.
- Rancher's form/YAML drift bugs (issues #15396, #6582) → form is a strict subset of YAML by design; round-trip tested.

## Phase 0 — Clear the deck (~1 day)

**Goal**: two consecutive hybrid pilots succeed without manual tailscale intervention.

- **[Task #471]** vmware + qemu plugins verify tailscale device liveness on resume; if missing/offline, SSH via LAN IP and re-run `tailscale logout && up --auth-key=<fresh>`.
- **qemu idempotency bug**: plugin re-provisions even when `pidAliveOverSSH` confirms the
  VM process is alive (observed in the hybrid pilot sessions; worked around manually).
  Diagnose and fix — the Phase 0 exit criterion will trip on this otherwise.
- Add integration test: two runs back-to-back with the same run_id, no manual touch.

**Exit criteria**: `launchpad up --config /tmp/lp-hybrid-pilot.yaml && launchpad down && launchpad up ...` clean.

## Phase 1 — Engine foundations (5–7 days)

Backend-only. This is codex's "critical prerequisite" work — runs, events, and gates become first-class engine concepts.

### 1a. Event journal (`internal/eventjournal`)

- Types: `Event{Seq int64; Time; Kind; VMKey; Fields}`, `Journal` (append-only, per-run).
- Files: `runs/<id>/events.jsonl`, one JSON envelope per line, monotonic `seq`.
- API:
  ```go
  type Journal interface {
      Append(ev Event) error
      Subscribe(sinceSeq int64) (<-chan Event, func(), error)  // replay-then-live, no drops
      Close() error
  }
  ```
- Bounded broadcast channels per subscriber; **backpressure counters, never block the orchestrator**.
- Unit tests: seq monotonic under concurrency; late-joiner replay yields identical prefix; slow subscriber gets counter, fast subscriber unaffected.

### 1b. RunManager (`internal/runmanager`)

- Per-run: `context.Context`, `CancelFunc`, `sync.Mutex`, `status`, `Journal`, `dirLock`.
- States: `pending | running | cancelling | tearing_down | complete | failed`.
- `Start(cfg Config) → (run_id, error)`, `Cancel(run_id)`, `TearDown(run_id)`, `Get(run_id) → RunSnapshot`.
- **Resume vs replay** (both must be first-class; resume is the recovery path we
  actually use today):
  - `Start` with an existing run_id whose status is `failed` = **resume**: reuses the
    state file, skips already-provisioned VMs (existing idempotent behavior), appends
    to the same `events.jsonl`.
  - `Replay(run_id) → (new_run_id, error)` = **new run** from the persisted
    `config.yaml` of an old one; fresh state, fresh journal.
- Directory lock (`flock` on `runs/<id>/.lock`, records owner pid + mode) — enforces
  the single-writer process model above; a second process opens read-only.
- Max-concurrency cap; queue overflow returns 409.
- Actually wires `CmdCancel` (today ignored at `orchestrator.go:288`) into a real cancel path.

### 1c. envstore (`internal/envstore`)

- Directory: `~/.launchpad/{env.json, scenarios/*.yaml, runs/<id>/}`.
- Atomic writes: tmp file + `os.Rename`, `0600` on secret files.
- File locks per file via `flock`.
- Types:
  ```go
  type Env struct {
      Hosts    map[string]HostProfile
      Tailnets map[string]TailnetRef      // API-key-ref, not the key itself
      LLM      map[string]LLMKeyRef
  }
  type HostProfile struct {
      Kind        string  // qemu | vmware
      SSHEndpoint string  // for qemu
      ESXiURL     string  // for vmware
      Creds       CredRef // secret reference, not value
  }
  ```
- API: `Load()`, `SaveHost(name, HostProfile)`, `ListHosts()`, `RemoveHost(name)`, `ResolveSecret(CredRef) → string`.
- CLI: `launchpad env add-host`, `list-hosts`, `remove-host` (parity with future UI).

### 1d. Secrets split (`internal/secretsref`)

- `SecretRef{Store, Key}` — `Store` is `env` or `keychain` (macOS keychain optional).
- Public `runs/<id>/config.yaml` contains `SecretRef` values, not raw secrets.
- `Resolve(SecretRef, envstore) → string` at run time only.
- **Grep test**: after any run, `grep -rE '(sk-|tskey-)' runs/<id>/` returns empty. Enforced in CI.

### 1e. Target instance = target + profile

- Manifests stay keyed by **target** (they describe the plugin binary). What must be
  keyed by `TargetInstance = {Target, Profile}` is the **client map + Initialize
  config**: `o.clients` in `orchestrator.go` (today `map[string]*pluginhost.Client`
  with a "first plugin_config wins" rule, see comment at ~orchestrator.go:186) becomes
  `map[TargetInstance]*pluginhost.Client`, one subprocess per instance, each
  initialized with its own profile's config.
- `Compose(env, scenario, overrides) → Config` produces `[]VMSpec` where each spec carries `TargetInstance`.
- `Compose` lives in `internal/orchestrator` alongside the existing `config.go`
  (no package extraction — see architecture tree note).
- Unblocks: two ESXi hosts, MSSP + tenant sharing target but different creds.

### 1f. `Config` resolution + persisted resolved config

- Extend `State` with `ResolvedConfig Config` written once at `runmanager.Start`.
- `runs/<id>/config.yaml` (public, SecretRef-only) is the replay source.
- `launchpad replay <run_id>` reads `config.yaml`, resolves secrets from current envstore, kicks off a new run.

### Milestone / codex review 1

- `launchpad env add-host …`, `launchpad up --scenario=hybrid-pilot`, `launchpad cancel <id>`, `launchpad replay <id>` all work.
- `events.jsonl` complete and monotonic across the hybrid pilot; codex review sanity-checks the engine before SDK touch.

## Phase 2 — Gate protocol v2 (3–5 days)

SDK-touching. High blast radius; get it right in one pass.

### 2a. Protocol v2 spec

- `gate.request` becomes a **plugin-originated JSON-RPC request** with `id`; human answer is the response.
- Payload:
  ```json
  {
    "id": "…", "title": "Tailscale ACL update required",
    "prompt": "Paste the following ACL fragment…",
    "input_schema": {
      "kind": "text|secret|boolean|multiline|choice",
      "choices": ["…"],
      "default": "…",
      "required": true,
      "pattern": "regex"
    },
    "timeout_seconds": 600,
    "run_id": "…", "vm_key": "…", "phase": "…"
  }
  ```
- `hello` handshake carries `protocol_version`; host negotiates down for old plugins.
- **`condition.update` notification** (new in v2, same bump): `{vm_key, condition,
  status: True|False|Provisioning|Unknown, message}`. This is the data source for the
  Conditions table (Phase 3c endpoint, Phase 5e UI) — without it, conditions would
  have to be regex-scraped from free-text progress messages, which is exactly the
  fragility the pattern exists to avoid. Plugins emit it at transitions they already
  know (`vm_created`, `tailscale_online`, `cloud_init`); the install phase emits the
  SocTalk-level ones (`k3s_ready`, `soctalk_agent`, `tenant_chart`, `wazuh_ready`).
  `internal/conditions` folds these events into the per-VM table.
- **Plugin-side full-duplex is in scope, not just host-side.** `gate.request` is sent
  while the plugin is still servicing `vm.create` — which breaks v1's "one method
  in-flight per subprocess" assumption on the *plugin* side too. SDK v2 must give
  plugins a mutex-guarded stdout writer and a recv path that can deliver the gate
  response while the main handler goroutine is blocked waiting for it.

### 2b. pluginhost.Client — full-duplex

- Today `pluginhost/client.go:160` drops plugin-originated requests with both `id` and `method`. Fix: route them to a dispatcher.
- Register `gate.request` handler that hands off to `gatebus.Open` and returns the eventual answer as the JSON-RPC response.
- Parking a goroutine per gate is fine per codex.

### 2c. gatebus (`internal/gatebus`)

- Per-run open-gates map keyed by `gate_id`.
- `Open(runID, Gate) → chan Answer` (blocks the plugin RPC).
- `Resolve(runID, gate_id, Answer) → error` (routes back).
- `Cancel(runID, gate_id, reason)` (on run cancel/timeout, fills default or errors).
- Timeout default-fill: `timeout_seconds` elapses → fill `default` if `required=false && default != nil`, else fail run.
- Emits `EvGateOpen{gid, schema, prompt, default}`, `EvGateResolved{gid, source, value_redacted}` into eventjournal.

### 2d. CLI answer paths

- `--auto-resolve-gates=defaults` (current bool behavior; fills default for each gate).
- `--gate-answers=file.yaml` (map `gate_id → value`).
- Interactive TTY mode prints the prompt and reads stdin.

### 2e. Migrate existing gates

- Current `tailscale_acl_pasted` (auto-resolved boolean) becomes a structured `choice` or `boolean` gate emitted from the plugin (or orchestrator on the plugin's behalf).
- Update qemu + vmware plugins accordingly.

### 2f. SDK bump + compliance tests

- `soctalk-launchpad-sdk-go` version bump to v2 (full-duplex plugin runtime: concurrent
  stdout writes, background recv dispatch — see 2a).
- Compliance tests: (1) plugin emits `gate.request` mid-`vm.create`, host answers,
  plugin receives via response while the create call is still open; (2) plugin emits
  `condition.update`, host folds it into the conditions table.
- **Mock plugin** (`plugins/mock`) built against SDK v2: simulates provisioning with
  configurable step timings, gate prompts, and failure injection. This is what CI —
  including the Phase 5 Playwright suite — runs against; no real hypervisor needed.
- Python SDK stays on v1 for one release (protocol negotiation covers it).

### Milestone / codex review 2

- Mock plugin gate flow tested end-to-end.
- `--auto-resolve-gates=defaults` still passes the hybrid pilot.
- Codex reviews protocol before HTTP investment.

## Phase 3 — HTTP + WS server (3–5 days)

Still no UI. Everything the UI will need, testable via `curl` and `websocat`.

### 3a. httpapi package layout

```
internal/httpapi/
├── server.go        // NewServer, ListenAndServe, token gen
├── middleware.go    // auth, origin, panic recovery, request id
├── rest.go          // REST handlers wired to envstore + runmanager
├── ws.go            // /api/ws handler + subscribe protocol
├── static.go        // //go:embed frontend_build; SPA fallback
└── errors.go        // RFC-7807-style JSON error schema
```

### 3b. Auth + Origin

- Per-server random token generated at start (32-byte hex).
- URL printed at startup: `http://127.0.0.1:PORT/?t=TOKEN`.
- Middleware: require `?t=TOKEN` or `X-Launchpad-Token` header on every REST + WS request.
- The SPA moves the token from the URL to sessionStorage on first load and strips the
  query param (`history.replaceState`) — keeps the token out of browser history.
- **Origin header allowlist**: `http://127.0.0.1:PORT`, `http://localhost:PORT`. Reject everything else — closes the vulnerability codex flagged (and that Semaphore has today).

### 3c. REST endpoints

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/env` | envstore snapshot, presence-only for secrets |
| PUT | `/api/env/hosts/:name` | add/edit host profile |
| DELETE | `/api/env/hosts/:name` | remove |
| POST | `/api/env/hosts/:name:reachability` | probe (SSH ping / API ping) |
| GET | `/api/scenarios` | list |
| POST | `/api/scenarios` | create |
| GET | `/api/scenarios/:name` | detail |
| PUT | `/api/scenarios/:name` | update |
| GET | `/api/runs` | list with status |
| POST | `/api/runs` | start; `Idempotency-Key` header; returns `{run_id}` |
| GET | `/api/runs/:id` | detail (resolved config + state + conditions) |
| GET | `/api/runs/:id/conditions` | Rancher-style per-VM conditions table |
| GET | `/api/runs/:id/events` | server-side history (paged, `?since_seq=N`) |
| POST | `/api/runs/:id/cancel` | wire to runmanager.Cancel |
| POST | `/api/runs/:id/down` | wire to runmanager.TearDown |
| POST | `/api/runs/:id/replay` | new run from this run's persisted config; returns `{run_id}` |
| DELETE | `/api/runs/:id` | delete run record (rejected unless `complete`/`failed` and torn down) |
| GET | `/api/runs/:id/credentials` | **run-generated** credentials only (see secrets boundary) |
| POST | `/api/runs/:id/vms/:key/actions/:action` | quick actions; MVP set: `attack-sim` (wraps `/opt/scripts/run-attack.sh` on the VM) |
| GET | `/api/runs/:id/gates` | open gates |
| POST | `/api/runs/:id/gates/:gid` | answer |

- JSON error schema:
  ```json
  {"error": {"code": "gate_timeout", "message": "…", "detail": {…}}}
  ```
- **Secrets boundary** (resolves the presence-only vs Access-tab tension):
  - *User-supplied* secrets (tailscale API key, LLM keys, host creds): presence-only,
    **no read-back endpoint ever**.
  - *Run-generated* credentials (MSSP admin password minted for this run): retrievable
    via `GET /api/runs/:id/credentials` — that's what the Access tab's reveal toggle
    calls. They are demo credentials scoped to VMs this tool created.
  - Gate answers with `kind=secret` are **not persisted** (journal records
    `value_redacted` only) — consequence: replaying a run with secret gates re-prompts.
    Accepted trade-off.
- The `Tail logs` quick action is **dropped from MVP** (needs a streaming SSH-exec
  endpoint; defer to Phase 6 alongside debug bundle).

### 3d. WS `/api/ws` protocol

- Client subscribes: `{"subscribe": {"run_id": "…", "since_seq": 0}}`.
- Server replays from `events.jsonl` starting at `since_seq`, then switches to live tail without gaps.
- Message envelope: `{"run_id": "…", "seq": N, "ev": "vm_progress", "…": …}`.
- Client can send `{"unsubscribe": {"run_id": "…"}}`.
- Multi-run subscription supported (top nav needs all-runs summary).
- Keepalive: 20s write timeout / 108s ping / 120s pong wait (steal Semaphore's tested constants).

### 3e. `cmd/ui`

- Flags: `--port` (0 = random), `--no-open` (skip browser), `--dev` (skip static handler, expect Vite on 5173).
- Binds `127.0.0.1:PORT`. Prints URL with token. Optionally `open <url>`.

### 3f. Idempotency + concurrent control

- `POST /api/runs` accepts `Idempotency-Key` header; RunManager rejects duplicates within the same key.
- `POST /api/runs/:id/cancel` is idempotent (returns 200 whether already cancelled or not).

### Milestone / codex review 3

- Full engine drivable from HTTP + WS with no UI.
- API-level test suite (Go) exercises hybrid pilot via HTTP.
- Codex reviews the API surface before UI investment.

## Phase 4 — Frontend scaffolding + shared plumbing (2–3 days)

No screens yet. Build the plumbing so screens are trivial to add.

### 4a. Scaffolding

- `frontend/` with pnpm, SvelteKit 2, Svelte 4, Vite 5, TS, Tailwind 3, Skeleton UI, adapter-static, `@sveltejs/vite-plugin-svelte`.
- `svelte.config.js`: adapter-static, `fallback: 'index.html'`.
- `+layout.ts`: `prerender = true; ssr = false`.
- Path aliases matching SocTalk (`$lib`, `$components`, `$stores`, `$api`).

### 4b. Design system inheritance

- Copy `tailwind.config.ts` + Skeleton theme from SocTalk `frontend/` (level-a reuse — no shared package yet).
- Import Skeleton primitives directly.

### 4c. Svelte stores

```
src/lib/stores/
├── auth.ts        // token from URL, session state
├── env.ts         // hosts, tailnets, key presence
├── scenarios.ts   // list + current
├── runs.ts        // list + current
├── events.ts      // per-run event stream, seq cursor
├── conditions.ts  // per-VM derived condition table
└── gates.ts       // open gates per run
```

### 4d. WS client (translate Semaphore's `Socket.js` pattern)

- `src/lib/ws.ts`:
  - Session-aware lifecycle (drops WS on logout).
  - Auto-reconnect with 2s backoff.
  - Single dispatcher fans messages to per-run listeners.
  - Subscribes with `?since_seq=` cursor from `events.ts` store so refresh replays cleanly.
- Component API: `useRunEvents(runId, { fromSeq })` → readable store of events.

### 4e. Layout shell

- Top bar: launchpad wordmark, connection dot (WS status), settings gear.
- Left nav (Rancher-style, 5 entries max): **Runs · Hosts · Scenarios · Env · Settings**.
- Skeleton `AppShell` primitive.

### 4f. Shared components

- `StatusPill.svelte` — pending/running/cancelling/complete/failed color scheme.
- `ConditionRow.svelte` — Rancher-style `Status | Message | LastUpdated` row.
- `ResourceList.svelte` — universal list-view frame (primary action button top-right, per-row context menu, search + filter).
- `ResourceDetailTabs.svelte` — tabbed detail-view frame.
- `FormYamlToggle.svelte` — Rancher pattern: form is a subset of YAML; toggle shows warning if YAML has fields form can't render.
- `GateModal.svelte` — renders inputs from `input_schema` (text/secret/boolean/multiline/choice).
- `EventFeed.svelte` — filterable, autoscrolling, ANSI-colored (use `ansi_up`).
- `VMCard.svelte` — Rancher-inspired VM summary card with per-condition rollup.

### 4g. `//go:embed` integration

- Makefile: `pnpm build` → `frontend/build/` → `cp -R` to `cli/internal/httpapi/frontend_build/` → `go build`.
- Dev mode: `pnpm dev` on 5173 with Vite proxy to `http://localhost:8080/api` (both REST + WS).

### 4h. Playwright bootstrap

- `frontend/tests/` with `@playwright/test`.
- First test: token in URL loads app, connection dot goes green, layout shell renders.

### Milestone

- Dev loop works: touch Svelte code → HMR. Touch Go code → `go run` picks up.
- WS live-connects; empty screens with correct nav; Playwright smoke passes.

## Phase 5 — Core screens (5–7 days)

Rancher patterns applied throughout. Each screen has a Playwright test.

### 5a. Runs list (`/`)

- Scenario card grid at top (`Local demo`, `Hybrid pilot`, `Cloud PoC`, `From YAML`, `+ New`).
- Recent-runs `ResourceList` below with status pill + elapsed + phase + primary action `New Run`.
- Row context menu: `Open Explorer` (default), `Cancel` (if running), `Down`, `Replay`, `Delete`.

### 5b. Scenario launch modal

- 3 questions in a compact form: MSSP host, tenant host, tenant count.
- Preview ribbon below (one horizontal line: resolved computed config summary).
- Buttons: `Launch`, `Copy as CLI`, `Show YAML`.
- `Launch` POSTs `/api/runs` with `Idempotency-Key`, navigates to `/runs/[id]`.

### 5c. Run Explorer shell (`/runs/[id]`)

- Top bar: run_id, elapsed timer, phase pill, `Cancel` + `Down` + `Debug bundle` buttons.
- Left side nav (scoped to this run, Rancher-style): **Overview · VMs · Events · Gates · Config · Access**.
- URL is stable; hard-refresh replays events from persisted `events.jsonl` via WS `since_seq`.

### 5d. Overview tab

- Top-line status: phase + one-sentence current message.
- Phase timeline: `planning → provisioning → installing → complete` with animation as phases fire.
- VM roll-up grid: one small card per VM with status + condition summary.

### 5e. VMs tab + VM detail

- List of `VMCard`s (Rancher list pattern).
- Click a card → VM detail: **Conditions table** (Rancher pattern), Overview, per-VM log filter.
- Conditions come from `internal/conditions` folding protocol-v2 `condition.update`
  events (Phase 2a) — served at `/api/runs/:id/conditions`, streamed via WS updates.
  Never regex-derived from log text.
- Example Conditions view:

```
lp-tenant-acme (VMware)              [ Provisioning ]  15m elapsed

Conditions
  vm_created         True         OVA imported (id=6)              14m ago
  tailscale_online   True         100.99.6.3 checked in            10m ago
  cloud_init         True         finished 46s                      9m ago
  k3s_ready          True         v1.36.2+k3s1                      6m ago
  soctalk_agent      True         registered (installation_id=…)    5m ago
  tenant_chart       Provisioning installing soctalk-tenant         now
  wazuh_ready        Unknown      waiting on tenant_chart            —
```

### 5f. Events tab

- `EventFeed` with filters: by vm_key, by level, search text.
- Autoscroll toggle. Timestamp column. ANSI colorized.
- Backed by `/api/runs/:id/events?since_seq=…` for initial load, WS for live tail.

### 5g. Gates tab + global GateModal

- Gates tab lists open + resolved gates for this run.
- **Global `GateModal`**: pops up as soon as `EvGateOpen` fires, regardless of which tab is active. Renders input by `input_schema`. Submits to `POST /api/runs/:id/gates/:gid`.
- Countdown timer if `timeout_seconds` set; shows what the default is.

### 5h. Config tab

- Resolved config YAML displayed read-only during run; editable when `status ∈ {complete, failed}` for `Replay with edits` flow.
- Form/YAML toggle (with the subset discipline).
- `Copy as CLI` button emits equivalent `launchpad up --scenario=… --…`.

### 5i. Access tab (money shot)

- Big card per VM: URL (clickable, copy-to-clipboard), credentials (masked; reveal
  toggle calls `GET /api/runs/:id/credentials` — run-generated creds only, per the
  secrets boundary), SSH one-liner, quick actions (`Open in browser`,
  `Run attack simulator` via the actions endpoint). `Tail logs` deferred to Phase 6.
- Bottom: `Save as scenario` (persists this concrete config to `~/.launchpad/scenarios/`), `Tear down`.

### 5j. Hosts screen (`/hosts`)

- `ResourceList` of host profiles.
- Add/Edit form. Reachability probe button (calls `POST /api/env/hosts/:name:reachability`).
- Row context menu: `Edit`, `Duplicate`, `Runs using this host`, `Remove`.

### 5k. Scenarios screen (`/scenarios`)

- `ResourceList` of presets.
- Detail view: Form/YAML toggle. Form is a subset by design.
- Row context menu: `Launch`, `Edit`, `Duplicate`, `Delete`.

### 5l. Env screen (`/env`)

- Tailnet API key: presence-only display, `Rotate` action.
- LLM key(s): presence-only, per-provider.
- Global SSH identity: presence-only.

### 5m. Playwright suite

Runs against the **mock target plugin** (Phase 2f) so the full suite works in CI with
no hypervisor; the real hybrid pilot is a manual/nightly job on the NUC+ESXi rig.

- E2E happy path: launch mock scenario → run completes → Access tab shows URL.
- Gate resolution: mock plugin opens a gate mid-run, user submits, run continues.
- Cancel mid-run: click Cancel during provisioning, verify RunManager honors it.
- Failure injection: mock plugin fails a VM; Conditions table shows the failed
  condition with a specific message (non-negotiable #5 regression check).
- Add host: from empty env, add host profile, launch scenario, verify it's used.
- Refresh mid-run: hard-refresh the tab, verify events replay via `since_seq`.
- Read-only mode: run started via CLI, UI shows "owned by CLI process" and disables
  cancel/gate controls (process-model check).

### Milestone / codex review 4

- Full hybrid pilot demoable through the browser without touching the CLI.
- Playwright green.
- Codex reviews the full E2E before declaring MVP.

## Phase 6 — Polish + post-MVP (ongoing)

Deliberately deferred out of MVP; slot in as user demand justifies.

- **Command palette (⌘K)** — "Launch hybrid pilot", "Open latest run", "Tear down current run", "Add host".
- **Debug bundle export** — `POST /api/runs/:id/debug-bundle` returns tar of `config.yaml + events.jsonl + gates/ + plugin manifests`.
- **`Tail logs` quick action** — streaming SSH-exec endpoint (deferred from Phase 5i).
- **Server-delegating CLI** — `up` detects a running `launchpad ui` server and delegates over HTTP, restoring full CLI↔UI parity for gates/cancel (see Process model).
- **Env editing UI polish** — currently form-only; add per-provider wizards.
- **Multi-user auth** — beyond loopback: OIDC via the same middleware chain.
- **Electron wrapper** — same SPA + Playwright unchanged.
- **Plugin-contributed UI** — Rancher extension pattern; per-plugin Svelte components loaded dynamically. Preparation: plugin-specific fields already isolated in per-target components since Phase 4.
- **Docs walkthroughs** — screenshots captured via the pipeline that lives *outside* the docs repo.

## Cross-cutting non-negotiables

Baked into every phase, enforced by tests:

1. **User-supplied secrets never appear in `config.yaml`, events, logs, or API bodies** — presence-only, no read-back. Run-*generated* credentials are the one scoped exception (`GET /api/runs/:id/credentials`, see Phase 3c secrets boundary). Grep test in CI: `grep -rE '(sk-|tskey-auth-|password:.*[A-Za-z0-9]{8,})' ~/.launchpad/runs/` returns empty.
2. **Plugin protocol version captured per run** in `runs/<id>/manifest.json`.
3. **CLI ↔ UI env parity** guarded by envstore file locks; both write through the same package.
4. **`data-testid` on every element the UI exposes** — enforced in code review; Playwright selectors never touch class names.
5. **Every waiting state has a specific human-readable message.** Rancher's #1 failure mode; avoid it from day 1.
6. **Origin allowlist strict from MVP** — no `CheckOrigin: return true` (Semaphore's mistake).
7. **Bounded broadcast channels** — event journal never blocks the orchestrator; slow subscribers get a counter, not backpressure.
8. **Form is a subset of YAML.** Never let them drift; test round-trip both directions.

## Test strategy

| Layer | Tools | What it proves |
|---|---|---|
| Unit | Go `testing` | envstore round-trip, Compose correctness, gatebus concurrency, event journal seq monotonicity, secret redaction |
| Integration (Go) | `testing` + mock plugin subprocess | Full run through orchestrator with gates, cancel, replay |
| HTTP API | Go `httptest` | REST shape stability, WS replay-then-live, idempotency, origin/token rejection |
| E2E (UI) | Playwright vs **mock target plugin** (CI, no hypervisor) | Happy path, gate resolution, cancel, failure injection, add host, refresh mid-run, read-only mode |
| E2E (real infra) | manual/nightly on NUC + nested ESXi | Full hybrid pilot through the browser |
| Grep tests | shell/CI | No secrets in unexpected files, no hardcoded plugin names in shell |

## Codex review gates

Per house rule (`Codex review at milestones only`):

1. **End of Phase 1** — engine foundations, before SDK touch.
2. **End of Phase 2** — protocol v2, before HTTP investment.
3. **End of Phase 3** — API freeze, before UI investment.
4. **End of Phase 5** — full E2E, before declaring MVP.

## Risks and mitigations

| Risk | Impact | Mitigation |
|---|---|---|
| SDK protocol v2 breaks Python SDK | Existing Python plugins stop working | Protocol version negotiation in `hello`; compat mode covers v1 plugins for 1 release |
| Playwright brittleness | Test flakes block MVP | `data-testid` discipline enforced in review from day 1; no `class` or `text` selectors |
| Secret/replay split shortcut | Secrets leak into replayable config | Grep test in CI; Phase 1d ships with the test in place |
| File locking flakiness on macOS | envstore corruption | Test on Linux + macOS from Phase 1; use `flock`; atomic-rename fallback |
| Event backpressure | Slow subscriber blocks orchestrator | Bounded per-subscriber channel; drop with counter, never block source |
| Scope creep on Phase 5 | MVP slips | Phase 6 list is committed; new asks defer there |
| Rancher-style "stuck without why" regression | UX credibility damage | Every wait state must have a specific message; Phase 5 review checks this per screen |
| Nested ESXi resource pressure | Playwright hits real infra failures | CI Playwright runs against mock plugin; real-infra pilot is manual/nightly |
| CLI-started run invisible to UI controls | Confusing "why can't I cancel this?" UX | Single-writer model: UI labels CLI-owned runs read-only; Playwright test covers it; server-delegating CLI is the Phase 6 fix |

## Timeline

| Phase | Estimate | Depends on |
|---|---|---|
| 0 — Bug fixes + prep | 1 day | — |
| 1 — Engine foundations | 5–7 days | 0 |
| 2 — Gate protocol v2 | 3–5 days | 1 |
| 3 — HTTP + WS server | 3–5 days | 2 |
| 4 — Frontend scaffolding | 2–3 days | 3 |
| 5 — Core screens | 5–7 days | 4 |
| 6 — Polish | ongoing | 5 |

Phase estimates sum to 19–28 working days, so **~4–6 calendar weeks to MVP** at
sustained focus (3–4 weeks is the floor, not the estimate), four codex reviews
gating the way.

## Out of scope for MVP (explicit)

- Multi-user auth / OIDC / RBAC
- Multi-node HA / cluster mode (keep `Broadcaster` interface but ship `LocalBroadcaster` only, per Semaphore)
- Plugin-contributed UI (dynamic loader deferred to Phase 6+)
- Cloud-hosted mode / remote access (loopback-only)
- Command palette
- Debug bundle export
- Electron / Tauri wrapper
- Docs site
- Migrations from existing `~/.launchpad/runs/*.json` (fresh directory in Phase 1c; migration is Phase 6)
