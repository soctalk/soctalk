# P2-0 — Core invariants for AI-led native IR

## 1. Scope and non-goals

This doc defines the backend invariants the MVP depends on: data shape,
state machines, visibility, and failure semantics. No UI, no prompt
engineering, no campaigns, no correlation scoring. Those land in P2-1
(conversation UI) and P2-2 (campaigns) once this is fixed.

In-scope for MVP:
- One case, one active run, one analyst gate.
- Visibility classes as a first-class data concern.
- Execution log separate from conversation.
- Related-case hints by cheap shared-signal match.
- One-way TheHive export.

Out of scope (v1.x):
- Campaign entity and scored correlation.
- NL policy editor with historical diff.
- Vector memory / similarity retrieval.
- External threat-intel ingestion (MISP/OpenCTI).
- Multi-agent / specialized agents.

## 2. Core entities

Minimal shape. Full column lists live in the migration; only load-bearing
fields are named here.

```
alerts               raw ingest from adapter; AI-triaged
cases                investigation unit; one run at a time
case_runs            a single AI execution span against a case
case_events          ordered event inbox per case (immutable)
proposals            AI-proposed actions awaiting human gate
execution_log        append-only audit of all meaningful actions
notes                markdown / evidence blocks
iocs                 typed artifacts; carry external_context
case_iocs, case_assets   bridge tables
case_links           related-case edges (shared IOC / asset / rule)
case_outbox          outbound work for executors and exports
```

Every content-bearing row carries `tenant_id`, `visibility`, and
`created_at`. RLS applies per tenancy.

## 3. Visibility model

Classes (enum):

```
mssp_only         default; internal reasoning, raw tool output, hypotheses
customer_safe     approved for customer view
system            lifecycle and state-change events, always visible
tool_output       classified per-tool at registration time
```

Rules:

1. `visibility` is a column on every user-visible row (messages, notes,
   proposals, tool_output records, timeline entries, facts-panel fields).
2. Default on insert is `mssp_only`. Promotion to `customer_safe` is an
   explicit operation.
3. Customer portal queries filter at the RLS policy layer, not at
   render. A customer-viewer session cannot read `mssp_only` rows even
   via raw SQL.
4. Proposals have field-level visibility: `{action, outcome}` may be
   `customer_safe` while `{rationale, blast_radius}` stays `mssp_only`.
   Rendered as two projections.
5. Every visibility promotion emits an `execution_log` entry with the
   actor and rationale.

Default-deny-promotion: policies may downgrade visibility but may not
upgrade without an explicit action by an authorized principal.

## 4. Run lifecycle

States:

```
active           run consuming events and taking steps
waiting_on_gate  a proposal is pending; run does not mutate state
halted_budget    budget exceeded; requires analyst resume
paused           analyst-paused
completed        case closed
failed           unrecoverable error; requires analyst resume or restart
```

Transitions:

```
active → waiting_on_gate     on proposal created (status = proposed)
waiting_on_gate → active     on proposal approved/rejected (new event)
active → halted_budget       on budget exceeded
halted_budget → active       on analyst resume (grants new budget)
active → paused              on analyst pause
paused → active              on analyst resume
active → completed           on case close
* → failed                   on uncaught error, preserved for diagnosis
```

Invariants:

- At most one run per case in state `active | waiting_on_gate |
  halted_budget | paused`. Enforced via a partial unique index on
  `case_runs(case_id) WHERE status IN (...)`.
- Budget counters on the run: `tokens_used`, `dollars_used`,
  `tool_calls_used`, `wall_clock_ms`. Enforced server-side; soft warn
  at 75%, hard halt at 100%.
- A `waiting_on_gate` run does not process inbox events except
  gate-resolution events (proposal.approved / .rejected).

## 5. Event inbox, ordering, coalescing, idempotency

All incoming work for a case lands in `case_events`:

```
event_id              uuid PK
case_id               FK
run_id                FK nullable
seq                   bigint, case-scoped monotonic (sequence)
kind                  enum (alert_ingested, tool_result,
                            proposal_approved, proposal_rejected,
                            analyst_message, analyst_correction,
                            budget_warning, external_signal, ...)
payload               jsonb
causation_event_id    uuid nullable (which event caused this one)
correlation_id        uuid (spans a causally-related fan-out)
idempotency_key       text unique per case
created_at            timestamptz
```

Rules:

1. `seq` is issued by a case-scoped sequence on insert. Consumers read
   strictly in `seq` order.
2. `idempotency_key` is unique per `case_id`. Duplicate insert is
   silently dropped (return the existing row).
3. Coalescing: before insert, events matching `(case_id, kind,
   payload.signature, window)` merge into a single row. Signature is
   kind-specific (alert: fingerprint of IOC + rule + asset; tool_result:
   tool_id + params hash).
4. `causation_event_id` links cause → effect for replay.
   `correlation_id` groups events from a single external trigger or
   analyst action.
5. Events are immutable. Updates express as follow-on events.

Burst example: 100 similar host alerts in 5 minutes coalesce into one
`alert_ingested` event carrying an `asset_ids: [...]` list. The run
processes it once.

## 6. Proposal lifecycle and execution contract

States:

```
draft        being composed by the AI
proposed     submitted to human gate
approved     human approved (with typed reason if required)
rejected     human rejected (reason required)
executing    outbox picked up; executor running
executed     action complete, result recorded
rolled_back  post-execution reversal (rare, analyst-initiated)
failed       executor error
```

Idempotency:

```
proposal.idempotency_key = sha256(case_id || action_type ||
                                   canonical_json(params))
```

Duplicate proposals within an active window (default 15 minutes) are
rejected at insert. Guarantees the AI cannot double-fire even under
re-run.

Gate behavior:

- On `proposed`: run transitions to `waiting_on_gate`.
- On `approved`: insert row in `case_outbox` with
  `kind = 'execute_proposal'`, `idempotency_key = proposal.idempotency_key`.
  Emit `proposal_approved` into `case_events`. Run resumes.
- On `rejected`: emit `proposal_rejected` with reason into
  `case_events`. Run resumes. No outbox row.

Execution:

- Separate executor worker consumes `case_outbox` and performs the
  action.
- On success: records `execute_proposal_result` into `case_events`,
  updates proposal → `executed`, writes `execution_log` entry.
- On failure: records error, updates proposal → `failed`, writes
  `execution_log` entry. The run may propose a retry.
- Exactly-once via `idempotency_key`: outbox rows with duplicate keys
  are rejected. Executor workers claim rows with a lease (e.g.,
  `FOR UPDATE SKIP LOCKED`).

The AI run does not execute side effects inline. Everything goes
through the outbox.

## 7. Execution log schema and invariants

Append-only, separate from conversation:

```
log_id              uuid PK
case_id             FK
run_id              FK nullable
actor_kind          enum (ai, human, system, executor)
actor_id            text
kind                enum (tool_call, proposal_state_change,
                          approval, override, visibility_promotion,
                          correction_applied, policy_bound,
                          export_emitted, ...)
subject_type        enum (case, proposal, ioc, asset, note, ...)
subject_id          text
before              jsonb nullable
after               jsonb nullable
versions            jsonb (model_id, prompt_version, template_version,
                           policy_version at time of action)
ts                  timestamptz default now()
```

Invariants:

1. No UPDATE or DELETE permitted from app roles. Only INSERT + SELECT.
   Enforced at the Postgres role-grant layer.
2. Every proposal state change, every tool call, every approval,
   every analyst override of an AI decision, every visibility change,
   every correction, every outbox dispatch writes a row.
3. `versions` captures the stack that produced the action. Required for
   reproducibility and post-hoc calibration.
4. The conversation is a rendered view of a subset of events; it is not
   audit. Destroying or compacting conversation does not destroy audit.

## 8. Facts-panel authority and correction flow

Structured case state (hypotheses, IOCs, assets, timeline summary,
confidence, active directives) is a reducer output over `case_events`.
It is never directly mutated by conversation.

Rules:

1. Conversation messages do not write structured state.
2. AI updates to structured state happen via AI-emitted events
   (`hypothesis_updated`, `ioc_added`, `asset_linked`).
3. Analyst edits in the facts panel emit `analyst_correction` events.
   The reducer applies them. The AI consumes the correction as the next
   inbox event and re-reasons from the corrected state.
4. The facts panel is eventually consistent with `case_events`. A
   materialized projection (table or view) is maintained; reads can
   hit it directly.
5. Direct corrections to the execution log are forbidden; corrections
   express as new events plus a pointer to the corrected one.

## 9. Tool capability taxonomy

Every tool is registered with a capability class, a default approval
policy, and a cost model.

Capability classes:

```
read_local               inspect SocTalk state only
read_external_silent     no target footprint (feeds, cached intel, vector)
read_external_attributed trace at target (SIEM query, EDR read)
write_sandbox            footprint without target mutation (detonation)
write_external           target state change (block, isolate, notify)
```

Default approval policy per class:

```
read_local                → autonomous
read_external_silent      → autonomous
read_external_attributed  → analyst_approve
write_sandbox             → analyst_approve
write_external            → typed_reason
```

Per-tool cost model: `{tokens_est, dollars_est, wall_ms_est, footprint}`.
The run budget tracks the sum.

## 10. Policy precedence

Policies are merged in this order, lower overrides higher:

```
1. install default       (shipped in chart, read-only in v1)
2. tenant override       (MSSP sets per customer)
3. case template         (phishing, ransomware, etc.)
4. case-local override   (set for this one case by analyst)
```

For each policy key (tool approval, auto-close, visibility promotion,
response templates, budget), the effective value is the deepest scope
that defines it.

Invariants:

1. Visibility promotion is never set to `permissive` by default at
   install scope. Default is "explicit promotion required."
2. A tenant policy cannot override an install-level hard cap (e.g.,
   `max_tokens_per_case`).
3. Case-local overrides are scoped to the case and do not persist to
   future cases.

## 11. Auto-close / reopen semantics

Auto-close for high-confidence FPs:

```
Trigger:
  AI assessment = fp, confidence ≥ policy.auto_close_threshold
  AND policy.auto_close_enabled is true for the tenant
  AND no active directive prevents auto-close

Action:
  case.status = 'auto_closed_fp'
  case.reopen_window_until = now() + policy.reopen_window
  case.reopen_signature = {
    ioc_fingerprints: [...],
    asset_ids: [...],
    time_window: {start, end}
  }
  run transitions to completed
  execution_log row written
```

Reopen:

```
Trigger:
  new case_events row with kind ∈ {alert_ingested, external_signal}
  whose signature intersects a case's reopen_signature
  where case.status = 'auto_closed_fp'
    AND now() < case.reopen_window_until

Action:
  case.status = 'active'
  emit reopened event into case_events
  new run created
  execution_log row written
  conversation receives a system message noting the reopen
```

Kill switch:
- `IntegrationConfig.auto_close_enabled` per tenant (default: on).
- `CaseTemplate.auto_close_disabled` per case type.

## 12. TheHive export contract (outbox-based, one-way)

Mirror cases, IOCs, and selected notes outbound to TheHive when the
tenant has `thehive_export_enabled`. Never accept inbound changes.

Outbox row (in `case_outbox`):

```
id                  uuid PK
kind                'export.thehive.case' | 'export.thehive.ioc' | ...
external_system     'thehive'
external_ref        TheHive object id (filled on first successful mirror)
object_type         case | ioc | note
object_id           internal subject id
idempotency_key     sha256(object_type || object_id || state_hash)
payload             jsonb
export_status       pending | in_flight | succeeded | failed | skipped
attempts            int
last_error          text nullable
next_attempt_at     timestamptz
created_at, updated_at
```

Rules:

1. State change on a mirrored object enqueues an export row with a
   fresh `idempotency_key` (incorporates the state hash).
2. Worker claims with `FOR UPDATE SKIP LOCKED`. On success, records
   `external_ref` (creating or updating on TheHive side as needed) and
   writes execution_log.
3. Inbound webhooks from TheHive are accepted only for read-only
   dashboard cases (not v1). Any attempt to accept inbound state is
   explicitly rejected and logged.
4. No reconciliation loop — TheHive is a downstream mirror, the source
   of truth is SocTalk.
5. Failed exports retry with exponential backoff up to a cap; permanent
   failure surfaces on the integrations health panel.

## 13. Mandatory tests and invariants

Test suite (unit + integration) must cover:

1. **Execution log immutability.** UPDATE and DELETE against
   `execution_log` from the app role fail at the Postgres layer.
2. **Single active run per case.** Concurrent attempts to create a
   second active run fail with a unique-constraint violation.
3. **Proposal idempotency.** Submitting two proposals with the same
   idempotency key within the window: the second is rejected.
4. **Gate-pause behavior.** A run with a `proposed` proposal does not
   consume non-gate events from its inbox.
5. **Outbox exactly-once.** Two workers claiming the same outbox row
   result in one succeeding, one no-oping.
6. **Visibility enforcement.** A customer-viewer session cannot select
   `mssp_only` rows from any table, even with raw SQL.
7. **Visibility promotion logged.** Every promotion from `mssp_only`
   to `customer_safe` produces an `execution_log` row.
8. **Correction flow.** Analyst correction event produces a new event
   that the reducer applies; the facts-panel projection reflects the
   correction.
9. **Auto-close reopen.** An event matching a reopen_signature within
   the window reopens the case and starts a new run.
10. **TheHive export idempotency.** Re-running an export for an object
    whose state has not changed is a no-op (same idempotency_key).
11. **Tool approval policy.** A `write_external` tool call without a
    typed_reason approval cannot reach the executor.
12. **Policy precedence.** Case-local override wins over tenant which
    wins over install for the same policy key.

## 14. Out of this spec

- Component models, visual behavior, command-bar parsing → P2-1.
- Campaign correlation, scoring, cross-tenant mechanics → P2-2.
- Prompt library, LLM tool registry contents, model-version policy
  → separate P2-3 (LLM runtime) when we get there.
