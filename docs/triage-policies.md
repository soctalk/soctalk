# Triage Policies

A **Triage Policy** is a declarative governance policy over SocTalk's autonomous LLM
triage loop. It shapes *how* an alert is triaged — never *what actions are taken*. It
cannot act, cannot order response steps, and **cannot lower a disposition**. It is not a
SOAR workflow and not a human IR checklist.

> The word **"playbook" is reserved** for a future, separate document kind — **Response
> Playbooks** — the imperative post-disposition workflows (notify / ticket / isolate /
> block) that fire *after* triage commits, outside the agentic loop. Do not use "playbook"
> for the triage-policy kind anywhere in product/UI/docs.

## What a triage policy governs — the five levers

A triage policy binds to alerts (`applies_to`: rule groups / rule ids / authorization
tracks) and expresses up to five governance levers:

1. **Required evidence steps** (`required_steps`) — deterministic graph nodes that MUST run
   before a verdict is legal (e.g. `gather_authorization_context`). Adds rigor; never
   closes.
2. **Per-phase legal action sets** (`legal_actions`) — which supervisor actions are
   permitted in the `triage` vs `decide` phase.
3. **Raise-only post-verdict guardrails** (`guardrails`) — a sandboxed condition language
   over the state contract; each guardrail may only `override` a decision **up** the ladder
   `close < needs_more_info < escalate`, or `interrupt` to human sign-off.
4. **Close sign-off classes** (`close_signoff_data_classes`) — a committing close on an
   asset of one of these data classes is interrupted for human sign-off.
5. **Deterministic disposition** (`deterministic_disposition`, built-in policies only) — a
   vetted class close (e.g. operational noise) without an LLM look; every security-indicator
   veto still applies.

## The core invariant: suppression is inexpressible

A triage policy can only make triage **more conservative**, never less:

- Guardrail effects are **raise-only** — `DECISION_RANK` and the `to` enum make `close`
  unreachable; the guard skips any override that isn't strictly higher
  (`soctalk/playbook/guard.py`).
- `deterministic_disposition` is a **built-in-only** capability — authored/file policies
  cannot set it (`authoring.py`, `registry.py`), so UI/file authors cannot mint an
  auto-close class.
- The **non-overridable safety floor** (`soctalk/playbook/floor.py`) vetoes any auto-close
  over an IOC, an active-incident overlap, or contradicted authorization — regardless of any
  policy.

See the docstrings in `soctalk/playbook/models.py` and `DECISION_RANK` for the grammar.

> **Known gap (do not rely on it as a boundary):** authored `legal_actions` is *not* fully
> raise-only — a set that omits `VERDICT` and includes `CLOSE` can steer toward an
> auto-close that bypasses the post-verdict guard (caught only by the coarser floor).
> Authoring is admin-gated, so this is an accepted risk today; do not treat authored
> policies as strictly raise-only until that validation gap is closed.

## Lifecycle

- **Built-in** policies are vetted code (`registry.py`), read-only, always active.
- **File** policies load per-process in the runs-worker from `SOCTALK_PLAYBOOK_DIR`
  (delivered via the tenant chart ConfigMap); default `shadow`.
- **Authored** policies are DB-backed, per-tenant, admin-authored via the API/UI:
  `draft` → `shadow` (evaluated for audit, never enforced) → `active` (governs) →
  `retired`. Activating an authored policy materializes it into the worker's playbook
  ConfigMap on a `tenant.reconcile`; the worker rollout is the activation gate.

**Shadow** policies are matched and their guardrails evaluated for audit only — nothing is
enforced. This lets an author observe a policy's would-fire behavior before activating it.

## Naming rationale (why "Triage Policy", not "Playbook")

The artifact is a policy governing an autonomous triage loop — matchers, evidence
requirements, allowed-action sets, raise-only guardrails, sign-off classes. In the SOC
domain, "playbook" means an imperative SOAR workflow or a human IR checklist — the opposite
of a declarative, suppression-incapable policy. Continuing to call it a "playbook"
re-teaches the wrong mental model. We rename now, ahead of adding real **Response
Playbooks**, so the domain word is free for the thing that earns it. (Rejected: "guardrail
policy" — too narrow; "decision policy" — sounds like it decides; "governance policy" —
GRC-flavored.)

## Terminology & legacy-name map

| Concept | Current name | Legacy names |
|---|---|---|
| The policy kind | **Triage Policy** | "playbook" |
| API (canonical) | `/api/mssp/triage-policies`, `/api/mssp/tenants/{id}/triage-policies[/…]` | `/api/mssp/playbooks*` (deprecated aliases, one release) |
| UI route | `/triage-policies` (+ `/editor`) | `/playbooks*` → 308 redirect |
| Wire field | `triage_policy_id` | `playbook_id` served as a deprecated mirror on ALL authored responses (canonical and alias), one release |
| DB table | `authored_triage_policy_revisions` (migration `v1_0035`, reversible) | `authored_playbook_revisions` |
| Python package | `soctalk.triage_policy.*` | `soctalk.playbook.*` (gone; no shim) |
| Worker env / ConfigMap | *(unchanged, deliberate)* | `SOCTALK_PLAYBOOK_DIR`, `soctalk-playbooks`, `authored-*.yaml` |

The worker rollout contract keeps its legacy `playbook` names deliberately — renaming it
is a chart/worker coordinated rollout, deferred. Everything else is renamed with the
compatibility bridges listed above.

**Reserved:** `playbook` — for the future post-disposition **Response Playbooks**. Do not
use it for the triage-policy kind.
