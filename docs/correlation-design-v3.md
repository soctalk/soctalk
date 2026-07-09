# Correlation design v3 — revised against shipped state (2026-07-09)

Supersedes v2. The premise changed: what v2 planned to BUILD as Phase-0
substrate largely shipped as a side effect of #14/#15/#17. Correlation is
now a *connect-and-broaden* effort, not a build.

## Substrate status (verified against main)

- Attach-to-active investigation: BUILT (`upsert_alert` promoted-attach) but
  keyed on same-signature only (`a.signature = :s`, triage.py:178).
- Reopen for all FP closes: DONE (#15).
- Idempotency: DONE (#17 alert_source_events unique).
- Typed entities w/ role + provenance: DONE (#17 `entities` {type,value,role,source_field}).
- Occurrence vs observation time: DONE (#17).
- Concurrency safety (advisory lock, run-state matrix, active_run_for_case guard): DONE (#14).
- MITRE / rule_groups / decoder / template_hash on the wire + evidence store: DONE (#17).
- Structured verdicts (indexable): DONE (#3).
- Correlation-keys table: REFRAMED to a derived index over entities/iocs (not a source of truth).
- Settle window: MISSING.
- Multi-alert delivery to the graph: MISSING (claim is LIMIT 1, worker_runs.py) — this is the gap
  that means correlation currently groups investigations but NOT reasoning, so the cost win is unrealized.

## Sequenced plan (order flipped from v2 — substrate is mostly done)

1. **Multi-alert claim delivery + compaction (#11).** Highest leverage, smallest surface.
   Claim returns all alerts linked to the investigation (not LIMIT 1); _build_state maps all;
   supervisor/verdict context render N alerts with token-aware top-k + overflow markers (#11).
   Turns the already-shipped attach from "DB grouping" into "one run reasons over N correlated alerts".
2. **Entity-overlap attach predicate.** After the same-signature check misses, a second lookup
   against a derived entity index (typed entities + IOC fingerprints, rarity-weighted, per-key-type
   window) attaches to an active investigation sharing a high-strength entity. Reuses the entire
   shipped attach sink (append_event, audit, run-state matrix). Derived index rebuildable from
   alert_source_events.entities — not a new source of truth.
3. **Settle window.** not_before on investigation_runs + claim predicate (Alertmanager group_wait):
   a burst accumulates before the first claim. Severity>=12 bypasses. The only genuinely-new
   deterministic piece.
4. **Verdict memoization + template-novelty suppression.** signature/template_hash -> prior structured
   verdict reuse (close recurring benign without an LLM call); novel templates fast-pathed to enrichment,
   known-benign templates suppressed (auto Dispatch-snooze). Cheap, both unblocked by #3/#17.
5. **Learned correlation layer (async, review-only).** Now with real features: typed-entity Jaccard,
   embeddings canonicalized from rule_groups/decoder/MITRE/entity-types, rarity from typed-entity
   frequency, tier-0 adjudicator on structured evidence with cache-warm prefix. Gated by HIL
   merge/detach labels (new actions) + structured verdicts. Deterministic entity match stays the only
   auto-attach; scorer suggests until labeled precision earns enforcement.

## New correlation signals #17 unlocked (beyond v2's key matching)

- Entity-graph via roles (actor/target/src/dst): lateral movement (same actor, many targets) vs
  targeted host (many actors, one target) — directed, not just co-occurrence.
- Kill-chain via MITRE tactics: correlate ATT&CK progression on one entity (incident narrative).
- Template-novelty routing: spend effort on novel log shapes, suppress high-frequency known-benign.
- Verdict memoization: structured verdict as the reusable value keyed by signature/template.

## Prior art mapping (native, no dependency)
- Netflix Dispatch: entity-dedup-into-existing-case == the typed-entity attach (step 2);
  snooze filters == template-novelty suppression (step 4).
- Prometheus Alertmanager: group_wait == settle window (step 3); group_interval == follow-up-run policy.

## Risks carried forward
- Hub keys: rarity/frequency demotion per typed entity (cheap aggregate now).
- Over-grouping: per-key-type + per-tenant windows, group-size cap (both exist from #14/#11 hooks).
- Dual representation: asset_ids stays frozen for coalescing/reopen; correlation keys off entities.
  Deliberate future revisit of coalescing onto typed entities (do not let the sidecar become permanent).
- Learned-layer feedback loop: labels from analyst actions only, never the scorer's own accepts.
- alerts JSONB unbounded growth (source_event_ids/initial_iocs) — pre-existing; aggregate in this program.
