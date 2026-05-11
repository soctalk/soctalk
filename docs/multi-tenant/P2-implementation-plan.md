# P2 — AI-led native IR, implementation plan

## Scope

Ship native, AI-led incident response as the default integration path.
Wazuh and native IR enabled by default; TheHive and MISP disabled by
default. Campaigns, NL policy editing, vector memory, and MISP runtime
deferred to v1.x.

Invariants anchored in P2-0. UI surface in P2-1 (to draft alongside
M6a, informed by the real backend).

## Integration posture

| Integration | Default | Toggle location | MVP runtime |
| --- | --- | --- | --- |
| Wazuh | enabled | chart + `IntegrationConfig` | deployed |
| Native IR | enabled | core platform, not toggleable | deployed |
| TheHive export | disabled | `IntegrationConfig.thehive_export_enabled` | schema + export worker (M5b) |
| MISP ingest | disabled | `IntegrationConfig.misp_ingest_enabled` | **schema column only, no runtime** |

## Milestones

```
M0     Spec commit (P2-0) + plan (this doc)
M1     DB foundation
M2     Reducer + inbox consumer + outbox executor
M3     Tool registry + policy loader
M4     API surface
M5a    Wazuh → alert → case pipeline
M5b    TheHive export worker (can land post-M6a)
M6a    Core UI: case list, conversation, facts panel, approve/reject
M7     Ancillary: alerts list, approvals queue, integrations settings, customer portal read-only
M8     Slack refresh (parallel; non-gating)
M6b    Tree navigator, command bar polish, slash commands → v1.x
M9     Tests (concurrent across M1–M7)
M10    Docs + rollout
```

Critical path: `M0 → M1 → M2 → M4 → M5a → M6a → M7`.

## Detail locks from P2-0 review

### a. DB session vars for visibility RLS

```
app.current_tenant_id   uuid
app.current_audience    text    'mssp' | 'customer'
app.current_user_role   text
```

Set in the identity middleware via `set_config(..., true)`. `audience`
derives from `user_type` (`mssp` → `'mssp'`, `tenant` → `'customer'`).

Pattern for every content-bearing table:

```sql
USING (
  tenant_id IS NOT DISTINCT FROM
    NULLIF(current_setting('app.current_tenant_id', true), '')::uuid
  AND (
    visibility IN ('customer_safe', 'system')
    OR current_setting('app.current_audience', true) = 'mssp'
  )
)
```

### b. Reducer contract

Event types and the fact-panel fields each may mutate:

```
alert_ingested          status, severity, opened_at, initial iocs/assets
hypothesis_updated      hypotheses[branch].{label, confidence, rationale_ref}
ioc_added / ioc_removed iocs set (soft-remove keeps history)
asset_linked / unlinked assets set
timeline_entry          timeline_summary append
analyst_correction      direct field override by (path, value)
directive_added/removed active_directives
policy_bound            active_policies
status_changed          status
confidence_recalibrated hypothesis confidences
reopened                status = 'active', reopen_count++
```

Reducer is deterministic and replay-safe. Events appended and projection
updated in the same transaction. Every case has a "drop projection,
reapply all events, assert equal" test.

### c. Outbox executor semantics

```
Claim:   FOR UPDATE SKIP LOCKED with 60s lease
Success: status='succeeded', external_ref populated, audit row written
Failure: attempts += 1, last_error, next_attempt_at = min(2^attempts · 10s, 30m) + jitter
Lease expired: reclaimable by another worker if claimed_at + lease < now
Terminal: attempts >= max (default 5) → status='failed', health surface
Idempotency: unique index on idempotency_key; dup insert returns existing
```

### d. Wazuh event mapping

```
1. Adapter POST /api/internal/adapter/events
   → insert into events (raw) with tenant_id
2. Triage worker:
   - severity classification + coalescing signature sha256(rule_id||asset_id||5min_bucket)
   - merge into existing open alert within window, else insert new alert
   - AI assessment band (real | unclear | likely_fp | high_conf_fp)
3. Promotion:
   - real/unclear → create case, insert alert_ingested event
   - likely_fp   → create case, low urgency
   - high_conf_fp + policy.auto_close → auto_close_case()
```

`alert_ingested` payload carries `source_events`, `asset_ids`,
`initial_iocs`, `rule_id`, `severity`, `confidence`.

### e. Reopen signature + matching

On auto-close:

```
reopen_signature = {
  ioc_fingerprints: [sha256(type + value)...],
  asset_ids:        [...],
  rule_ids:         [...],
  time_window:      {start: opened_at, end: opened_at + policy.reopen_window}
}
reopen_window_until = now() + policy.reopen_window   (default 30d)
```

Match: any-of (asset OR IOC OR rule) within the window. Broad by
design; cheap to dismiss false reopens, expensive to miss real ones.

### f. TheHive export idempotency key

```
key = sha256(object_type || object_id || canonical_json(state_snapshot))
```

`state_snapshot` is the subset of fields mirrored per object type
(case: title, severity, status, summary, iocs, assets, closed_at; ioc:
type, value, tlp, first_seen). New state → new key → new outbox row.
Same state → same key → unique index dedups. First mirror stores
`external_ref`; subsequent rows PATCH the existing TheHive record.

## Risk register

| Risk | Mitigation |
| --- | --- |
| LangGraph fit unclear | Ship without LangGraph in MVP; plain async tasks. Layer LangGraph in v1.x if the need is concrete |
| Visibility RLS miswrite | Tests before policies: write customer-viewer-cannot-select-mssp-only tests first, land policies to make them pass |
| Reducer drift | Append-only events + deterministic reducer + replay-from-events test per case |
| Executor crash leaves proposals stuck | 60s lease, reclaim semantics, terminal after 5 attempts |
| Customer-portal leak | Default-deny-promote + adversarial query tests |

## Rollout

1. M0 locked → M1 migration shipped → M2–M5a backend live end-to-end.
2. Backend tested via curl before UI exists.
3. M6a ships the minimal analyst loop; M7 fills in ancillary surfaces.
4. Beta after M6a + M7 + M9 (tests green).
5. Slack refresh (M8) parallelizable, non-gating.
6. M6b (tree navigator, command polish) lands post-beta as v1.x.

Upgrade path from current : additive. New tables, new columns with
safe defaults, no schema breaks. Existing deployments migrate by
running the new migration and restarting the API. Wazuh adapter wiring
already in place — native IR starts consuming events immediately.
