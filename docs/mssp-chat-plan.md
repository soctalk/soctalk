# MSSP Chat & Per-Tenant Wazuh Routing — Plan

Companion to [`chat-interface-plan.md`](./chat-interface-plan.md). That plan delivered
a chat scoped to a single tenant: the conversation always has a `tenant_id`, MSSP
operators must pin Open SOC before opening `/chat`, and Wazuh tools target the one
Wazuh instance whose creds live in the API pod's env.

This plan removes both constraints so the MSSP chat can:

1. Operate **without a tenant pin** — answer questions that span multiple tenants.
2. Query **any specific tenant's Wazuh** — routing creds + URL per call.

The two are coupled. An unpinned MSSP conversation that wants to ask
"how many active agents at acme-corp" needs (a) the chat to allow no `tenant_id` and
(b) the Wazuh tool to know which tenant's Wazuh to hit. So they ship together.

---

## Goals & non-goals

**Goals**
- MSSP-level users can open `/chat` without pinning Open SOC.
- Chat tools accept an optional `tenant_slug` filter; results carry tenant attribution.
- Every Wazuh tool routes to the named tenant's Wazuh server. No tenant → the model
  must specify, except when the conversation is already bound to one tenant.
- Tenant-bound users (customer roles) keep the existing behavior — no choice, no
  cross-tenant view, no slug parameter.
- Cost cap accounting still works (the existing per-tenant $15/day cap stops being
  obviously applicable for unpinned conversations; we need an MSSP-scope cap).

**Non-goals**
- Cross-tenant *writes* from chat (proposed_action still single-tenant by virtue of
  targeting one investigation/review).
- Auto-discovery of tenant from a free-form user message ("show me alerts at acme")
  — the model decides via tool args; we don't NLP the user text.
- MSSP-wide Wazuh fan-out queries (e.g. "show me critical CVEs across the whole
  fleet") in Phase 1. Out-of-band: a roll-up tool tier in Phase 4 below.
- Tenant-scoped users gaining any new capability. The pin requirement stays for
  them (it's the existing UX, and they only ever see one tenant).
- Changing the cred storage model for Wazuh. We use what `tenant_secrets` already
  points at.

---

## Current state recap

```
conversations.tenant_id  NOT NULL  ───  enforced both schema-side and API-side
                                       (POST /conversations returns 400 if MSSP user
                                        has no pin and no investigation_id)

chat tools:
  list_pending_reviews()    ─── role-aware session, NO tenant_slug arg
  recent_alerts(limit)      ─── role-aware session, no slug
  tenant_stats()            ─── MSSP-only, returns roll-up (already cross-tenant)
  search_investigations(q)  ─── role-aware session, no slug
  audit_trail(...)          ─── role-aware session, no slug
  get_investigation(id)     ─── role-aware session, id implies tenant

wazuh tools (14):
  wazuh.alert_summary, agents, rules_summary, …
  → all dispatch through soctalk.chat.wazuh_primitives.WazuhConfig.from_env()
  → ONE Wazuh URL/user/pass per API pod, set at pod start, never changes
```

The MSSP chat user today gets the "Open SOC required" notice on `/chat` and falls
out. The Wazuh tools always hit the same Wazuh.

---

## Architecture changes

### Two distinct conversation scopes

```
┌─────────────────────────┬──────────────────┬────────────────────────────────┐
│ Scope                   │ conv.tenant_id   │ Tool tenant resolution         │
├─────────────────────────┼──────────────────┼────────────────────────────────┤
│ tenant-bound            │ <uuid>           │ Implicit: conv.tenant_id       │
│   (customer role OR     │                  │ tenant_slug arg rejected if    │
│    MSSP-pinned)         │                  │ it doesn't match conv.tenant   │
├─────────────────────────┼──────────────────┼────────────────────────────────┤
│ mssp-fleet              │ NULL             │ Explicit: tenant_slug required │
│   (MSSP user, no pin,   │                  │ on every tool that targets a   │
│    no investigation)    │                  │ tenant; roll-up tools allowed  │
│                         │                  │ without slug                   │
└─────────────────────────┴──────────────────┴────────────────────────────────┘
```

The scope is decided at conversation create time and is **immutable**. Switching
scope = start a new conversation. This keeps audit / cost accounting / RLS-stamping
consistent for the conversation's lifetime.

### Per-tenant Wazuh routing data flow

```
agent loop
   │
   │  tool call: wazuh.alerts_summary(tenant_slug="acme-corp", time_range="24h")
   ▼
WAZUH_CHAT_TOOLS dispatcher
   │  1. Resolve effective tenant:
   │       conv.tenant_id ?  → must match named tenant OR slug omitted
   │       conv.tenant_id =None? → slug required
   │  2. Look up tenant by slug (MSSP session, BYPASSRLS)
   │  3. _resolve_wazuh_for(tenant_id)  ──────────────────┐
   │                                                       │
   │  4. Make HTTP call with that config, return result    │
   ▼                                                       │
result projection (adds `_tenant_slug` to top of payload)  │
                                                           │
                                                           ▼
                                          _resolve_wazuh_for(tenant_id):
                                          ┌──────────────────────────────┐
                                          │ a) integration_configs       │
                                          │     → wazuh_url, verify_ssl  │
                                          │ b) tenant_secrets row        │
                                          │     where purpose='wazuh-api'│
                                          │     → k8s ns + secret name   │
                                          │ c) read the k8s secret       │
                                          │     (kubernetes-asyncio)     │
                                          │     → username, password     │
                                          │ d) Build WazuhConfig         │
                                          │ e) Cache (TTL 5 min)         │
                                          └──────────────────────────────┘
```

---

## Data model changes

### `conversations.tenant_id` — drop NOT NULL

Ordering matters: add the `scope` column **first** (so the cross-column CHECK can
reference it), backfill existing rows, then drop the `tenant_id` NOT NULL, then
add the cross-column constraint.

```sql
-- 1. New scope column with a per-value CHECK that's self-contained.
ALTER TABLE conversations ADD COLUMN scope TEXT NOT NULL DEFAULT 'tenant'
    CHECK (scope IN ('tenant','mssp_fleet'));

-- 2. Existing rows are all tenant-scoped (the old API enforced that), so the
--    DEFAULT covers the backfill. No data migration step required.

-- 3. Now drop NOT NULL on tenant_id.
ALTER TABLE conversations ALTER COLUMN tenant_id DROP NOT NULL;

-- 4. Cross-column rule, added LAST so both columns exist.
ALTER TABLE conversations ADD CONSTRAINT ck_conversations_scope CHECK (
    -- tenant-bound:    tenant set, scope='tenant'
    -- mssp-fleet:      NULL tenant, NULL investigation, scope='mssp_fleet'
    (scope = 'tenant' AND tenant_id IS NOT NULL)
    OR
    (scope = 'mssp_fleet' AND tenant_id IS NULL AND investigation_id IS NULL)
);
```

Why an explicit `scope` column on top of NULL: makes RLS policy and audit-log
queries readable. `WHERE tenant_id IS NULL` is correct but cryptic; `WHERE scope =
'mssp_fleet'` reads.

### `chat_messages.tenant_id` — also nullable, mirror conversation scope

`chat_messages.tenant_id NOT NULL` made sense when every conv was tenant-bound. For
mssp_fleet conversations we set it to NULL too, matching `conv.tenant_id`. The
existing RLS policy already handles `tenant_id IS NULL` (audit_log uses the same
shape).

### RLS policies

Add a permissive branch on both tables: rows with `tenant_id IS NULL` are visible
only to MSSP-level roles. The existing policies remain unchanged for tenant rows.

**Use the existing GUC convention from `v1_0011_rename_case_to_investigation.py`
and `v1_0012_chat_tables.py`**: `NULLIF(current_setting('app.current_tenant_id',
true), '')::uuid` (the context setter writes `''` when unset, not NULL) and
`current_setting('app.current_audience', true) = 'mssp'` (not a new
`principal_kind` GUC).

```sql
DROP POLICY conversations_tenant_isolation ON conversations;
CREATE POLICY conversations_tenant_isolation ON conversations
    USING (
        -- tenant-scoped row visible to its tenant
        tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid
        -- fleet-scoped row visible to MSSP roles in fleet mode
        -- (no tenant pin AND audience='mssp')
        OR (
            tenant_id IS NULL
            AND COALESCE(NULLIF(current_setting('app.current_tenant_id', true), ''), '') = ''
            AND current_setting('app.current_audience', true) = 'mssp'
        )
    )
    WITH CHECK (
        tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid
        OR (
            tenant_id IS NULL
            AND COALESCE(NULLIF(current_setting('app.current_tenant_id', true), ''), '') = ''
            AND current_setting('app.current_audience', true) = 'mssp'
        )
    );
```

Same shape on `chat_messages`. The `_chat_session_for` helper inherits its GUCs
from the same context-setter that audit/analytics already use, so no new GUC is
introduced.

#### Fleet CRUD requires a pin-aware session strategy

A pinned MSSP user (Open SOC active on tenant X) still has
`app.current_tenant_id = X` in their request session. If they read or write a
**fleet** conversation, the RLS predicate above won't match the fleet branch
(which requires the tenant GUC to be blank).

The `_chat_session_for(identity, conv_scope)` helper therefore conditions GUCs
on the conversation's scope, not on the request's pin:

| `conv_scope`     | `app.current_tenant_id` | `app.current_audience` | Notes                         |
| ---------------- | ----------------------- | ---------------------- | ----------------------------- |
| `tenant`         | conv.tenant_id          | `mssp` or `tenant`     | matches tenant RLS branch     |
| `mssp_fleet`     | `''` (blank)            | `mssp`                 | matches fleet RLS branch      |

For fleet operations the helper opens its session with `SET LOCAL
app.current_tenant_id = ''` regardless of the request's pin. The pin remains
the request's Open SOC selection (used elsewhere); the chat session deliberately
overrides it for the conversation it is operating on. Authorization is enforced
by the audience check, not the GUC value.

This also covers the **read** path: listing a user's conversations runs two
RLS-scoped SELECTs (one with the user's pin GUC for tenant conv rows, one with
the blank+mssp GUCs for fleet rows) and UNIONs the results. Customer roles only
ever see the first; the helper short-circuits the fleet SELECT for them.

### No new tables for Wazuh creds

`tenant_secrets` is already the pointer table. We add a convention: rows with
`purpose='wazuh-api'` point at the k8s secret holding `username` + `password` for
that tenant's Wazuh Manager. The provisioning controller mirrors this convention
at tenant bootstrap. We add the row if it isn't already there for existing tenants
(backfill script).

---

## API changes

### `POST /api/chat/conversations`

```json
{
  "investigation_id": null,           // existing
  "scope": "tenant" | "mssp_fleet",   // new, defaults to "tenant"
  "title": null                       // existing
}
```

Server logic:

1. **Customer role**: ignore `scope`, force `"tenant"`. `tenant_id` = caller's home tenant.
2. **MSSP-level**:
   - `investigation_id` present → scope forced to `"tenant"`, `tenant_id` inherited
     from the investigation row (existing rule).
   - `scope == "tenant"`: require a `current_tenant` pin. `tenant_id` = pin.
   - `scope == "mssp_fleet"`: `tenant_id = NULL`. Pin is *not* required, but if
     set it is ignored (the conversation is fleet-scoped, not pin-scoped).

The "must pin to chat" 400 only fires for `scope == "tenant"` now.

### `GET /api/chat/conversations`

Add `scope` to the response. UI uses it to render the "All tenants" badge.

### `POST /api/chat/conversations/{id}/messages`

No request shape change. The handler resolves the conv's scope from the row and
passes it into `TurnContext`.

### Cost cap

`assert_tenant_daily_cap_ok()` currently joins on `tenant_id`. Add a mirror cap
for mssp-fleet conversations: sum chat dollars where `tenant_id IS NULL` per
**user_id** per day, cap configured by env (`SOCTALK_MSSP_USER_DAILY_CAP_USD`,
default $15 same as tenant cap). Keeps fleet conversations from being a budget
side-door.

---

## Tool surface changes

### Every tenant-targeted tool grows an optional `tenant_slug`

```python
# Before
async def list_pending_reviews(db, *, limit: int = 20):

# After
async def list_pending_reviews(db, *, tenant_slug: str | None = None,
                               limit: int = 20):
```

Resolution rule (shared helper `_resolve_target_tenant`):

```
ctx.scope == 'tenant':
    tenant_slug arg ignored (or rejected if it disagrees with conv.tenant)
    target_tenant_id = ctx.tenant_id

ctx.scope == 'mssp_fleet':
    tenant_slug provided  → look up tenant; target_tenant_id = that tenant
    tenant_slug omitted   → return {"error": "tenant_slug required ...", "hint": "..."}
                            (tool result, NOT an exception — model retries)
```

The MSSP-scope session is BYPASSRLS (existing role), so the helper just runs a
`SELECT id FROM tenants WHERE slug = $1`. Cache the slug→id map (5 min TTL,
invalidation on tenant create/delete via the existing tenant-config event bus).

### Tool result projection

Every tenant-targeted tool result MUST carry a `_tenant` field:

```json
{
  "_tenant": {"id": "…", "slug": "acme-corp", "name": "Acme Corp"},
  "rows": [...]
}
```

This is what makes the model able to attribute correctly back to the user. Without
it, the assistant might say "I see 17 critical reviews" with no way for the user
to know which tenant. The agent's system prompt instructs it to mention the
tenant slug in any user-facing summary.

### New roll-up tools (for `mssp_fleet` scope without a slug)

| Tool                          | Returns                                                              |
| ----------------------------- | -------------------------------------------------------------------- |
| `list_tenants()`              | Slugs + display names + counts. The "what tenants exist" entry.      |
| `fleet_pending_reviews()`     | Pending review counts per tenant (no row bodies).                    |
| `fleet_recent_alert_counts()` | Alert counts per tenant for last N hours.                            |
| `fleet_active_investigations()` | Open investigation counts per tenant.                              |

These are **read-only DB aggregates**, not Wazuh fan-outs. Wazuh fleet roll-ups
are explicitly Phase 4.

### Wazuh tools — per-call tenant routing

All 14 native Wazuh tools (`wazuh.alert_summary`, `wazuh.agents`, …) gain
`tenant_slug` and route through the resolver above. The result projection adds
`_tenant` exactly like the DB tools.

For `scope == "tenant"`: `tenant_slug` is implicit (conv's tenant). The model can
omit it and the dispatcher fills it in.

For `scope == "mssp_fleet"`: `tenant_slug` required. The system prompt
emphasizes this and lists available tenants by slug (from `list_tenants()`
output cached for the turn).

### Cred resolution — `_resolve_wazuh_for(tenant_id)`

The Wazuh integration is two services with **separate credentials**:

- **Manager API** (port 55000, JWT bearer auth) — `WAZUH_API_USERNAME` / `WAZUH_API_PASSWORD`
- **Indexer** (OpenSearch, port 9200, HTTP Basic) — `INDEXER_USERNAME` / `INDEXER_PASSWORD`

Both keys already live in the same per-tenant k8s secret (see
`charts/wazuh/templates/secrets.yaml` — single `<tenant>-wazuh-creds` secret with
all 4 keys). The chart wires them into the runs-worker / adapter env as
`WAZUH_API_USERNAME`, `WAZUH_API_PASSWORD`, `WAZUH_INDEXER_USERNAME`,
`WAZUH_INDEXER_PASSWORD`. We must surface BOTH pairs in `WazuhConfig` — the
existing `_IndexerClient` already authenticates with the indexer credentials
separately from the JWT token, so they can't share creds.

```python
@dataclass
class WazuhConfig:
    manager_url: str           # https://…:55000
    manager_user: str
    manager_pass: str
    indexer_url: str           # https://…:9200 (separate column in
                               # integration_configs — see schema change below)
    indexer_user: str
    indexer_pass: str
    verify_ssl: bool


async def _resolve_wazuh_for(tenant_id: UUID, db: AsyncSession) -> WazuhConfig:
    # 1. integration_configs row (MSSP-session SELECT)
    cfg = await _get_integration_config(db, tenant_id)
    if not cfg or not cfg.wazuh_url or not cfg.wazuh_enabled:
        raise WazuhNotConfigured(tenant_id, "no wazuh_url in integration_configs")

    # 2. tenant_secrets pointer
    sec = await _get_tenant_secret(db, tenant_id, purpose="wazuh-api")
    if not sec:
        raise WazuhNotConfigured(tenant_id, "no wazuh-api tenant_secret")

    # 3. Read the k8s secret (cross-namespace).
    creds = await _k8s_secret_read(sec.k8s_namespace, sec.k8s_secret_name)
    mgr_user = creds.get("WAZUH_API_USERNAME") or creds.get("username")
    mgr_pw   = creds.get("WAZUH_API_PASSWORD") or creds.get("password")
    idx_user = creds.get("INDEXER_USERNAME") or creds.get("WAZUH_INDEXER_USERNAME")
    idx_pw   = creds.get("INDEXER_PASSWORD") or creds.get("WAZUH_INDEXER_PASSWORD")
    if not (mgr_user and mgr_pw and idx_user and idx_pw):
        raise WazuhNotConfigured(tenant_id, "wazuh-api secret missing required keys")

    return WazuhConfig(
        manager_url=cfg.wazuh_url,
        manager_user=mgr_user,
        manager_pass=mgr_pw,
        indexer_url=cfg.wazuh_indexer_url or _derive_indexer_url(cfg.wazuh_url),
        indexer_user=idx_user,
        indexer_pass=idx_pw,
        verify_ssl=cfg.wazuh_verify_ssl,
    )
```

**Schema add for indexer URL.** Add a nullable `wazuh_indexer_url` column to
`integration_configs` (same Alembic migration as the chat-scope changes).

The Wazuh chart deploys the Manager and Indexer as **two distinct Services**:
`wazuh-<slug>-wazuh-manager:55000` and `wazuh-<slug>-wazuh-indexer:9200`. Port
substitution alone (the obvious tempting derivation) does NOT work — the
Manager Service does not listen on 9200.

The resolver therefore prefers the explicit column when set, and otherwise
derives by substituting BOTH the service-name segment and the port:

```python
def _derive_indexer_url(manager_url: str) -> str:
    # https://wazuh-acme-wazuh-manager:55000  →
    # https://wazuh-acme-wazuh-indexer:9200
    return manager_url.replace("-wazuh-manager", "-wazuh-indexer") \
                      .replace(":55000", ":9200")
```

The Phase 5 backfill populates the column for every existing tenant so the
fallback is only ever a safety net. The provisioning controller writes it on
new-tenant bootstrap.

Cached for 5 min per tenant_id (creds + JWT). Cache invalidated on a 401 — re-read
on next call. Same TTL semantics as the existing env-only path.

### K8s client placement

The API pod's ServiceAccount currently can't `get` Secrets in `tenant-<slug>`
namespaces. Add a `ClusterRole` + `RoleBinding` (per-tenant namespace) — same
pattern the provisioning controller already uses to *write* per-tenant secrets.
The chart adds the binding when a tenant is provisioned, so existing tenants
need a one-shot backfill.

The k8s client itself: `kubernetes_asyncio.client.CoreV1Api`. Lazy-load once,
reuse across calls. Connect via in-cluster config (the pod is already in-cluster).

### Provisioning controller hook

When a new tenant is provisioned:

1. Create the per-tenant Wazuh k8s secret (existing).
2. Write the `tenant_secrets` row with `purpose='wazuh-api'`, pointing at it (NEW).
3. Bind the API pod's ServiceAccount to read that namespace's secrets (NEW).
4. Populate `integration_configs.wazuh_url` (existing).

For existing tenants without `tenant_secrets` rows for purpose=`'wazuh-api'`:
a **one-shot ops script** (not an Alembic migration) creates them by listing
each `tenant-<slug>` namespace and reading the standard
`wazuh-<slug>-wazuh-creds` secret (the Wazuh chart renders with the release
prefix `wazuh-<slug>` — see `src/soctalk/core/provisioning/controller.py:289`
`release_wazuh=f"wazuh-{tenant.slug}"`). Keeping this out of Alembic matters
because:

- Migrations run in CI / local-dev / off-cluster upgrade contexts where the
  Kubernetes API is not reachable, and a migration that imports
  `kubernetes_asyncio` and calls the cluster will fail those runs for reasons
  unrelated to schema.
- The reconciliation is naturally idempotent and re-runnable; it doesn't need
  Alembic's once-per-revision semantics.

The script lives at `scripts/ops/backfill_wazuh_tenant_secrets.py` and is also
called by the provisioning controller on the **tenant_secrets reconciliation**
loop (so newly bootstrapped tenants get their row automatically; the script is
the safety net for tenants that were created before this feature shipped).

---

## System prompt updates

Two new prompt variants:

### MSSP fleet prompt

```
You are the SocTalk MSSP analyst copilot. You see ALL tenants. The active
conversation is fleet-scoped: no single tenant is selected by default.

When you call a tool that targets a specific tenant (any wazuh.* tool, any
DB tool except the `fleet_*` roll-ups, get_investigation), you MUST pass
`tenant_slug` explicitly. If you don't know which tenant the user means,
call `list_tenants()` first.

When summarizing results to the user, always cite the tenant slug
("acme-corp: 12 critical alerts in the last 24h"). Do not blend results
across tenants in one bullet.

For broad ("show me the fleet") questions, prefer the `fleet_*` tools.
They return aggregated counts per tenant and are far cheaper than calling
single-tenant tools 50 times.
```

### Tenant-bound MSSP prompt (existing, slightly augmented)

```
… (existing prompt) …

You are scoped to tenant `<slug>` for this conversation. Do not pass
`tenant_slug` to tool calls — it is implicit.
```

---

## UI changes

### `/chat` page

```
Before:                              After:
┌──────────────────────────┐         ┌──────────────────────────┐
│ Conversations            │         │ Conversations            │
├──────────────────────────┤         ├──────────────────────────┤
│ [Open SOC required]      │         │ + New (tenant)           │
│                          │         │ + New (fleet)            │
│ Pin a tenant to use chat │         │                          │
└──────────────────────────┘         │  · "Q3 audit"   [acme]   │
                                     │  · "Fleet vuln"  [Fleet] │
                                     └──────────────────────────┘
```

- `+ New (tenant)` opens the existing tenant-pinning flow when MSSP user has no pin.
- `+ New (fleet)` creates a `scope='mssp_fleet'` conversation. Customer roles don't see this button.
- Conversation list rows show a tenant badge (slug or "Fleet").

### Per-message UI

When a tool call returns with `_tenant.slug` populated, the `ToolCallBadge`
component renders the slug next to the tool name:

```
🔧 wazuh.alert_summary @ acme-corp · 142 alerts
```

For fleet roll-up tools, the badge omits the tenant chip.

### Composer hint

In `mssp_fleet` scope, the composer placeholder reads:

```
Ask about any tenant. Use tenant names ("acme-corp") to scope queries.
```

---

## Phasing

| Phase | Scope                                                      | Effort |
| ----- | ---------------------------------------------------------- | ------ |
| **1** | Schema: scope column + nullable tenant_id + RLS policies + Alembic migration | 0.5 day |
| **2** | API: scope parameter on POST /conversations + cost cap split + tests | 0.5 day |
| **3** | DB tools: tenant_slug param + result `_tenant` projection + `list_tenants` + 3 fleet roll-ups | 0.5 day |
| **4** | Wazuh routing: `_resolve_wazuh_for` + k8s client + tenant_slug on all 14 Wazuh tools + cache | 1 day |
| **5** | Provisioning: split worker into its own Deployment, dedicated API SA, per-tenant Role + RoleBinding (`resourceNames`-narrowed), ops backfill script for existing tenants | 1 day |
| **6** | Frontend: scope-aware conversation create + tenant badges + composer hint | 0.5 day |
| **7** | E2E Playwright: tenant isolation (acme query doesn't see labtenant data, both via DB and via Wazuh) | 0.5 day |

Total ~4.5 dev days.

---

## Risks

1. **K8s RBAC sprawl + ServiceAccount identity.** Two intertwined issues here:

   **(a) The API pod currently runs as `<release>-controller` SA.** See
   `charts/soctalk-system/templates/30-api.yaml:48`. That SA is broad — it has
   helm-install, namespace-create, and secret-write across tenant namespaces.

   **Important coupling**: the API pod ALSO runs the in-process
   `ProvisioningWorker` (see `app_v1._lifespan` lines 88-96, gated by
   `SOCTALK_PROVISIONING_WORKER=1` which is the default). That worker needs
   the broad controller SA to do its Helm / NS / Secret operations on tenant
   bootstrap. If we simply switch the API Deployment to a new narrow `<release>-api`
   SA, tenant provisioning breaks.

   Phase 5 therefore does this as a single coordinated change:

   1. Add a new `<release>-provisioning-worker` Deployment (one replica) that
      runs the same image with `SOCTALK_PROVISIONING_WORKER=1` and a fresh API
      entrypoint that mounts no HTTP router (or simply runs the existing API
      entrypoint with no Service/Ingress in front of it). It binds to the
      existing `<release>-controller` SA.
   2. Set `SOCTALK_PROVISIONING_WORKER=0` on the API Deployment.
   3. Switch the API Deployment to a new dedicated `<release>-api` SA which
      has only the new tenant-scoped wazuh-creds RoleBindings (and whatever
      minimal cluster perms the API actually needs — the metrics scrape, etc;
      currently the API needs none beyond namespace-default).
   4. The controller SA stays bound to the new provisioning-worker Deployment
      and nothing else.

   If splitting the worker is too disruptive for this phase, the **fallback**
   is to leave the API on the controller SA and bind the per-tenant wazuh-creds
   Role to that SA. This gives up the "blast radius is one secret per
   namespace" claim — the API's reach is whatever the controller SA already
   allows — but unblocks the rest of the feature. The plan defaults to the
   split; fallback is documented here so it's an option if Phase 5 needs to
   contract.

   **(b) RBAC cannot scope Secret reads by label.** `resources: ['secrets']`
   grants get on every Secret in the namespace unless `resourceNames` is
   enumerated. We narrow via exact name match.

   The actual Wazuh credentials Secret is rendered by the Wazuh chart with the
   release prefix: `wazuh-<slug>-wazuh-creds` (confirmed in
   `charts/linux-ep/values.yaml` and the wazuh chart's
   `templates/secrets.yaml`). Use that exact name:

   ```yaml
   kind: Role
   metadata:
     namespace: tenant-<slug>
     name: read-wazuh-creds
   rules:
     - apiGroups: [""]
       resources: ["secrets"]
       resourceNames: ["wazuh-<slug>-wazuh-creds"]   # exact match
       verbs: ["get"]
   ---
   kind: RoleBinding
   metadata:
     namespace: tenant-<slug>
     name: api-reads-wazuh-creds
   roleRef:
     kind: Role
     name: read-wazuh-creds
   subjects:
     - kind: ServiceAccount
       name: {{ .Release.Name }}-api   # in soctalk-system NS
       namespace: soctalk-system
   ```

   The provisioning controller writes this Role + RoleBinding pair when
   bootstrapping a tenant (same template the runs-worker token RoleBinding
   uses). Blast radius is exactly one Secret per tenant namespace; the API SA
   cannot read any other secret in that namespace.

2. **Cross-namespace network policies.** The chat path originates from the API
   pod (`soctalk-system` NS, labeled `app.kubernetes.io/component: api`), but
   the tenant chart's `allow-from-soctalk-system` policy currently only permits
   ingress from `app.kubernetes.io/component: orchestrator`. As written, chat
   Wazuh calls will be denied whenever tenant NetworkPolicies are enforced.

   Fix in Phase 5: edit `charts/soctalk-tenant/templates/20-networkpolicies.yaml`
   `allow-from-soctalk-system.ingress[0].from[0].podSelector` to match both
   components:

   ```yaml
   podSelector:
     matchExpressions:
       - key: app.kubernetes.io/component
         operator: In
         values: [orchestrator, api]
   ```

   Ports already include 55000 (Manager) and 9200 (Indexer). One-line chart
   change; rolls out per-tenant on `helm upgrade` of the tenant chart.

3. **Tenant-slug spoofing.** A customer-role user trying to pass `tenant_slug` to
   a tool to peek at another tenant. Mitigated by the resolver: if
   `ctx.scope == 'tenant'` and the slug arg disagrees with the conv's bound tenant,
   the tool returns an error result. The DB-tool layer never sees a non-matching
   slug make it through.

4. **Cost-cap accounting for fleet conversations.** Current cap aggregates by
   `tenant_id`. Fleet convs have `tenant_id IS NULL` so they fall out of the
   tenant cap. Mitigated by the new per-MSSP-user-per-day cap (cf. API section).
   Open question: should fleet convs ALSO bill against the queried tenant's cap?
   Leaning no — keeps fleet querying predictable; MSSP user owns the budget.

5. **`tenant_secrets` row creation race during provisioning.** If a new tenant is
   created and the user immediately opens a fleet chat asking about that tenant
   before the secret row + RoleBinding lands, the tool returns `WazuhNotConfigured`
   with a helpful message ("tenant just provisioned, retry in ~30s"). Not catastrophic.

6. **JWT cache invalidation across tenants.** The current cache is one
   `_ManagerClient` instance with one token. With multi-tenant routing, the cache
   becomes keyed on `tenant_id`. A tenant that rotates its Wazuh password causes
   a 401; the cache evicts that one entry, re-resolves, gets the new password.
   Other tenants are unaffected.

7. **Indexer URL derivation.** Currently env supplies both `WAZUH_URL` (Manager,
   port 55000) and `WAZUH_INDEXER_URL` (port 9200). In the wazuh chart these
   are **two distinct Services** — `wazuh-<slug>-wazuh-manager` and
   `wazuh-<slug>-wazuh-indexer`. The Manager Service does NOT expose 9200;
   port-swap derivation breaks.

   Resolved by adding the nullable `wazuh_indexer_url` column AND requiring it
   to be populated. The Phase 5 ops backfill script writes
   `https://wazuh-<slug>-wazuh-indexer:9200` into the column for every existing
   tenant in the same pass that creates the `tenant_secrets` row. The
   provisioning controller does the same on tenant bootstrap.

   Fallback derivation in the resolver substitutes the service-name segment
   (`-wazuh-manager` → `-wazuh-indexer`) and the port (`55000` → `9200`) rather
   than just port-swapping — covers tenants whose column hasn't been
   backfilled yet. The resolver logs a warning when it falls back, so we can
   spot tenants that drift from the convention.

8. **Audit-log shape change.** Audit rows for chat actions in fleet scope carry
   `tenant_id = NULL`. The audit dashboard's "filter by tenant" needs a "Fleet"
   pseudo-option, otherwise these rows are invisible. Frontend change in Phase 6.

---

## Out of scope (deferred)

- **Wazuh fan-out** ("show me agents across all tenants" calling each Wazuh in
  parallel and aggregating). Plan-shaped: a `fleet_wazuh.agent_counts()` tool that
  runs the manager-side query against every configured tenant Wazuh and returns
  per-tenant counts. Sequential first, parallel later. Phase 4 of the OVERALL
  MSSP roadmap, not Phase 4 of this plan.
- **Cross-tenant joins in DB tools** ("show me the analyst with the most
  approved reviews across all tenants this week"). The role-aware session pattern
  doesn't support it cleanly — needs a dedicated MSSP analytics role + cap.
- **Per-tenant model selection.** Conversation pins one model. A fleet conv hits
  the MSSP's chat model regardless of what each tenant has configured.
- **Tenant-scope migration of existing fleet conversations.** Once created as
  fleet, a conversation stays fleet. No "save as tenant-scoped" button.
- **MISP / Cortex / TheHive per-tenant routing.** Same pattern will apply when
  those tools join the chat surface; for now they're env-config-only.

---

## Open questions for review

1. **Should `tenant_id` on `chat_messages` mirror `conv.tenant_id` strictly?**
   Currently it duplicates the conv's tenant for read-perf on RLS. Same convention
   for NULL? (Lean yes — keeps the table self-describing under RLS.)

2. **Do we expose a "switch slug for this turn" UI affordance**, or rely entirely
   on the model picking the slug? Lean rely-on-model — adding a "queried tenant"
   dropdown above the composer is more UI than this is worth.

3. **Should `fleet_*` tools be available in tenant-scope conversations?**
   Lean **no** — a tenant-bound MSSP chat shouldn't be able to peek at the fleet
   without explicitly switching scope. Hides the slug arg confusion.

4. **Indexer URL: derive or column?** See Risk #7. Need to confirm whether any
   existing deployment runs the Indexer on a separate host from the Manager.

5. **K8s secret read latency.** Adds ~50-200ms to first Wazuh call per tenant per
   5 min. Acceptable? (Lean yes — Wazuh API calls themselves are slower than that.)
