# P0-1: Tenant Security Model

Gate artifact: Principal catalog, actor×resource matrix, RLS policy matrix, Postgres role model, endpoint classification, token claim schemas, audit requirements, secret placement. Drives: `P0-4-postgres-rls.md`, `P0-5-secret-placement.md`, Phase 1 implementation of multi-tenancy, Phase 2 RBAC in charts.

## 1 Principal catalog

Eight principals. See `00-decisions.md` D-07.

| # | Principal | Category | Scope | Authenticates via |
|---|---|---|---|---|
| 1 | **User** (role ∈ {platform_admin, mssp_admin, analyst, customer_viewer}) | Human | Role-derived | Ingress OIDC → SocTalk JWT |
| 2 | **Worker** | SocTalk service (background) | One tenant per job | Service JWT, short-lived, issued by SocTalk API at dispatch |
| 3 | **System** | SocTalk service (cross-tenant ops) | Install-wide, RLS-bypass | Code-path gated; no JWT |
| 4 | **SocTalk K8s ServiceAccount** | SocTalk service (K8s identity) | Cluster, name-convention-scoped to `tenant-*` | K8s projected token |
| 5 | **Tenant adapter** | Data plane sidecar | Single tenant, calls SocTalk API only | Adapter JWT, tenant-scoped, short-lived |
| 6 | **Wazuh agent** | External endpoint agent | Single tenant's Wazuh manager | Wazuh `authd` enrollment → per-agent mTLS |
| 7 | **MSSP cluster admin** | Human, out-of-band | Entire cluster (unbounded) | `kubectl` credentials |
| 8 | **Cloud license issuer** | Trust anchor | Offline signing authority | Ed25519 key in HSM/KMS (V1.5+) |

### 1.1 User roles

| Role | Scope | Typical function |
|---|---|---|
| `platform_admin` | Install-wide | SocTalk upgrades, install settings, audit export, license rotation (V1.5) |
| `mssp_admin` | Cross-tenant | Customer CRUD, user management, cross-tenant reporting, branding |
| `analyst` | Cross-tenant | Triage, approvals, investigation work; auditable impersonation into any tenant |
| `customer_viewer` | Single tenant | Read-only dashboards, incidents, reports, audit trail |

Scope derivation: `role ∈ {platform_admin, mssp_admin, analyst}` ⇒ `tenant_id` NULL in DB, cross-tenant access via elevated Postgres role or explicit impersonation. `role = customer_viewer` ⇒ `tenant_id` required in user row and JWT.

### 1.2 Worker principal discipline (critical)

Every background job **must** carry `tenant_id` in its payload. Worker entrypoints are decorated with `@tenant_scoped_worker` which sets `app.current_tenant_id` before any DB access. Workers connect as `soctalk_app` Postgres role and are **RLS-subject**: forgetting to set context yields zero rows, not cross-tenant leakage.

### 1.3 System principal discipline (critical)

Cross-tenant operations (MSSP rollups, migrations, admin tooling) use the `System` principal via a `system_context()` Python context manager. Entry emits an audit row. The context manager is the single gate. `import-linter` prevents its import outside designated system modules. System principal connects as `soctalk_mssp` Postgres role which has `BYPASSRLS`.

## 2 Resource catalog

### 2.1 Database resources (tenant-scoped)

All have `tenant_id` FK and are subject to RLS:

- `Event`: event store, append-only
- `InvestigationReadModel`: projected investigation state
- `MetricsHourly`, `IOCStats`, `RuleStats`, `AnalyzerStats`: per-tenant projections
- `PendingReview`: HIL queue
- `IntegrationConfig`: per-tenant integration URLs, endpoints, thresholds
- `BrandingConfig`: per-tenant app name, logo, colors
- `TenantSecret`: references (ns + name + version) to K8s Secrets; **no raw material**
- `TenantLifecycleEvent`: append-only log of tenant state transitions, config revisions
- `AuditLog`: append-only log of mutation actions, with `mssp_user_id` when performed via impersonation

### 2.2 Database resources (install-scoped, non-tenant)

No `tenant_id`; Organization-scoped or global:

- `Organization`: install-wide (mssp_id, mssp_name, install_id, install_label, reserved license_jwt)
- `User`: includes both MSSP-side users (nullable tenant_id) and customer users (tenant_id required)
- `MSSPUser`/`TenantUser` semantics derived from role + tenant_id presence; single table
- `Release`: SocTalk version metadata (install-wide)
- Install settings (feature flags, system-wide toggles)

### 2.3 Kubernetes resources

| Resource | Scope | Managed by |
|---|---|---|
| Namespace `soctalk-system` | Install-level | MSSP cluster admin (created by Helm) |
| Namespace `tenant-<slug>` | Per tenant | SocTalk K8s ServiceAccount (cluster verbs) |
| `Deployment`, `Service`, `PVC`, `Secret`, `ConfigMap`, `NetworkPolicy`, `ResourceQuota`, `LimitRange`, `ServiceAccount`, `Role`, `RoleBinding` in tenant-* | Per tenant | SocTalk K8s ServiceAccount |

### 2.4 API endpoints (classification)

See section 5.

### 2.5 Secrets

See section 9 and `P0-5-secret-placement.md`.

## 3 Actor × resource matrix

Matrix is expressed as allowed actions per (principal, resource-group). `R`=read, `W`=write, `-`=deny.

| Resource group | `platform_admin` | `mssp_admin` | `analyst` | `customer_viewer` | `Worker` | `System` | `SocTalk K8s SA` | `Tenant adapter` |
|---|---|---|---|---|---|---|---|---|
| Tenant-scoped DB (own tenant) | RW (any) | RW (any) | RW (any) | R (own) | RW (job's tenant) | RW (any via bypass) | | - |
| Install-scoped DB (Organization, Release, settings) | RW | R (minus license) | R | | R | RW | | - |
| User management (MSSP-side) | RW | R (+ invite) | R | | - | RW | | - |
| User management (tenant-side, within own tenant) | RW | RW | | R self | | - | | - |
| Audit log (own tenant) | R all | R all | R all | R own | W | W | | W (via bootstrap) |
| License material (V1.5) | R | | - | | - | R | | - |
| K8s namespaces `tenant-*` | (via API only) | (via API only) | (via API only) | | - | | CRUD | |
| K8s resources within tenant-* | (via API only) | (via API only) | (via API only) | | - | | CRUD | R self |
| K8s resources in `soctalk-system` | | - | | - | | - | R (own ns) | |
| Per-tenant LLM Secret | | - | | - | R (own tenant) | | mount | |
| Per-tenant integration Secrets (Wazuh/TheHive/Cortex API creds) | | - | | - | R (own tenant) | | mount | |
| Cloud telemetry (V1.5) | | - | | - | W (anonymized aggregate) | W | | - |

Notes:
- "via API only" means the human principal triggers K8s operations by calling SocTalk API endpoints, not directly. API handlers use the SocTalk K8s ServiceAccount.
- `analyst` acting on a tenant writes audit rows with both `user_id` and the tenant's `tenant_id`: Customer-side audit view shows these as impersonation entries.
- `Worker` reads tenant-scoped Secrets via K8s mount when orchestrator pod needs per-tenant LLM key for the tenant it's currently processing. Mount strategy: projected per-tenant at orchestrator startup if small enough, or env-var rotation per job dispatch for larger fleets (V1.5 decision).

## 4 RLS policy matrix

See `P0-4-postgres-rls.md` for SQL. Summary:

| Table | Policy | `USING` | `WITH CHECK` |
|---|---|---|---|
| All tenant-scoped tables | `tenant_isolation` | `tenant_id = current_setting('app.current_tenant_id')::uuid` | same |
| `User` (where `tenant_id IS NOT NULL`) | same | same | same |
| `AuditLog` | `audit_read` | same for read; writes allowed from Worker + System | same |
| Install-scoped tables | no RLS | | - |

All tenant-scoped tables have `FORCE ROW LEVEL SECURITY` so table owner (`soctalk_admin`) is also RLS-subject. System principal uses `soctalk_mssp` role (`BYPASSRLS`) to intentionally cross-tenant.

## 5 API endpoint classification

Three categories. Never one endpoint that serves two categories.

### 5.1 `/api/mssp/*`. MSSP-side (requires `platform_admin` | `mssp_admin` | `analyst`)

Cross-tenant capable. When a handler needs cross-tenant visibility (rollups, fleet views), it uses the `System` principal through `system_context()`. When a handler acts on a specific tenant (impersonation), it sets `app.current_tenant_id` and stays RLS-subject.

Examples: `POST /api/mssp/tenants`, `GET /api/mssp/tenants`, `POST /api/mssp/impersonate/:tenant_id`, `GET /api/mssp/audit`, `POST /api/mssp/users`, `GET /api/mssp/fleet/summary`.

### 5.2 `/api/tenant/*`. Tenant-side (requires `customer_viewer`)

Hard-scoped. Tenant context from JWT; no impersonation entry. All queries RLS-enforced via `soctalk_app`: Read-only in V1 (except user self-service).

Examples: `GET /api/tenant/overview`, `GET /api/tenant/incidents`, `GET /api/tenant/reports`, `GET /api/tenant/audit`, `GET /api/tenant/branding`.

### 5.3 `/api/internal/*`. Service-to-service (requires Worker JWT or Adapter JWT)

Not user-facing. Short-lived service JWTs with explicit tenant context. Examples: `POST /api/internal/adapter/health`, `POST /api/internal/adapter/bootstrap`, `GET /api/internal/adapter/config`.

No endpoint accepts both `/api/mssp/*` and `/api/tenant/*` semantics. If a capability is needed on both sides, it is implemented as two endpoints with different authz and different context flows.

## 6 Token claim schemas

### 6.1 MSSP-side User JWT (issued by SocTalk after ingress OIDC handoff)

```json
{
  "iss": "soctalk",
  "sub": "user_<uuid>",
  "iat": 1713475200,
  "exp": 1713478800,
  "jti": "<uuid>",
  "user_type": "mssp",
  "role": "platform_admin | mssp_admin | analyst",
  "current_tenant": null
}
```

When an `mssp_admin` or `analyst` enters tenant context, a new short-lived token is minted with `current_tenant: "<tenant_uuid>"`. Impersonation tokens have max 30-minute TTL and are logged at mint time.

### 6.2 Tenant-side User JWT

```json
{
  "iss": "soctalk",
  "sub": "user_<uuid>",
  "iat": 1713475200,
  "exp": 1713478800,
  "jti": "<uuid>",
  "user_type": "tenant",
  "role": "customer_viewer",
  "tenant_id": "<tenant_uuid>"
}
```

### 6.3 Worker service JWT

```json
{
  "iss": "soctalk",
  "sub": "worker",
  "iat": ...,
  "exp": ...,
  "jti": "<uuid>",
  "user_type": "worker",
  "tenant_id": "<tenant_uuid>",
  "job_id": "<uuid>",
  "job_type": "triage | enrich | decide | ..."
}
```

### 6.4 Adapter JWT

```json
{
  "iss": "soctalk",
  "sub": "adapter",
  "iat": ...,
  "exp": ...,
  "jti": "<uuid>",
  "user_type": "adapter",
  "tenant_id": "<tenant_uuid>",
  "scope": "adapter"
}
```

Adapter JWTs are refreshed weekly; rotation is a SocTalk-controller-side secret rewrite in the tenant namespace.

### 6.5 License JWT (V1.5: reserved schema)

```json
{
  "iss": "https://cloud.soctalk.io",
  "sub": "mssp_<uuid>",
  "install_id": "install_<uuid>",
  "aud": "soctalk-install",
  "iat": ..., "nbf": ..., "exp": ...,
  "jti": "<uuid>",
  "ver": 1,
  "tier": "starter | pro | enterprise",
  "features": ["white_label", "offline_llm", "custom_mcp", ...],
  "end_client_cap": 50,
  "install_cap": 50,
  "channel": "stable | beta"
}
```

Signed with Ed25519 (alg=EdDSA). Header includes `kid` for key identifier. JWKS distributed via ConfigMap in `soctalk-system`: Not enforced in V1; schema reserved for forward compatibility.

## 7 Audit requirements

Every mutation writes an `AuditLog` row with:

- `id` (uuid), `timestamp`, `tenant_id` (nullable for install-scoped events)
- `actor_principal` (User | Worker | System | Adapter)
- `actor_id` (user_id | "worker:<job_id>" | "system:<reason>" | adapter's tenant_id)
- `action` (enum: `tenant.create`, `tenant.suspend`, `investigation.approve`, `settings.update`, `user.impersonate`, ...)
- `resource_type`, `resource_id`
- `before`, `after` (JSON snapshots for state-changing actions)
- `acting_as` (nullable; set when `mssp_admin`/`analyst` is impersonating a tenant)
- `request_id` (correlates with log lines)

Retention: 90 days in V1, configurable per-install in V1.5. Customer can view audit rows where `tenant_id = own` including entries with `acting_as` populated (transparency into MSSP actions).

MSSP cross-tenant audit view runs under `System` principal.

## 8 Degraded-mode operation allowlist (V1.5 when licensing lands)

V1 has no license enforcement. When licensing lands, expired-license behavior is:

| Operation | Works when license expired? |
|---|---|
| Existing-tenant alert ingestion | Yes |
| Existing-tenant triage + LLM calls | Yes |
| Existing pending-review HIL approvals | Yes |
| Customer UI read/view | Yes |
| Existing audit log writes | Yes |
| Case creation in TheHive via MCP | Yes |
| Data plane (Wazuh/TheHive/Cortex) running | Yes (license not read by data plane) |
| New tenant creation | **No** |
| Tenant upgrade | **No** |
| Enterprise features | **No** (per `features[]`) |
| New user creation | **No** |

## 9 Secret placement

Summary; full matrix in `P0-5-secret-placement.md`.

| Secret | Location | Accessed by | Rotation |
|---|---|---|---|
| Per-tenant LLM API key | K8s Secret in `soctalk-system`, named `tenant-<id>-llm` | Worker (mount, per-tenant projection) | MSSP-initiated via tenant config UI |
| Per-tenant integration creds (Wazuh API, TheHive token, Cortex key) | K8s Secret in `soctalk-system`, named `tenant-<id>-integrations` | Worker (MCP subprocess env) | MSSP-initiated via tenant config UI |
| Data plane service bootstrap creds (Wazuh admin pw, TheHive init token, Cortex admin key) | K8s Secret in respective `tenant-<slug>` ns | Respective data plane Deployment | Runbook (V1); automated V1.5 |
| Adapter token signing key | K8s Secret in `soctalk-system`, named `soctalk-adapter-signing-key` | SocTalk API + controller pod only | Manual V1; automated rotation V1.5 |
| Tenant adapter bearer token | K8s Secret in respective `tenant-<slug>` ns, named `adapter-token` | Tenant adapter only | Minted on tenant provisioning; rotated by controller |
| User-facing session/JWT signing key | K8s Secret in `soctalk-system`, named `soctalk-jwt-signing-key` | SocTalk API pod | Manual V1; rotation procedure in V1.5 |
| Postgres credentials | K8s Secret in `soctalk-system`, named `soctalk-postgres-creds` (three entries: admin, app, mssp) | Respective SocTalk pods | Manual V1 |
| License material (V1.5) | K8s Secret in `soctalk-system`, named `soctalk-license` | SocTalk API pod (read on startup, re-read on SIGHUP) | Issued by Cloud (V1.5); dropped into Secret manually V1.5 |

**Invariant**: raw secret material never in Postgres. `TenantSecret` table stores `(namespace, name, version_label)` tuples only.

## 10 Known architectural limits

- **MSSP cluster admin trust**: principal #7 has unbounded K8s access. SocTalk's isolation model presumes this principal is trusted. Customers requiring defense against insider threat at MSSP level need dedicated-node/dedicated-VM tiering (V2+).
- **Admission boundary scope**: V1 constrains the SocTalk controller ServiceAccount with `ValidatingAdmissionPolicy` for tenant namespaces and namespaced resource mutations, but MSSP cluster-admin users remain trusted break-glass operators. Kyverno is an optional V1.5 hardening path.
- **No license enforcement (V1)**: license JWT and feature gates deferred to V1.5. Pilot MSSPs operate on honor.
- **LLM response cache**: keyed on `(tenant_id, prompt_hash)` from day 1. If ever relaxed, cross-tenant content leak risk; test suite asserts the key composition.
- **SSE subscriptions**: tenant-scoped at subscription time. Connection-persistence bugs could deliver cross-tenant events on a stale subscription; explicit SSE isolation test in Phase 1 gate.
- **Worker context leakage**: every worker entrypoint must set `app.current_tenant_id`: Defensive default is zero rows under RLS, not cross-tenant leakage, but test suite asserts the defense.

## 11 Test requirements (mandated for Phase 1 gate)

1. **Cross-tenant API probe**: for every `/api/tenant/*` and `/api/mssp/*` endpoint that accesses tenant-scoped data, craft requests as tenant A that attempt reads/writes of tenant B resources. Assert 0 rows or 403.
2. **Raw-SQL RLS probe**: connect as `soctalk_app`, set `app.current_tenant_id = A`, execute `SELECT * FROM events` (unfiltered); assert only tenant A rows returned.
3. **Worker context default**: dispatch a worker job without setting tenant context; assert queries return 0 rows (defensive-zero behavior).
4. **SSE isolation**: subscribe as tenant A to the events SSE; mutate in tenant B; assert no event delivered on A's stream.
5. **LLM cache isolation**: trigger identical prompts from tenant A and tenant B; assert cache misses on second call for B (different key) and hits on third call for A (same key).
6. **Impersonation audit**: as `mssp_admin`, impersonate tenant A, perform a mutation; assert `AuditLog` row exists with `acting_as=<mssp_admin_id>` and `tenant_id=A`; assert customer user in A can read the row.
7. **System context audit**: trigger an `/api/mssp/fleet/summary` call; assert audit row for system-context entry with reason.

Tests are part of the Phase 1 gate. None optional.
