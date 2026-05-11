# postgres-rls: Postgres RLS Hygiene

Gate artifact: Defines the three-role Postgres model, RLS policy templates, `FORCE ROW LEVEL SECURITY` discipline, and the isolation test template mandated for the release gate.

## 1 Roles

Three Postgres roles. No application ever connects as `postgres` superuser.

| Role | Purpose | Used by | DDL? | BYPASSRLS? |
|---|---|---|---|---|
| `soctalk_admin` | Table owner; used only by Alembic at migration time | Alembic (run via a dedicated Kubernetes Job at deploy) | Yes | No |
| `soctalk_app` | Runtime application role | SocTalk API pods, orchestrator pods, worker jobs: all "normal" traffic | No | No |
| `soctalk_mssp` | Cross-tenant elevated role | `System` principal via `system_context()` only | No | **Yes** |

Rationale for three roles (not two): `soctalk_admin` can neither run at app time (too much privilege) nor bypass RLS unintentionally. `soctalk_app` is RLS-subject so application bugs can't leak cross-tenant. `soctalk_mssp` is intentionally cross-tenant but segregated to audited code paths only.

## 2 Role DDL

Created in the initial migration:

```sql
-- roles
CREATE ROLE soctalk_admin LOGIN PASSWORD :'admin_pw';
CREATE ROLE soctalk_app   LOGIN PASSWORD :'app_pw';
CREATE ROLE soctalk_mssp  LOGIN PASSWORD :'mssp_pw' BYPASSRLS;

-- db ownership
ALTER DATABASE soctalk OWNER TO soctalk_admin;

-- default privileges so future tables created by soctalk_admin are granted appropriately
ALTER DEFAULT PRIVILEGES FOR ROLE soctalk_admin
  IN SCHEMA public
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO soctalk_app;

ALTER DEFAULT PRIVILEGES FOR ROLE soctalk_admin
  IN SCHEMA public
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO soctalk_mssp;

ALTER DEFAULT PRIVILEGES FOR ROLE soctalk_admin
  IN SCHEMA public
  GRANT USAGE, SELECT ON SEQUENCES TO soctalk_app, soctalk_mssp;
```

Credentials stored in K8s Secrets under `soctalk-system`:
- `soctalk-postgres-admin-creds`: mounted only to the Alembic Job
- `soctalk-postgres-app-creds`: mounted to SocTalk API + orchestrator pods
- `soctalk-postgres-mssp-creds`: mounted to SocTalk API pod only (read by `system_context()` factory)

## 3. `FORCE ROW LEVEL SECURITY`: why

Default Postgres behavior: **table owners and superusers bypass RLS automatically**. Without `FORCE ROW LEVEL SECURITY`, `soctalk_admin` (the owner) would not be subject to policies, but `soctalk_admin` runs migrations, and a migration that reads tenant-scoped data to transform it could accidentally cross tenants.

Applying `ALTER TABLE <t> FORCE ROW LEVEL SECURITY` makes even the owner RLS-subject. Migrations that intentionally need cross-tenant access must either:
1. Temporarily grant themselves `BYPASSRLS` (privileged, audited), or
2. Set `app.current_tenant_id` explicitly before each access (preferred for per-tenant data transforms).

## 4 Session variables

SocTalk sets `app.current_tenant_id` (a custom GUC) per transaction. Policies reference it via `current_setting('app.current_tenant_id', true)`. The `true` second argument returns NULL if unset (rather than erroring), which keeps isolation tests clean.

Middleware :

```python
async def tenant_context_middleware(request, call_next):
    tenant_id = resolve_tenant_from_request(request)  # from JWT
    async with db_session_factory() as session:
        if tenant_id is not None:
            # ``SET LOCAL`` does not accept bind parameters in PostgreSQL.
            # ``set_config(name, value, is_local)`` is the parameterisable
            # equivalent (``is_local=true`` gives ``SET LOCAL`` semantics).
            await session.execute(
                text("SELECT set_config('app.current_tenant_id', :tid, true)"),
                {"tid": str(tenant_id)}
            )
        request.state.db = session
        response = await call_next(request)
    return response
```

``set_config(..., true)`` is transaction-scoped; there is no connection pollution across requests.

## 5 Policy template (applied to every tenant-scoped table)

For every tenant-scoped table, the migration applies the following:

```sql
ALTER TABLE <table> ENABLE ROW LEVEL SECURITY;
ALTER TABLE <table> FORCE ROW LEVEL SECURITY;

-- Read + mutate policy: tenant match
CREATE POLICY <table>_tenant_isolation ON <table>
  FOR ALL
  TO soctalk_app
  USING (tenant_id = current_setting('app.current_tenant_id', true)::uuid)
  WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true)::uuid);

-- soctalk_admin: subject to FORCE RLS. Owner explicitly gets no privilege exception.
-- soctalk_mssp: BYPASSRLS role-level; policies not consulted.
```

### 5.1 Tenant-scoped tables (applied to each)

- `investigations` (renamed from `InvestigationReadModel`)
- `events`
- `metrics_hourly`
- `ioc_stats`, `rule_stats`, `analyzer_stats`
- `pending_reviews`
- `integration_configs`
- `branding_configs`
- `tenant_secrets`
- `tenant_lifecycle_events`
- `audit_log`
- `users` (conditional policy: see §5.2)

### 5.2 `users` table conditional policy

Users table holds both MSSP-side users (tenant_id NULL) and tenant-side users (tenant_id set). Policy:

```sql
CREATE POLICY users_tenant_or_null ON users
  FOR ALL
  TO soctalk_app
  USING (
    tenant_id IS NULL
    OR tenant_id = current_setting('app.current_tenant_id', true)::uuid
  )
  WITH CHECK (
    tenant_id IS NULL
    OR tenant_id = current_setting('app.current_tenant_id', true)::uuid
  );
```

MSSP-side users are visible to any context (needed for join operations in MSSP-API handlers operating under `soctalk_mssp`/`System` principal). Tenant users require tenant context.

## 6 Install-scoped tables (no RLS)

These have no `tenant_id` and no RLS:

- `organizations`
- `releases`
- `install_settings`
- (optional) `feature_flags`

`GRANT SELECT` to `soctalk_app`; `INSERT/UPDATE/DELETE` limited to `soctalk_mssp` for most (MSSP admins modify via API under `System` context).

## 7 Idempotency key scoping

Event store's idempotency key must be composite:

```sql
ALTER TABLE events DROP CONSTRAINT events_idempotency_key_unique;
ALTER TABLE events ADD CONSTRAINT events_tenant_idempotency_unique
  UNIQUE (tenant_id, idempotency_key);
```

Reason: absent this, an external alert ID collision between two tenants would cause a cross-tenant event reject/duplicate. With composite key, each tenant has its own idempotency namespace.

## 8 Migration phasing

Migrations land in this order (Alembic revisions):

1. `add_tenants_and_organizations`: create `tenants`, `organizations`, seed default MSSP row for the install.
2. `add_tenant_id_to_core_tables`: add nullable `tenant_id` columns to existing tenant-scoped tables.
3. `backfill_tenant_id`: if any existing data: associate with a "default tenant" for migration continuity; has no existing data to worry about in a greenfield pilot, but the migration path exists.
4. `make_tenant_id_not_null`: once backfilled, tighten constraint.
5. `enable_rls_on_tenant_scoped_tables`: apply policies, FORCE RLS.
6. `create_postgres_roles`: idempotent role creation (guarded by `DO $$ BEGIN ... EXCEPTION ... END $$;` blocks).
7. `convert_idempotency_keys_to_composite`: drop+recreate unique constraint.
8. `add_new_tenant_scoped_tables` creates `audit_log`, `tenant_lifecycle_events`, `integration_configs`, `branding_configs`, and `tenant_secrets`.

All migrations forward-only. Each migration must include a test that asserts RLS behavior post-apply. Rollback strategy: restore from pre-migration Postgres dump (backup/restore runbook); no `downgrade()` Alembic functions in this release (to avoid giving a false sense of clean reversal).

## 9 Isolation test template (gate)

### Test 1 Application endpoint probe

For every endpoint in `/api/tenant/*` and `/api/mssp/*`:

```python
async def test_no_cross_tenant_access(client, seed_two_tenants):
    tenant_a, tenant_b = seed_two_tenants
    # authenticate as tenant A user
    resp = await client.get("/api/tenant/investigations",
                            headers={"Authorization": f"Bearer {tenant_a.token}"})
    data = resp.json()
    assert all(item["tenant_id"] == str(tenant_a.id) for item in data["items"])
    assert not any(item["tenant_id"] == str(tenant_b.id) for item in data["items"])
```

### Test 2 Raw SQL under `soctalk_app`

```python
async def test_raw_sql_respects_rls():
    async with app_connection() as conn:
        # ``SET LOCAL`` does not accept bind parameters; ``set_config`` is
        # the parameterisable equivalent (``is_local=true`` gives the same
        # transaction-scoped semantics).
        await conn.execute(
            text("SELECT set_config('app.current_tenant_id', :tid, true)"),
            {"tid": str(tenant_a.id)},
        )
        result = await conn.execute(text("SELECT tenant_id FROM events"))
        rows = result.fetchall()
        for row in rows:
            assert row.tenant_id == tenant_a.id
        # Also verify: unset context yields zero rows (defensive-zero)
    async with app_connection() as conn:
        # no SET LOCAL
        result = await conn.execute(text("SELECT count(*) FROM events"))
        assert result.scalar() == 0
```

### Test 3 Worker context default

```python
async def test_worker_without_context_sees_nothing():
    # dispatch a worker function without setting context
    @tenant_scoped_worker
    async def hostile_worker(state):
        # intentionally does NOT set context (simulates a bug)
        # Decorator should reject or queries should return 0 rows
        result = await db.execute(select(Event))
        return result.all()
    # Worker decorator raises if tenant_id not in state
    with pytest.raises(MissingTenantContext):
        await hostile_worker({})
    # If decorator defensive-zeros instead, assert zero rows
```

### Test 4 FORCE RLS catches owner

```python
async def test_admin_role_is_rls_subject():
    async with admin_connection() as conn:
        # no SET LOCAL app.current_tenant_id
        result = await conn.execute(text("SELECT count(*) FROM events"))
        assert result.scalar() == 0  # admin is NOT bypassing
```

### Test 5 MSSP role can bypass intentionally

```python
async def test_mssp_role_bypasses_for_rollup():
    async with mssp_connection() as conn:
        result = await conn.execute(text("SELECT count(*) FROM events"))
        # mssp role sees all events across tenants
        assert result.scalar() == total_events_across_tenants
```

### Test 6 SSE stream isolation

```python
async def test_sse_no_cross_tenant_delivery(ws_client):
    sub_a = await ws_client.subscribe("/api/tenant/events/stream",
                                      token=tenant_a.token)
    # trigger an event in tenant B
    await inject_event(tenant_b, "test.event")
    # wait a short period; assert no message delivered on sub_a
    with pytest.raises(asyncio.TimeoutError):
        await asyncio.wait_for(sub_a.receive(), timeout=2.0)
```

### Test 7 Idempotency isolation

```python
async def test_idempotency_key_per_tenant():
    # same external idempotency_key in two tenants must not collide
    await insert_event(tenant_a, idempotency_key="ext-123")
    await insert_event(tenant_b, idempotency_key="ext-123")  # should succeed
    # but a duplicate within same tenant should fail
    with pytest.raises(IntegrityError):
        await insert_event(tenant_a, idempotency_key="ext-123")
```

All seven tests are required to pass for the release gate. No optional.

## 10 Operational notes

- **Connection pools**: separate pool per role. SocTalk API has two pools (`soctalk_app` and `soctalk_mssp`); worker pod has one (`soctalk_app`): Alembic Job uses a throwaway connection as `soctalk_admin`.
- **Logging**: every connection logs its role (in `pg_stat_activity.usename`): Operators can audit which role is running which query.
- **Superuser access**: Postgres superuser exists but is only used for break-glass debugging, not by any application code. Credentials stored separately and rotated after use.

## 11 Gate criteria

- [x] This document merged as reference.
- [ ] Alembic migrations implement role DDL, policies, FORCE RLS, composite idempotency keys.
- [ ] tests suite includes tests 1–7 above and passes.
- [ ] Secret generation for three Postgres credentials is part of `soctalk-system` chart install.
