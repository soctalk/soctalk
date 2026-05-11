"""Mandatory V1 isolation tests (postgres-rls §9).

These are the Phase 1 gate tests: all must pass before Phase 2 begins.

Tests:
1. Raw SQL under soctalk_app respects RLS per tenant context.
2. Raw SQL with no tenant context returns zero rows (defensive-zero).
3. soctalk_admin is subject to FORCE RLS (not a bypass).
4. soctalk_mssp bypasses for cross-tenant rollups.
5. Idempotency key is per-tenant composite.
6. System context entry emits an audit row.
7. SSE isolation is covered by API integration tests.

Tests that need the running FastAPI app (endpoint cross-tenant probe, SSE
isolation, worker context default, impersonation audit, LLM cache) live in
``test_api_isolation.py`` and are marked ``@pytest.mark.integration``.
"""

from __future__ import annotations

import os
from uuid import uuid4

import pytest
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

SKIP_INTEGRATION = os.getenv("SKIP_INTEGRATION", "0") == "1"

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        SKIP_INTEGRATION,
        reason="SKIP_INTEGRATION set; V1 RLS tests require Postgres",
    ),
]


async def test_raw_sql_respects_rls(app_session: AsyncSession, seed_two_tenants):
    """postgres-rls Test 2. ``soctalk_app`` query under tenant context returns only
    that tenant's rows."""
    tenant_a, tenant_b = seed_two_tenants

    # Insert events for both tenants via admin (seed is already in place;
    # augment with more events so the count is non-trivial).
    # Insert directly with SQL bypassing models for speed.

    # Set context to tenant A and assert only A's events visible. ``SET
    # LOCAL`` itself does not accept bind parameters; ``set_config`` is the
    # parameterisable equivalent.
    await app_session.execute(
        text("SELECT set_config('app.current_tenant_id', :tid, true)"),
        {"tid": str(tenant_a.tenant_id)},
    )
    result = await app_session.execute(
        text("SELECT tenant_id FROM integration_configs")
    )
    rows = result.fetchall()
    assert all(row.tenant_id == tenant_a.tenant_id for row in rows), (
        "soctalk_app with tenant_a context returned non-A rows"
    )
    assert len(rows) == 1, f"expected 1 row for tenant_a, got {len(rows)}"


async def test_raw_sql_without_context_is_defensive_zero(
    app_session: AsyncSession, seed_two_tenants
):
    """postgres-rls Test 2b: no ``SET LOCAL`` → zero rows under RLS policy."""
    # Do NOT set app.current_tenant_id on this transaction.
    result = await app_session.execute(
        text("SELECT count(*) FROM integration_configs")
    )
    count = result.scalar()
    assert count == 0, f"expected defensive-zero, got count={count}"


async def test_audit_log_respects_rls(
    app_session: AsyncSession,
    mssp_session: AsyncSession,
    seed_two_tenants,
):
    """Tenant audit rows are isolated like other tenant-scoped tables."""
    tenant_a, tenant_b = seed_two_tenants
    action = f"test.audit.{uuid4()}"

    await mssp_session.execute(
        text("""
            INSERT INTO audit_log (id, tenant_id, actor_principal, actor_id, action)
            VALUES
              (gen_random_uuid(), :tenant_a, 'system', 'test', :action),
              (gen_random_uuid(), :tenant_b, 'system', 'test', :action)
        """),
        {
            "tenant_a": str(tenant_a.tenant_id),
            "tenant_b": str(tenant_b.tenant_id),
            "action": action,
        },
    )
    await mssp_session.commit()

    await app_session.rollback()
    await app_session.execute(
        text("SELECT set_config('app.current_tenant_id', :tid, true)"),
        {"tid": str(tenant_a.tenant_id)},
    )
    rows = (await app_session.execute(
        text("SELECT tenant_id FROM audit_log WHERE action = :action"),
        {"action": action},
    )).all()

    assert [row.tenant_id for row in rows] == [tenant_a.tenant_id]


async def test_admin_role_is_rls_subject(
    admin_session: AsyncSession, seed_two_tenants
):
    """postgres-rls Test 4. FORCE RLS makes the table owner RLS-subject too.

    Note: the admin session already ran seeding above in the fixture, which
    doesn't violate RLS because fixtures use the admin role on a freshly-
    migrated schema where the seed inserts are allowed by the (tenant_id IS
    NULL OR matches) policy for organizations/tenants/users (install-scoped)
    and by explicit SET LOCAL for tenant-scoped rows.
    """
    # With no tenant context set, a SELECT against a tenant-scoped table
    # under admin role should return zero rows (FORCE RLS).
    # We use a fresh session-less query to avoid inheriting any prior
    # SET LOCAL on the fixture session.
    await admin_session.rollback()  # discard any prior txn state
    result = await admin_session.execute(
        text("SELECT count(*) FROM integration_configs")
    )
    count = result.scalar()
    assert count == 0, (
        f"admin role NOT RLS-subject: saw {count} rows without context "
        "(expected 0 under FORCE ROW LEVEL SECURITY)"
    )


async def test_mssp_role_bypasses_for_rollup(
    mssp_session: AsyncSession, seed_two_tenants
):
    """postgres-rls Test 5. BYPASSRLS role sees all tenants."""
    result = await mssp_session.execute(
        text("SELECT count(*) FROM integration_configs")
    )
    count = result.scalar()
    assert count == 2, (
        f"mssp role should see both tenants' config rows; got {count}"
    )


async def test_idempotency_key_per_tenant(
    mssp_session: AsyncSession, seed_two_tenants
):
    """postgres-rls Test 7: same external idempotency_key in two tenants must not collide.

    Uses ``mssp_session`` (BYPASSRLS) because the ``events`` policy only grants
    ``soctalk_app`` — admin role has no matching policy and FORCE RLS denies
    by default. In production, event inserts happen under the app role within
    a worker's tenant context, which is tested separately.
    """
    tenant_a, tenant_b = seed_two_tenants
    shared_key = "ext-123"

    # Tenant A: insert event with shared key.
    await mssp_session.execute(
        text("""
            INSERT INTO events (id, aggregate_id, aggregate_type, event_type, version,
                                timestamp, data, event_metadata, idempotency_key, tenant_id)
            VALUES (gen_random_uuid(), gen_random_uuid(), 'Investigation', 'test', 1,
                    now(), '{}'::jsonb, '{}'::jsonb, :k, :t)
        """),
        {"k": shared_key, "t": str(tenant_a.tenant_id)},
    )
    # Tenant B: same key: should SUCCEED because composite index is (tenant_id, key).
    await mssp_session.execute(
        text("""
            INSERT INTO events (id, aggregate_id, aggregate_type, event_type, version,
                                timestamp, data, event_metadata, idempotency_key, tenant_id)
            VALUES (gen_random_uuid(), gen_random_uuid(), 'Investigation', 'test', 1,
                    now(), '{}'::jsonb, '{}'::jsonb, :k, :t)
        """),
        {"k": shared_key, "t": str(tenant_b.tenant_id)},
    )
    await mssp_session.commit()

    # Second insert in tenant A with same key MUST fail (unique violation).
    with pytest.raises(IntegrityError):
        await mssp_session.execute(
            text("""
                INSERT INTO events (id, aggregate_id, aggregate_type, event_type, version,
                                    timestamp, data, event_metadata, idempotency_key, tenant_id)
                VALUES (gen_random_uuid(), gen_random_uuid(), 'Investigation', 'test', 2,
                        now(), '{}'::jsonb, '{}'::jsonb, :k, :t)
            """),
            {"k": shared_key, "t": str(tenant_a.tenant_id)},
        )
        await mssp_session.commit()
    await mssp_session.rollback()


async def test_system_context_emits_audit_row(mssp_session: AsyncSession):
    """security-model §7: entering system_context writes an audit row."""
    from soctalk.core.tenancy.context import system_context

    async with system_context(mssp_session, reason="test.system_ctx"):
        result = await mssp_session.execute(
            text("SELECT count(*) FROM audit_log WHERE action='system.context.enter'")
        )
        count = result.scalar()
        assert count >= 1, "system_context should emit an audit row"


async def test_soctalk_roles_attributes(admin_session: AsyncSession):
    """Make role attributes explicit so the RLS tests' premises are recorded.

    ``soctalk_admin`` must NOT be SUPERUSER or BYPASSRLS (otherwise
    ``test_admin_role_is_rls_subject`` becomes a no-op).
    ``soctalk_app``   must NOT be BYPASSRLS (RLS must actually bite).
    ``soctalk_mssp``  must be BYPASSRLS (system-context relies on it).
    """
    rows = (await admin_session.execute(
        text(
            "SELECT rolname, rolsuper, rolbypassrls FROM pg_roles "
            "WHERE rolname IN ('soctalk_admin','soctalk_app','soctalk_mssp') "
            "ORDER BY rolname"
        )
    )).all()
    attrs = {r[0]: (r[1], r[2]) for r in rows}

    assert attrs["soctalk_admin"] == (False, False), \
        f"soctalk_admin must be NOSUPERUSER NOBYPASSRLS, got {attrs['soctalk_admin']}"
    assert attrs["soctalk_app"] == (False, False), \
        f"soctalk_app must be NOSUPERUSER NOBYPASSRLS, got {attrs['soctalk_app']}"
    assert attrs["soctalk_mssp"] == (False, True), \
        f"soctalk_mssp must be NOSUPERUSER BYPASSRLS, got {attrs['soctalk_mssp']}"


async def test_with_check_blocks_cross_tenant_insert(
    app_session: AsyncSession, seed_two_tenants
):
    """RLS ``WITH CHECK`` blocks cross-tenant inserts under ``soctalk_app``."""
    tenant_a, tenant_b = seed_two_tenants

    # Context set to tenant A.
    await app_session.execute(
        text("SELECT set_config('app.current_tenant_id', :tid, true)"),
        {"tid": str(tenant_a.tenant_id)},
    )
    # Attempting to INSERT into tenant B's namespace must fail WITH CHECK.
    import pytest
    from sqlalchemy.exc import ProgrammingError

    with pytest.raises(ProgrammingError):
        await app_session.execute(
            text("""
                INSERT INTO events (id, aggregate_id, aggregate_type, event_type,
                                    version, timestamp, data, event_metadata,
                                    idempotency_key, tenant_id)
                VALUES (gen_random_uuid(), gen_random_uuid(), 'Investigation',
                        'test', 1, now(), '{}'::jsonb, '{}'::jsonb,
                        :k, :t)
            """),
            {"k": "insert-probe", "t": str(tenant_b.tenant_id)},
        )
    await app_session.rollback()
