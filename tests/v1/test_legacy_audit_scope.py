"""Tenant scoping of the audit and analytics pages (``/api/audit*``, ``/api/analytics/*``).

These legacy endpoints picked their DB session on role alone:

- an MSSP ``analyst`` has no home tenant, so ``tenant_context(None)`` ran
  ``set_config('app.current_tenant_id', 'None')`` and every audit/analytics
  call failed with a 500, pinned or not;
- a pinned ``mssp_admin``/``mssp_manager`` still read fleet-wide data through
  the BYPASSRLS session (the defect ``/api/metrics`` already fixed);
- tenant users read through ``TenantContext``, which stamps
  ``audience='mssp'``, so the audience policy on ``investigations`` let them
  see ``mssp_only`` rows.

They now resolve scope like ``/api/metrics`` and the review queue. The tests
run the real app stack over httpx's ASGI transport so the session pin reaches
RLS exactly as in production.
"""

from __future__ import annotations

import os
from uuid import UUID, uuid4

import httpx
import pytest
import pytest_asyncio
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

SKIP_INTEGRATION = os.getenv("SKIP_INTEGRATION", "0") == "1"

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        SKIP_INTEGRATION,
        reason="SKIP_INTEGRATION set; audit scoping tests need Postgres",
    ),
]

_PASSWORD = "audit-scope-pw-2026!"
_ORIGIN = "http://testserver"
_CSRF = {"Origin": _ORIGIN}
_ADMIN = "admin-a@mssp-a.example"
_ANALYST = "analyst@mssp-a.example"
_VIEWER = "viewer-a@acme.example"


async def _reset_global_engines(*, close: bool) -> None:
    """Drop the loop-bound module-global engines (see test_metrics_bridge_tenant_scope)."""
    from soctalk.core.tenancy import db as tenancy_db

    for engine_attr, sm_attr in (("_APP_ENGINE", "_APP_SM"), ("_MSSP_ENGINE", "_MSSP_SM")):
        engine = getattr(tenancy_db, engine_attr)
        if engine is not None:
            await engine.dispose(close=close)
        setattr(tenancy_db, engine_attr, None)
        setattr(tenancy_db, sm_attr, None)


@pytest_asyncio.fixture
async def api_client(monkeypatch):
    monkeypatch.setenv("SOCTALK_AUTH_MODE", "internal")
    monkeypatch.setenv("SOCTALK_PUBLIC_ORIGIN", _ORIGIN)
    monkeypatch.setenv("SOCTALK_AUTH_COOKIE_SECURE", "0")
    monkeypatch.setenv("SOCTALK_PROVISIONING_WORKER", "0")
    from soctalk.core.api.app_v1 import create_app
    from soctalk.core.auth.rate_limit import reset_default_limiter

    reset_default_limiter()
    await _reset_global_engines(close=False)
    transport = httpx.ASGITransport(app=create_app())
    async with httpx.AsyncClient(transport=transport, base_url=_ORIGIN) as client:
        yield client
    await _reset_global_engines(close=True)
    reset_default_limiter()


async def _event(db: AsyncSession, tenant_id: UUID, aggregate_id: UUID | None = None) -> None:
    await db.execute(
        text(
            "INSERT INTO events (id, aggregate_id, aggregate_type, event_type, version, "
            "timestamp, data, event_metadata, tenant_id) "
            "VALUES (gen_random_uuid(), :agg, 'Investigation', 'audit.scope.test', 1, "
            "now(), '{}'::jsonb, '{}'::jsonb, :t)"
        ),
        {"agg": str(aggregate_id or uuid4()), "t": str(tenant_id)},
    )


async def _investigation(db: AsyncSession, tenant_id: UUID, short_id: str, visibility: str) -> UUID:
    inv = uuid4()
    await db.execute(
        text(
            "INSERT INTO investigations "
            "(id, tenant_id, short_id, title, severity, status, visibility, opened_at) "
            "VALUES (:id, :t, :sid, :title, 5, 'active', :vis, now())"
        ),
        {
            "id": str(inv),
            "t": str(tenant_id),
            "sid": short_id,
            "title": f"{visibility} case",
            "vis": visibility,
        },
    )
    return inv


@pytest_asyncio.fixture
async def seeded(seed_two_tenants, mssp_session: AsyncSession):
    """Tenant A: 2 events, a customer_safe and an mssp_only investigation. Tenant B: 3 events.

    Logins: the seeded mssp_admin and tenant-A viewer, plus an MSSP analyst.
    """
    from soctalk.core.auth.models import PasswordCredential
    from soctalk.core.auth.passwords import hash_password
    from soctalk.core.tenancy.models import Role, User, UserType

    tenant_a, tenant_b = seed_two_tenants
    mssp_session.add(User(email=_ANALYST, user_type=UserType.MSSP.value, role=Role.ANALYST.value))
    await mssp_session.flush()
    for email in (_ADMIN, _ANALYST, _VIEWER):
        uid = (
            await mssp_session.execute(text("SELECT id FROM users WHERE email = :e"), {"e": email})
        ).scalar_one()
        mssp_session.add(PasswordCredential(user_id=uid, password_hash=hash_password(_PASSWORD)))

    await mssp_session.execute(text("DELETE FROM events"))
    safe = await _investigation(mssp_session, tenant_a.tenant_id, "2026-9001", "customer_safe")
    hidden = await _investigation(mssp_session, tenant_a.tenant_id, "2026-9002", "mssp_only")
    await _event(mssp_session, tenant_a.tenant_id, safe)
    await _event(mssp_session, tenant_a.tenant_id, hidden)
    for _ in range(3):
        await _event(mssp_session, tenant_b.tenant_id)
    await mssp_session.commit()
    return tenant_a, tenant_b, safe, hidden


async def _login(client: httpx.AsyncClient, email: str) -> None:
    r = await client.post(
        "/api/auth/login", json={"email": email, "password": _PASSWORD}, headers=_CSRF
    )
    assert r.status_code == 200, r.text


async def _pin(client: httpx.AsyncClient, slug: str | None) -> None:
    r = await client.post("/api/auth/assume-tenant", json={"slug": slug}, headers=_CSRF)
    assert r.status_code == 200, r.text


async def _audit_total(client: httpx.AsyncClient) -> int:
    r = await client.get("/api/audit")
    assert r.status_code == 200, r.text
    return r.json()["total"]


_SCOPED_PATHS = (
    "/api/audit",
    "/api/audit/event-types",
    "/api/audit/stats",
    "/api/analytics/summary",
    "/api/analytics/kpis",
    "/api/analytics/ai-behavior",
    "/api/analytics/human-review",
    "/api/analytics/outcomes",
)


async def test_unpinned_analyst_is_refused_not_500(api_client: httpx.AsyncClient, seeded):
    await _login(api_client, _ANALYST)
    for path in _SCOPED_PATHS:
        r = await api_client.get(path)
        assert r.status_code == 403, (path, r.status_code, r.text)
        assert r.json()["detail"] == "tenant scope required"


async def test_pinned_analyst_reads_the_pinned_tenant(api_client: httpx.AsyncClient, seeded):
    tenant_a, _b, _safe, _hidden = seeded
    await _login(api_client, _ANALYST)
    await _pin(api_client, tenant_a.slug)
    for path in _SCOPED_PATHS:
        r = await api_client.get(path)
        assert r.status_code == 200, (path, r.status_code, r.text)
    assert await _audit_total(api_client) == 2
    stats = (await api_client.get("/api/audit/stats")).json()
    assert stats["total_events"] == 2
    kpis = (await api_client.get("/api/analytics/kpis")).json()
    assert kpis["total_investigations"] == 2  # MSSP audience sees mssp_only too


async def test_pinned_admin_is_scoped_to_the_pin(api_client: httpx.AsyncClient, seeded):
    _a, tenant_b, _safe, _hidden = seeded
    await _login(api_client, _ADMIN)
    assert await _audit_total(api_client) == 5  # unpinned: fleet-wide
    await _pin(api_client, tenant_b.slug)
    assert await _audit_total(api_client) == 3
    kpis = (await api_client.get("/api/analytics/kpis")).json()
    assert kpis["total_investigations"] == 0
    await _pin(api_client, None)
    assert await _audit_total(api_client) == 5


async def test_tenant_user_sees_own_tenant_and_customer_audience_only(
    api_client: httpx.AsyncClient, seeded
):
    _a, _b, safe, hidden = seeded
    await _login(api_client, _VIEWER)
    assert await _audit_total(api_client) == 2
    kpis = (await api_client.get("/api/analytics/kpis")).json()
    assert kpis["total_investigations"] == 1

    shown = (await api_client.get(f"/api/audit/investigation/{safe}")).json()
    assert shown["title"] == "customer_safe case"
    masked = (await api_client.get(f"/api/audit/investigation/{hidden}")).json()
    assert masked["title"] is None, (
        "an mssp_only investigation title leaked to the customer audience"
    )
