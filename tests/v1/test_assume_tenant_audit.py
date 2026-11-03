"""``POST /api/auth/assume-tenant``: the target must exist and every pin change is audited.

The tenant pin is how MSSP staff open a customer's tenant. It used to accept
any well-formed tenant id (200 for a tenant that does not exist) and wrote no
audit row, although ``AuditAction.USER_IMPERSONATE`` exists for exactly this:
the customer had no trace of MSSP staff opening its tenant.
"""

from __future__ import annotations

import os
from uuid import uuid4

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
        reason="SKIP_INTEGRATION set; assume-tenant audit tests need Postgres",
    ),
]

_PASSWORD = "assume-tenant-pw-2026!"
_ORIGIN = "http://testserver"
_CSRF = {"Origin": _ORIGIN}
_ADMIN = "admin-a@mssp-a.example"


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
async def client(monkeypatch, seed_two_tenants, mssp_session: AsyncSession):
    from soctalk.core.auth.models import PasswordCredential
    from soctalk.core.auth.passwords import hash_password

    uid = (
        await mssp_session.execute(text("SELECT id FROM users WHERE email = :e"), {"e": _ADMIN})
    ).scalar_one()
    mssp_session.add(PasswordCredential(user_id=uid, password_hash=hash_password(_PASSWORD)))
    await mssp_session.commit()

    monkeypatch.setenv("SOCTALK_AUTH_MODE", "internal")
    monkeypatch.setenv("SOCTALK_PUBLIC_ORIGIN", _ORIGIN)
    monkeypatch.setenv("SOCTALK_AUTH_COOKIE_SECURE", "0")
    monkeypatch.setenv("SOCTALK_PROVISIONING_WORKER", "0")
    from soctalk.core.api.app_v1 import create_app
    from soctalk.core.auth.rate_limit import reset_default_limiter

    reset_default_limiter()
    await _reset_global_engines(close=False)
    transport = httpx.ASGITransport(app=create_app())
    async with httpx.AsyncClient(transport=transport, base_url=_ORIGIN) as c:
        r = await c.post(
            "/api/auth/login", json={"email": _ADMIN, "password": _PASSWORD}, headers=_CSRF
        )
        assert r.status_code == 200, r.text
        yield c, seed_two_tenants, str(uid)
    await _reset_global_engines(close=True)
    reset_default_limiter()


async def _pin(c: httpx.AsyncClient, **body) -> httpx.Response:
    return await c.post("/api/auth/assume-tenant", json=body, headers=_CSRF)


async def _rows(db: AsyncSession) -> list[tuple[str, str, str, str]]:
    rows = (
        await db.execute(
            text(
                "SELECT coalesce(tenant_id::text, ''), actor_id, resource_id, notes "
                "FROM audit_log WHERE action = 'user.impersonate' ORDER BY timestamp, id"
            )
        )
    ).all()
    await db.commit()
    return [tuple(r) for r in rows]


async def test_unknown_tenant_id_is_refused(client, mssp_session: AsyncSession):
    c, _tenants, _uid = client
    r = await _pin(c, tenant_id=str(uuid4()))
    assert r.status_code == 404, r.text
    me = (await c.get("/api/auth/me")).json()
    assert me["current_tenant"] is None
    assert await _rows(mssp_session) == []


async def test_every_pin_change_is_audited_on_the_tenant(client, mssp_session: AsyncSession):
    c, (tenant_a, tenant_b), uid = client
    a, b = str(tenant_a.tenant_id), str(tenant_b.tenant_id)

    assert (await _pin(c, slug=tenant_a.slug)).status_code == 200
    assert (await _pin(c, slug=tenant_a.slug)).status_code == 200  # same pin: no new row
    r = await _pin(c, tenant_id=b)  # switch while pinned
    assert r.status_code == 200, r.text
    assert r.json()["current_tenant_slug"] == tenant_b.slug
    assert (await _pin(c)).status_code == 200  # clear

    assert await _rows(mssp_session) == [
        (a, uid, a, "tenant pin set; previous=none"),
        (b, uid, b, f"tenant pin set; previous={a}"),
        (b, uid, b, "tenant pin cleared"),
    ]


async def test_tenant_sees_the_pin_in_its_own_audit_scope(client, app_session: AsyncSession):
    """The row is written with the tenant's id, so the tenant-scoped (RLS) view returns it."""
    c, (tenant_a, tenant_b), uid = client
    assert (await _pin(c, slug=tenant_a.slug)).status_code == 200

    from soctalk.core.tenancy.context import tenant_context

    async with tenant_context(app_session, tenant_a.tenant_id):
        seen_a = (
            (
                await app_session.execute(
                    text("SELECT actor_id FROM audit_log WHERE action = 'user.impersonate'")
                )
            )
            .scalars()
            .all()
        )
    await app_session.commit()
    async with tenant_context(app_session, tenant_b.tenant_id):
        seen_b = (
            (
                await app_session.execute(
                    text("SELECT actor_id FROM audit_log WHERE action = 'user.impersonate'")
                )
            )
            .scalars()
            .all()
        )
    await app_session.commit()
    assert seen_a == [uid]
    assert seen_b == []
