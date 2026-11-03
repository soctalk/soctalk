"""A tenant_admin can reset the password of a user in its own tenant.

Before this endpoint existed a tenant user who forgot their password had no
recovery path: the MSSP-side reset (``POST /api/mssp/users/{id}/password/reset``)
deliberately refuses tenant users and the tenant self-service API had no reset
at all, so the only fix was the ``soctalk-auth set-password`` CLI inside the
api pod.

These tests drive ``POST /api/tenant/users/{id}/password/reset`` through the
real app (DBSessionMiddleware, internal session middleware, RLS on the
app-role session) over httpx and read the results back on a separate
MSSP-role session.
"""

from __future__ import annotations

import os
from collections.abc import AsyncIterator, Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import httpx
import pytest
import pytest_asyncio
from fastapi import HTTPException
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from soctalk.core.tenancy.models import Role, UserType

SKIP_INTEGRATION = os.getenv("SKIP_INTEGRATION", "0") == "1"

_ORIGIN = "http://testserver"
_PASSWORD = "tenant-reset-pw-2026!"


def _reset_url(user_id: UUID | str) -> str:
    return f"/api/tenant/users/{user_id}/password/reset"


# --------------------------------------------------------------------------- #
# No DB: the endpoint does not exist outside internal auth mode
# --------------------------------------------------------------------------- #


class _FakeRequest:
    def __init__(self, identity):
        self.state = type("S", (), {"user_identity": identity, "db": None})()


async def test_reset_is_not_found_in_proxy_auth_mode(monkeypatch):
    """Under ``SOCTALK_AUTH_MODE=proxy`` the IdP owns passwords; like the
    MSSP reset (not mounted in proxy mode) the tenant reset answers 404."""
    from soctalk.core.api.users import reset_tenant_user_password

    monkeypatch.setenv("SOCTALK_AUTH_MODE", "proxy")
    req = _FakeRequest(
        {
            "user_id": str(uuid4()),
            "email": "admin@example.test",
            "user_type": UserType.TENANT.value,
            "role": Role.TENANT_ADMIN.value,
            "tenant_id": str(uuid4()),
            "current_tenant": None,
        }
    )
    with pytest.raises(HTTPException) as exc:
        await reset_tenant_user_password(uuid4(), req)
    assert exc.value.status_code == 404


# --------------------------------------------------------------------------- #
# Postgres: the real HTTP stack
# --------------------------------------------------------------------------- #

async def _reset_global_engines(*, close: bool) -> None:
    """Drop ``soctalk.core.tenancy.db``'s loop-bound module-global engines
    (see ``test_metrics_bridge_tenant_scope.py`` for why)."""
    from soctalk.core.tenancy import db as tenancy_db

    for engine_attr, sm_attr in (
        ("_APP_ENGINE", "_APP_SM"),
        ("_MSSP_ENGINE", "_MSSP_SM"),
    ):
        engine = getattr(tenancy_db, engine_attr)
        if engine is not None:
            await engine.dispose(close=close)
        setattr(tenancy_db, engine_attr, None)
        setattr(tenancy_db, sm_attr, None)


ClientFactory = Callable[[], Awaitable[httpx.AsyncClient]]


@pytest_asyncio.fixture
async def new_client(monkeypatch) -> AsyncIterator[ClientFactory]:
    """Hands out httpx clients (one cookie jar each) on the full V1 app."""
    monkeypatch.setenv("SOCTALK_AUTH_MODE", "internal")
    monkeypatch.setenv("SOCTALK_PUBLIC_ORIGIN", _ORIGIN)
    monkeypatch.setenv("SOCTALK_AUTH_COOKIE_SECURE", "0")
    monkeypatch.setenv("SOCTALK_PROVISIONING_WORKER", "0")

    from soctalk.core.api.app_v1 import create_app
    from soctalk.core.auth.rate_limit import reset_default_limiter

    reset_default_limiter()
    await _reset_global_engines(close=False)

    app = create_app()
    opened: list[httpx.AsyncClient] = []

    async def _make() -> httpx.AsyncClient:
        client = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url=_ORIGIN,
            headers={"Origin": _ORIGIN},  # CSRF: state-changing cookie requests
        )
        opened.append(client)
        return client

    yield _make

    for client in opened:
        await client.aclose()
    await _reset_global_engines(close=True)
    reset_default_limiter()


@dataclass(frozen=True)
class Cast:
    tenant_id: UUID
    other_tenant_id: UUID
    tenant_admin: str
    target: str
    target_id: UUID
    tenant_manager: str
    tenant_analyst: str
    customer_viewer: str
    other_tenant_user: str
    other_tenant_user_id: UUID
    mssp_admin: str
    mssp_admin_id: UUID


@pytest_asyncio.fixture
async def cast(seed_two_tenants, mssp_session: AsyncSession) -> Cast:
    """Tenant A gets an admin, the reset target, and one user per lesser role.
    Every login (including tenant B's user and an MSSP admin) gets a password."""
    from soctalk.core.auth.models import PasswordCredential
    from soctalk.core.auth.passwords import hash_password
    from soctalk.core.tenancy.models import User

    a, b = seed_two_tenants
    new_users = {
        "tenant-admin@example.test": Role.TENANT_ADMIN.value,
        "target@example.test": Role.TENANT_ANALYST.value,
        "tenant-manager@example.test": Role.TENANT_MANAGER.value,
        "tenant-analyst@example.test": Role.TENANT_ANALYST.value,
    }
    ids: dict[str, UUID] = {}
    for email, role in new_users.items():
        ids[email] = uuid4()
        mssp_session.add(
            User(
                id=ids[email],
                email=email,
                display_name=email.split("@")[0],
                user_type=UserType.TENANT.value,
                role=role,
                tenant_id=a.tenant_id,
                active=True,
            )
        )
    await mssp_session.flush()

    pw_hash = hash_password(_PASSWORD)
    for uid in (*ids.values(), a.viewer_user_id, b.viewer_user_id, a.admin_user_id):
        mssp_session.add(PasswordCredential(user_id=uid, password_hash=pw_hash))
    await mssp_session.commit()

    async def _email(uid: UUID) -> str:
        return (
            await mssp_session.execute(text("SELECT email FROM users WHERE id = :u"), {"u": uid})
        ).scalar_one()

    cast = Cast(
        tenant_id=a.tenant_id,
        other_tenant_id=b.tenant_id,
        tenant_admin="tenant-admin@example.test",
        target="target@example.test",
        target_id=ids["target@example.test"],
        tenant_manager="tenant-manager@example.test",
        tenant_analyst="tenant-analyst@example.test",
        customer_viewer=await _email(a.viewer_user_id),
        other_tenant_user=await _email(b.viewer_user_id),
        other_tenant_user_id=b.viewer_user_id,
        mssp_admin=await _email(a.admin_user_id),
        mssp_admin_id=a.admin_user_id,
    )
    await mssp_session.commit()
    return cast


async def _login(client: httpx.AsyncClient, email: str, password: str) -> httpx.Response:
    return await client.post("/api/auth/login", json={"email": email, "password": password})


async def _signed_in(new_client: ClientFactory, email: str) -> httpx.AsyncClient:
    client = await new_client()
    resp = await _login(client, email, _PASSWORD)
    assert resp.status_code == 200, resp.text
    assert resp.json()["must_change"] is False
    return client


async def _fetch(db: AsyncSession, sql: str, **params):
    rows = (await db.execute(text(sql), params)).mappings().all()
    await db.commit()  # end the read transaction: later reads must see new commits
    return rows


@pytest.mark.integration
@pytest.mark.skipif(SKIP_INTEGRATION, reason="needs Postgres")
async def test_tenant_admin_resets_a_locked_out_user(
    new_client: ClientFactory, cast: Cast, mssp_session: AsyncSession
):
    # The target is signed in somewhere, and has since locked itself out.
    target_old = await _signed_in(new_client, cast.target)
    assert (await target_old.get("/api/auth/me")).status_code == 200
    await mssp_session.execute(
        text(
            "UPDATE password_credentials SET consecutive_failures = 10, locked_until = :t "
            "WHERE user_id = :u"
        ),
        {"t": datetime.now(UTC) + timedelta(minutes=15), "u": cast.target_id},
    )
    await mssp_session.commit()

    admin = await _signed_in(new_client, cast.tenant_admin)
    resp = await admin.post(_reset_url(cast.target_id))
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["user_id"] == str(cast.target_id)
    assert body["must_change"] is True
    temp = body["temporary_password"]
    assert isinstance(temp, str) and len(temp) >= 24

    # Credential: must_change set, lockout cleared, no live session left.
    (cred,) = await _fetch(
        mssp_session,
        "SELECT must_change, consecutive_failures, locked_until "
        "FROM password_credentials WHERE user_id = :u",
        u=cast.target_id,
    )
    assert cred["must_change"] is True
    assert cred["consecutive_failures"] == 0
    assert cred["locked_until"] is None
    live = await _fetch(
        mssp_session,
        "SELECT id FROM sessions WHERE user_id = :u AND revoked_at IS NULL",
        u=cast.target_id,
    )
    assert live == []
    assert (await target_old.get("/api/auth/me")).status_code == 401

    # The audit row landed under the tenant RLS context and was committed.
    audit = await _fetch(
        mssp_session,
        "SELECT actor_id, tenant_id, resource_type, resource_id FROM audit_log "
        "WHERE action = 'auth.password.reset.admin'",
    )
    admin_id = (
        await _fetch(
            mssp_session, "SELECT id FROM users WHERE email = :e", e=cast.tenant_admin
        )
    )[0]["id"]
    assert [dict(r) for r in audit] == [
        {
            "actor_id": str(admin_id),
            "tenant_id": cast.tenant_id,
            "resource_type": "user",
            "resource_id": str(cast.target_id),
        }
    ]

    # The old password is gone; the temporary one signs in and forces a change.
    probe = await new_client()
    assert (await _login(probe, cast.target, _PASSWORD)).status_code == 401
    fresh = await new_client()
    login = await _login(fresh, cast.target, temp)
    assert login.status_code == 200, login.text
    assert login.json()["must_change"] is True
    assert login.json()["user"]["user_id"] == str(cast.target_id)
    # must_change gates everything but /me, password change and logout.
    assert (await fresh.get("/api/tenant/users")).status_code == 403

    # The admin's own session is untouched.
    assert (await admin.get("/api/auth/me")).status_code == 200


@pytest.mark.integration
@pytest.mark.skipif(SKIP_INTEGRATION, reason="needs Postgres")
async def test_self_reset_is_refused(new_client: ClientFactory, cast: Cast, mssp_session):
    admin = await _signed_in(new_client, cast.tenant_admin)
    me = (await admin.get("/api/auth/me")).json()
    resp = await admin.post(_reset_url(me["user_id"]))
    assert resp.status_code == 400, resp.text
    assert "password change" in resp.json()["detail"]
    # Still signed in, and the own password still works.
    assert (await admin.get("/api/auth/me")).status_code == 200
    assert (await _login(await new_client(), cast.tenant_admin, _PASSWORD)).status_code == 200


@pytest.mark.integration
@pytest.mark.skipif(SKIP_INTEGRATION, reason="needs Postgres")
async def test_targets_outside_the_own_tenant_are_not_found(
    new_client: ClientFactory, cast: Cast, mssp_session: AsyncSession
):
    admin = await _signed_in(new_client, cast.tenant_admin)
    for victim_id in (cast.mssp_admin_id, cast.other_tenant_user_id, uuid4()):
        resp = await admin.post(_reset_url(victim_id))
        assert resp.status_code == 404, (victim_id, resp.text)

    # Nothing changed for either account: their own passwords still work.
    for email in (cast.mssp_admin, cast.other_tenant_user):
        assert (await _login(await new_client(), email, _PASSWORD)).status_code == 200
    assert (
        await _fetch(
            mssp_session,
            "SELECT 1 FROM audit_log WHERE action = 'auth.password.reset.admin'",
        )
    ) == []


@pytest.mark.integration
@pytest.mark.skipif(SKIP_INTEGRATION, reason="needs Postgres")
async def test_deactivated_target_must_be_reactivated_first(
    new_client: ClientFactory, cast: Cast, mssp_session: AsyncSession
):
    admin = await _signed_in(new_client, cast.tenant_admin)
    deact = await admin.post(f"/api/tenant/users/{cast.target_id}/deactivate")
    assert deact.status_code == 200, deact.text

    resp = await admin.post(_reset_url(cast.target_id))
    assert resp.status_code == 409, resp.text
    assert "reactivate" in resp.json()["detail"]

    # Reactivate, then the reset goes through.
    react = await admin.patch(f"/api/tenant/users/{cast.target_id}", json={"active": True})
    assert react.status_code == 200, react.text
    resp = await admin.post(_reset_url(cast.target_id))
    assert resp.status_code == 200, resp.text
    login = await _login(await new_client(), cast.target, resp.json()["temporary_password"])
    assert login.status_code == 200
    assert login.json()["must_change"] is True


@pytest.mark.integration
@pytest.mark.skipif(SKIP_INTEGRATION, reason="needs Postgres")
@pytest.mark.parametrize(
    "caller", ["tenant_manager", "tenant_analyst", "customer_viewer", "mssp_admin"]
)
async def test_callers_without_tenant_manage_users_are_forbidden(
    caller: str, new_client: ClientFactory, cast: Cast, mssp_session: AsyncSession
):
    client = await _signed_in(new_client, getattr(cast, caller))
    resp = await client.post(_reset_url(cast.target_id))
    assert resp.status_code == 403, resp.text

    # The target's password is unchanged.
    assert (await _login(await new_client(), cast.target, _PASSWORD)).status_code == 200
    (cred,) = await _fetch(
        mssp_session,
        "SELECT must_change FROM password_credentials WHERE user_id = :u",
        u=cast.target_id,
    )
    assert cred["must_change"] is False
