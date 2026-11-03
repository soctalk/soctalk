"""Failed sign-ins must leave a trace through the real HTTP stack.

``authenticate()`` records every failure on the request's DB session: it
bumps ``password_credentials.consecutive_failures`` (10 → ``locked_until``)
and writes ``auth.login.failure`` / ``auth.lockout.triggered`` audit rows,
then raises. ``DBSessionMiddleware`` commits only for 2xx/3xx responses, so
the 401/423 that follows rolled all of it back: the account lockout could
never trigger and failed sign-ins were never audited.

``test_internal_auth.py`` calls ``authenticate()`` directly and commits by
hand, which is why it passed. These tests go through ``POST /api/auth/login``
with the real middleware stack and read the result back on a separate
MSSP-role session.
"""

from __future__ import annotations

import os

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
        reason="SKIP_INTEGRATION set; login persistence tests need Postgres",
    ),
]

_PASSWORD = "login-failure-pw-2026!"
_ORIGIN = "http://testserver"
_CSRF_HEADERS = {"Origin": _ORIGIN}
_EMAIL = "admin-a@mssp-a.example"


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


@pytest_asyncio.fixture
async def api_client(monkeypatch):
    """The full V1 app (DBSessionMiddleware included) behind httpx."""
    monkeypatch.setenv("SOCTALK_AUTH_MODE", "internal")
    monkeypatch.setenv("SOCTALK_PUBLIC_ORIGIN", _ORIGIN)
    monkeypatch.setenv("SOCTALK_AUTH_COOKIE_SECURE", "0")
    monkeypatch.setenv("SOCTALK_PROVISIONING_WORKER", "0")

    from soctalk.core.api.app_v1 import create_app
    from soctalk.core.auth.rate_limit import reset_default_limiter

    reset_default_limiter()
    await _reset_global_engines(close=False)

    app = create_app()
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url=_ORIGIN) as client:
        yield client

    await _reset_global_engines(close=True)
    reset_default_limiter()


@pytest_asyncio.fixture
async def user_id(seed_two_tenants, mssp_session: AsyncSession) -> str:
    from soctalk.core.auth.models import PasswordCredential
    from soctalk.core.auth.passwords import hash_password

    uid = (
        await mssp_session.execute(
            text("SELECT id FROM users WHERE email = :e"), {"e": _EMAIL}
        )
    ).scalar_one()
    mssp_session.add(
        PasswordCredential(user_id=uid, password_hash=hash_password(_PASSWORD))
    )
    await mssp_session.commit()
    return str(uid)


async def _login(client: httpx.AsyncClient, email: str, password: str) -> httpx.Response:
    return await client.post(
        "/api/auth/login",
        json={"email": email, "password": password},
        headers=_CSRF_HEADERS,
    )


async def _failures(db: AsyncSession, uid: str) -> tuple[int, object]:
    row = (
        await db.execute(
            text(
                "SELECT consecutive_failures, locked_until "
                "FROM password_credentials WHERE user_id = :u"
            ),
            {"u": uid},
        )
    ).one()
    await db.commit()  # end the read transaction: later reads must see new commits
    return int(row[0]), row[1]


async def _audit(db: AsyncSession, action: str) -> list[str]:
    rows = (
        await db.execute(
            text("SELECT coalesce(notes, '') FROM audit_log WHERE action = :a ORDER BY timestamp"),
            {"a": action},
        )
    ).scalars().all()
    await db.commit()
    return list(rows)


async def test_wrong_password_is_counted_and_audited(
    api_client: httpx.AsyncClient, user_id: str, mssp_session: AsyncSession
):
    resp = await _login(api_client, _EMAIL, "wrong-password-123")
    assert resp.status_code == 401

    failures, locked_until = await _failures(mssp_session, user_id)
    assert failures == 1, "the failed attempt was rolled back with the 401"
    assert locked_until is None
    assert await _audit(mssp_session, "auth.login.failure") == ["reason=bad_password"]


async def test_unknown_email_is_audited(
    api_client: httpx.AsyncClient, user_id: str, mssp_session: AsyncSession
):
    resp = await _login(api_client, "nobody@example.test", "whatever-123456")
    assert resp.status_code == 401
    assert await _audit(mssp_session, "auth.login.failure") == ["reason=unknown_email"]


async def test_ten_failures_lock_the_account(
    api_client: httpx.AsyncClient, user_id: str, mssp_session: AsyncSession
):
    from soctalk.core.auth.rate_limit import reset_default_limiter

    for _ in range(10):
        resp = await _login(api_client, _EMAIL, "wrong-password-123")
        assert resp.status_code == 401

    failures, locked_until = await _failures(mssp_session, user_id)
    assert failures == 10
    assert locked_until is not None
    assert len(await _audit(mssp_session, "auth.lockout.triggered")) == 1

    # The in-process rate limiter (10 per 15 min, per pod) would answer 429
    # here; it resets on every restart and is not shared across replicas.
    # The lockout is the durable control, so take the limiter out of play.
    reset_default_limiter()
    resp = await _login(api_client, _EMAIL, _PASSWORD)
    assert resp.status_code == 423, resp.text
    assert resp.json()["detail"]["reason"] == "locked"
    assert "reason=locked" in await _audit(mssp_session, "auth.login.failure")


async def test_success_still_resets_the_counter(
    api_client: httpx.AsyncClient, user_id: str, mssp_session: AsyncSession
):
    assert (await _login(api_client, _EMAIL, "wrong-password-123")).status_code == 401
    assert (await _login(api_client, _EMAIL, _PASSWORD)).status_code == 200

    failures, _ = await _failures(mssp_session, user_id)
    assert failures == 0
