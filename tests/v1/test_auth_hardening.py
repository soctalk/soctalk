"""Sign-in and password-change hardening, through the real HTTP stack.

- Sign-in accepts the account's e-mail however it is typed (case, spaces).
- Rejections before the real verify (unknown e-mail, deactivated user) still
  pay for one argon2 verify, so response time does not reveal accounts.
- An administrator reset lifts the in-process rate limit for the e-mail.
- A wrong current password on ``/api/auth/password/change`` counts toward the
  lockout and is audited; at the threshold the account locks and every
  session ends. The new password must differ from the current one.
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
        reason="SKIP_INTEGRATION set; auth hardening tests need Postgres",
    ),
]

_PASSWORD = "auth-hardening-pw-2026!"
_ORIGIN = "http://testserver"
_CSRF = {"Origin": _ORIGIN}
_USER = "admin-a@mssp-a.example"
_ADMIN = "admin-b@mssp-b.example"


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
async def app(monkeypatch):
    monkeypatch.setenv("SOCTALK_AUTH_MODE", "internal")
    monkeypatch.setenv("SOCTALK_PUBLIC_ORIGIN", _ORIGIN)
    monkeypatch.setenv("SOCTALK_AUTH_COOKIE_SECURE", "0")
    monkeypatch.setenv("SOCTALK_PROVISIONING_WORKER", "0")
    from soctalk.core.api.app_v1 import create_app
    from soctalk.core.auth.rate_limit import reset_default_limiter

    reset_default_limiter()
    await _reset_global_engines(close=False)
    yield create_app()
    await _reset_global_engines(close=True)
    reset_default_limiter()


def _client(app) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=_ORIGIN)


@pytest_asyncio.fixture
async def user_id(seed_two_tenants, mssp_session: AsyncSession) -> str:
    from soctalk.core.auth.models import PasswordCredential
    from soctalk.core.auth.passwords import hash_password

    ids = {}
    for email in (_USER, _ADMIN):
        uid = (
            await mssp_session.execute(text("SELECT id FROM users WHERE email = :e"), {"e": email})
        ).scalar_one()
        mssp_session.add(PasswordCredential(user_id=uid, password_hash=hash_password(_PASSWORD)))
        ids[email] = str(uid)
    await mssp_session.commit()
    return ids[_USER]


async def _login(c: httpx.AsyncClient, email: str, password: str = _PASSWORD) -> httpx.Response:
    return await c.post(
        "/api/auth/login", json={"email": email, "password": password}, headers=_CSRF
    )


async def _change(c: httpx.AsyncClient, old: str, new: str) -> httpx.Response:
    return await c.post(
        "/api/auth/password/change",
        json={"old_password": old, "new_password": new},
        headers=_CSRF,
    )


async def _cred(db: AsyncSession, uid: str) -> tuple[int, bool, bool]:
    row = (
        await db.execute(
            text(
                "SELECT consecutive_failures, locked_until IS NOT NULL, must_change "
                "FROM password_credentials WHERE user_id = :u"
            ),
            {"u": uid},
        )
    ).one()
    await db.commit()
    return int(row[0]), bool(row[1]), bool(row[2])


async def _audit(db: AsyncSession, action: str) -> list[str]:
    rows = (
        (
            await db.execute(
                text(
                    "SELECT coalesce(notes, '') FROM audit_log WHERE action = :a ORDER BY timestamp"
                ),
                {"a": action},
            )
        )
        .scalars()
        .all()
    )
    await db.commit()
    return list(rows)


# --- e-mail normalisation ---------------------------------------------------------------


async def test_sign_in_ignores_email_case_and_spaces(app, user_id):
    async with _client(app) as c:
        r = await _login(c, "  Admin-A@MSSP-A.Example ")
        assert r.status_code == 200, r.text
        assert r.json()["user"]["email"] == _USER


async def test_mixed_case_stored_email_still_signs_in(app, user_id, mssp_session: AsyncSession):
    # Rows created outside the API (CLI, older installs) may not be lower-case.
    await mssp_session.execute(
        text("UPDATE users SET email = 'Admin-A@MSSP-A.example' WHERE id = :u"), {"u": user_id}
    )
    await mssp_session.commit()
    async with _client(app) as c:
        assert (await _login(c, _USER)).status_code == 200
        assert (await _login(c, "Admin-A@MSSP-A.example")).status_code == 200


# --- timing: early rejections still pay for a verify ------------------------------------------


async def test_early_rejections_spend_a_verify(
    app, user_id, mssp_session: AsyncSession, monkeypatch
):
    from soctalk.core.auth import service

    calls: list[str] = []
    real = service.spend_verify_time
    monkeypatch.setattr(service, "spend_verify_time", lambda pw: (calls.append(pw), real(pw)))
    async with _client(app) as c:
        assert (await _login(c, "nobody@example.test", "whatever-123456")).status_code == 401
        await mssp_session.execute(
            text("UPDATE users SET active = false WHERE id = :u"), {"u": user_id}
        )
        await mssp_session.commit()
        assert (await _login(c, _USER)).status_code == 401
    assert calls == ["whatever-123456", _PASSWORD]


# --- admin reset lifts the rate limit ----------------------------------------------------


async def test_admin_reset_lifts_the_rate_limit(app, user_id):
    async with _client(app) as victim, _client(app) as admin:
        for _ in range(10):
            assert (await _login(victim, _USER, "wrong-password-123")).status_code == 401
        assert (await _login(victim, _USER)).status_code == 429

        assert (await _login(admin, _ADMIN)).status_code == 200
        r = await admin.post(f"/api/mssp/users/{user_id}/password/reset", headers=_CSRF)
        assert r.status_code == 200, r.text
        temp = r.json()["temporary_password"]

        r = await _login(victim, _USER, temp)
        assert r.status_code == 200, r.text
        assert r.json()["must_change"] is True


# --- password change -------------------------------------------------------------------------


async def test_wrong_current_password_is_counted_and_audited(
    app, user_id, mssp_session: AsyncSession
):
    async with _client(app) as c:
        assert (await _login(c, _USER)).status_code == 200
        r = await _change(c, "not-the-password", "a-brand-new-password-1")
        assert r.status_code == 400
        assert r.json()["detail"] == "Current password is incorrect."
    assert (await _cred(mssp_session, user_id))[:2] == (1, False)
    assert await _audit(mssp_session, "auth.password.change.failure") == ["reason=bad_password"]


async def test_guessing_the_current_password_locks_and_signs_out(
    app, user_id, mssp_session: AsyncSession
):
    from soctalk.core.auth.rate_limit import reset_default_limiter

    async with _client(app) as c, _client(app) as other:
        assert (await _login(c, _USER)).status_code == 200
        assert (await _login(other, _USER)).status_code == 200
        for i in range(10):
            r = await _change(c, f"guess-{i}-xxxxxxxx", "a-brand-new-password-1")
            assert r.status_code == 400, (i, r.text)

        failures, locked, _ = await _cred(mssp_session, user_id)
        assert failures == 10 and locked
        assert len(await _audit(mssp_session, "auth.lockout.triggered")) == 1
        # Every session ends, the guessing one included.
        assert (await c.get("/api/auth/me")).status_code == 401
        assert (await other.get("/api/auth/me")).status_code == 401

        reset_default_limiter()
        r = await _login(c, _USER)
        assert r.status_code == 423, r.text


async def test_new_password_must_differ_from_current(app, user_id, mssp_session: AsyncSession):
    await mssp_session.execute(
        text("UPDATE password_credentials SET must_change = true WHERE user_id = :u"),
        {"u": user_id},
    )
    await mssp_session.commit()
    async with _client(app) as c:
        assert (await _login(c, _USER)).json()["must_change"] is True
        r = await _change(c, _PASSWORD, _PASSWORD)
        assert r.status_code == 400
        assert "different" in r.json()["detail"]
        assert (await _cred(mssp_session, user_id))[2] is True, "must_change cleared"
        assert (await _change(c, _PASSWORD, "a-brand-new-password-1")).status_code == 200
    assert (await _cred(mssp_session, user_id)) == (0, False, False)
