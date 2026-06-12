"""Unit tests for the internal auth HTTP surface.

These tests run without a real database. They exercise:

- mode-flag routing (proxy mode 404s /api/auth/*)
- CSRF enforcement (Origin/Referer check)
- The password-validation helper
- The in-process rate limiter

DB-backed behaviour (login success, lockout, password change, admin reset,
session expiry, must_change gating) is covered by ``test_internal_auth.py``
which is marked ``@pytest.mark.integration`` and skipped under
``SKIP_INTEGRATION=1``.
"""

from __future__ import annotations

import importlib
import os

import pytest


os.environ.setdefault(
    "DATABASE_URL_APP", "postgresql+asyncpg://stub:stub@localhost:9999/stub"
)
os.environ.setdefault(
    "DATABASE_URL_MSSP", "postgresql+asyncpg://stub:stub@localhost:9999/stub"
)
os.environ.setdefault(
    "SOCTALK_JWT_SIGNING_KEY", "test-signing-key-32-bytes-plaintext"
)
os.environ.setdefault(
    "SOCTALK_ADAPTER_SIGNING_KEY", "adapter-signing-key-32-bytes-plaintext"
)
os.environ.setdefault("SOCTALK_PUBLIC_ORIGIN", "https://soctalk.example")


import soctalk.core.tenancy.db as db_mod  # noqa: E402


# --- Stub session (same shape used elsewhere in the v1 tests) --------------


class _StubResult:
    def scalar_one_or_none(self):
        return None

    def scalar(self):
        return None

    def scalars(self):
        return self

    def all(self):
        return []


class StubSession:
    async def execute(self, *_a, **_kw):
        return _StubResult()

    async def flush(self):
        pass

    async def commit(self):
        pass

    async def rollback(self):
        pass

    def add(self, _obj):
        pass

    def add_all(self, _objs):
        pass


class _StubDBMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http":
            scope.setdefault("state", {})
            scope["state"]["db"] = StubSession()
        await self.app(scope, receive, send)


# Capture the real middleware class BEFORE stubbing so the module-scoped
# cleanup fixture below can restore it. The stub assignment happens at
# import (collection) time; the damage only becomes visible to OTHER test
# modules once ``_reload_app`` re-imports ``app_v1`` (which then binds the
# stub). Without restoration, every later ``create_app()`` — e.g. the
# metrics-bridge integration tests' fixture-time client — silently runs
# with a no-op DB session and logins 401 on "unknown email".
_REAL_DB_MIDDLEWARE = db_mod.DBSessionMiddleware
_PRIOR_AUTH_MODE = os.environ.get("SOCTALK_AUTH_MODE")

db_mod.DBSessionMiddleware = _StubDBMiddleware


@pytest.fixture(scope="module", autouse=True)
def _restore_global_modules():
    """Undo this module's process-global mutations at teardown.

    1. Restore the real ``DBSessionMiddleware`` on ``tenancy.db``.
    2. Restore ``SOCTALK_AUTH_MODE`` to its pre-module value.
    3. Reload ``auth.config`` and ``app_v1`` so their module globals
       re-bind against the restored state — later tests that call
       ``create_app()`` get the REAL middleware stack again.
    """
    yield
    db_mod.DBSessionMiddleware = _REAL_DB_MIDDLEWARE
    if _PRIOR_AUTH_MODE is None:
        os.environ.pop("SOCTALK_AUTH_MODE", None)
    else:
        os.environ["SOCTALK_AUTH_MODE"] = _PRIOR_AUTH_MODE
    import soctalk.core.auth.config as cfg

    importlib.reload(cfg)
    import soctalk.core.api.app_v1 as app_mod

    importlib.reload(app_mod)


# --- Helpers --------------------------------------------------------------


def _reload_app(mode: str):
    """Import ``create_app`` with ``SOCTALK_AUTH_MODE`` applied."""

    os.environ["SOCTALK_AUTH_MODE"] = mode
    import soctalk.core.auth.config as cfg

    importlib.reload(cfg)
    import soctalk.core.api.app_v1 as app_mod

    importlib.reload(app_mod)
    return app_mod.create_app


# --- Mode-flag routing -----------------------------------------------------


def test_proxy_mode_hides_auth_routes():
    from fastapi.testclient import TestClient

    create_app = _reload_app("proxy")
    client = TestClient(create_app())
    # In proxy mode the auth router is not registered.
    resp = client.post(
        "/api/auth/login",
        json={"email": "x@example.com", "password": "y"},
        headers={"Origin": "https://soctalk.example"},
    )
    assert resp.status_code == 404


def test_internal_mode_exposes_auth_routes():
    from fastapi.testclient import TestClient

    create_app = _reload_app("internal")
    client = TestClient(create_app())
    # The route exists; with a stub DB + unknown email we get 401.
    resp = client.post(
        "/api/auth/login",
        json={"email": "nobody@example.com", "password": "strongpw-1234"},
        headers={"Origin": "https://soctalk.example"},
    )
    assert resp.status_code == 401


def test_admin_reset_not_registered_in_proxy_mode():
    from fastapi.testclient import TestClient
    from uuid import uuid4

    create_app = _reload_app("proxy")
    client = TestClient(create_app())
    resp = client.post(
        f"/api/mssp/users/{uuid4()}/password/reset",
        headers={"Origin": "https://soctalk.example"},
    )
    assert resp.status_code == 404


# --- CSRF -----------------------------------------------------------------


def test_csrf_rejects_foreign_origin_when_session_cookie_present():
    """CSRF only fires when a session cookie is present (cookie-auth risk)."""

    from fastapi.testclient import TestClient
    from uuid import uuid4

    create_app = _reload_app("internal")
    client = TestClient(create_app())
    # Send a (fake) session cookie to trigger the Origin check.
    client.cookies.set("soctalk_session", str(uuid4()))
    resp = client.post(
        "/api/auth/login",
        json={"email": "x@example.com", "password": "y"},
        headers={"Origin": "https://attacker.example"},
    )
    assert resp.status_code == 403
    assert resp.json() == {"detail": "CSRF validation failed"}


def test_csrf_skipped_without_session_cookie():
    """Pre-login POST (no cookie) is not subject to CSRF enforcement."""

    from fastapi.testclient import TestClient

    create_app = _reload_app("internal")
    client = TestClient(create_app())
    resp = client.post(
        "/api/auth/login",
        json={"email": "x@example.com", "password": "y"},
    )
    # CSRF skipped; stub DB returns no user → 401.
    assert resp.status_code == 401


def test_csrf_accepts_referer_when_origin_missing():
    from fastapi.testclient import TestClient
    from uuid import uuid4

    create_app = _reload_app("internal")
    client = TestClient(create_app())
    client.cookies.set("soctalk_session", str(uuid4()))
    resp = client.post(
        "/api/auth/login",
        json={"email": "x@example.com", "password": "strongpw-1234"},
        headers={"Referer": "https://soctalk.example/login"},
    )
    # No Origin, valid Referer origin → CSRF passes; then stub DB → 401.
    assert resp.status_code == 401


def test_csrf_allows_get_without_origin():
    from fastapi.testclient import TestClient

    create_app = _reload_app("internal")
    client = TestClient(create_app())
    # GET /api/auth/me without Origin returns 401 (not authenticated), not 403.
    resp = client.get("/api/auth/me")
    assert resp.status_code == 401


# --- Password policy ------------------------------------------------------


def test_validate_password_enforces_minimum_length():
    from soctalk.core.auth.passwords import PasswordPolicyError, validate_password

    with pytest.raises(PasswordPolicyError):
        validate_password("short1!")
    validate_password("this-is-long-enough-1234")


def test_hash_and_verify_roundtrip():
    from soctalk.core.auth.passwords import hash_password, verify_password

    h = hash_password("correct horse battery staple")
    ok, maybe_new = verify_password("correct horse battery staple", h)
    assert ok
    # Fresh hash under current params; no rehash needed.
    assert maybe_new is None
    bad, _ = verify_password("wrong", h)
    assert not bad


# --- Rate limiter ---------------------------------------------------------


def test_rate_limiter_blocks_after_threshold():
    from soctalk.core.auth.rate_limit import RateLimiter

    limiter = RateLimiter()
    key = "test-key"
    for _ in range(10):
        assert limiter.hit(key)
    # Eleventh attempt in the window is blocked.
    assert not limiter.hit(key)


def test_rate_limiter_reset_clears_state():
    from soctalk.core.auth.rate_limit import RateLimiter

    limiter = RateLimiter()
    key = "test-key"
    for _ in range(10):
        limiter.hit(key)
    limiter.reset(key)
    assert limiter.hit(key)
