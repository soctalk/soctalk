"""Regression tests for /api/metrics tenant scoping under assume-tenant.

Live-incident repro (tenant.metrics.assume-tenant-scope): an mssp_admin
session pinned to tenant B via POST /api/auth/assume-tenant saw the
FLEET-WIDE investigation count on the dashboard overview card while the
investigations list (RLS-scoped) correctly showed 0 — because
``metrics_bridge.overview`` branched only on role and always took the
BYPASSRLS cross-tenant session for MSSP admins, never consulting
``identity.current_tenant``. ``hourly`` had the inverse defect: it
always used the request-bound RLS session, so an UNPINNED mssp_admin
got fail-closed all-zero buckets next to a fleet-wide overview card.

These tests run the real app stack (DBSessionMiddleware + internal
session middleware) over httpx's ASGI transport so the session-pin →
RLS-context plumbing is exercised exactly as in production:

1. Pinned MSSP session: overview, hourly, and /api/investigations all
   agree on the PINNED tenant's counts (zero for an empty tenant even
   while another tenant holds rows; the real counts once re-pinned).
2. Unpinned MSSP session: fleet-wide overview (incl. pending_reviews,
   whose RLS policy is fail-closed for the app role) AND fleet-wide
   hourly buckets. A tenant-bound user sees only their tenant in both.

Requires the integration Postgres (same harness as the other tests in
this package); skipped under SKIP_INTEGRATION=1.
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
        reason="SKIP_INTEGRATION set; metrics scoping tests need Postgres",
    ),
]


_PASSWORD = "metrics-scope-pw-2026!"
_ORIGIN = "http://testserver"
# Origin header for state-changing requests: the internal-session
# middleware applies CSRF origin validation before any handler runs.
_CSRF_HEADERS = {"Origin": _ORIGIN}

_MSSP_ADMIN_EMAIL = "admin-a@mssp-a.example"
_TENANT_VIEWER_EMAIL = "viewer-a@acme.example"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


async def _reset_global_engines(*, close: bool) -> None:
    """Drop ``soctalk.core.tenancy.db``'s module-global engines.

    pytest-asyncio gives every test its own event loop, but asyncpg
    connections are bound to the loop they were created on. Other code
    paths (e.g. the login-time MSSP user lookup) lazily create the
    global engines on whatever test's loop runs first, so this module
    must reset them around each test: ``close=False`` at setup (the
    pooled connections belong to a dead/foreign loop and cannot be
    awaited from here — discard the pool without touching them) and
    ``close=True`` at teardown (the engines were rebuilt on OUR loop,
    so a clean dispose works).
    """
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
    """The full V1 app behind an httpx ASGI client.

    Real middleware stack (app-role DB session + internal session
    cookie resolution) so the tenant pin lands in ``app.current_tenant_id``
    the same way it does in production. The lifespan is intentionally
    NOT run (no provisioning worker / lease reaper in tests).
    """
    monkeypatch.setenv("SOCTALK_AUTH_MODE", "internal")
    # CSRF: state-changing requests with a session cookie must carry an
    # Origin matching the configured public origin.
    monkeypatch.setenv("SOCTALK_PUBLIC_ORIGIN", _ORIGIN)
    # The session cookie defaults to Secure; httpx won't return Secure
    # cookies over the http:// test origin.
    monkeypatch.setenv("SOCTALK_AUTH_COOKIE_SECURE", "0")
    monkeypatch.setenv("SOCTALK_PROVISIONING_WORKER", "0")

    from soctalk.core.api.app_v1 import create_app

    await _reset_global_engines(close=False)

    app = create_app()
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url=_ORIGIN) as client:
        yield client

    await _reset_global_engines(close=True)


@pytest_asyncio.fixture
async def seeded(seed_two_tenants, mssp_session: AsyncSession):
    """Two tenants + login credentials for an mssp_admin and a tenant viewer.

    ``seed_two_tenants`` already TRUNCATEd the tenant-scoped tables;
    ``pending_reviews`` is not in that list, so clear it here — the
    overview rollup counts its rows.
    """
    from soctalk.core.auth.models import PasswordCredential
    from soctalk.core.auth.passwords import hash_password

    tenant_a, tenant_b = seed_two_tenants

    for email in (_MSSP_ADMIN_EMAIL, _TENANT_VIEWER_EMAIL):
        user_id = (
            await mssp_session.execute(
                text("SELECT id FROM users WHERE email = :e"), {"e": email}
            )
        ).scalar_one()
        mssp_session.add(
            PasswordCredential(
                user_id=user_id, password_hash=hash_password(_PASSWORD)
            )
        )
    await mssp_session.execute(text("DELETE FROM pending_reviews"))
    await mssp_session.commit()
    return tenant_a, tenant_b


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _seed_investigation(
    db: AsyncSession,
    tenant_id: UUID,
    short_id: str,
    severity: int,
) -> UUID:
    """One active investigation opened now.

    ``visibility='customer_safe'`` so the tenant-bound viewer can see it
    too (the default ``mssp_only`` is hidden from customer audience and
    would conflate the visibility filter with the tenant-scoping
    behavior under test).
    """
    case_id = uuid4()
    await db.execute(
        text(
            "INSERT INTO investigations "
            "(id, tenant_id, short_id, title, severity, status, visibility, opened_at) "
            "VALUES (:id, :t, :sid, 'metrics scope test', :sev, 'active', "
            "'customer_safe', now())"
        ),
        {"id": str(case_id), "t": str(tenant_id), "sid": short_id, "sev": severity},
    )
    return case_id


async def _seed_pending_review(
    db: AsyncSession, tenant_id: UUID, investigation_id: UUID
) -> None:
    await db.execute(
        text(
            "INSERT INTO pending_reviews "
            "(id, investigation_id, tenant_id, status, title, description, "
            " max_severity, findings, enrichments, created_at) "
            "VALUES (:id, :inv, :t, 'pending', 'review', 'metrics scope test', "
            "'high', '{}', '{}'::jsonb, now())"
        ),
        {"id": str(uuid4()), "inv": str(investigation_id), "t": str(tenant_id)},
    )


async def _login(client: httpx.AsyncClient, email: str) -> None:
    resp = await client.post(
        "/api/auth/login",
        json={"email": email, "password": _PASSWORD},
        headers=_CSRF_HEADERS,
    )
    assert resp.status_code == 200, f"login failed: {resp.status_code} {resp.text}"


async def _logout(client: httpx.AsyncClient) -> None:
    resp = await client.post("/api/auth/logout", headers=_CSRF_HEADERS)
    assert resp.status_code == 200, f"logout failed: {resp.status_code} {resp.text}"


async def _assume_tenant(client: httpx.AsyncClient, slug: str | None) -> dict:
    resp = await client.post(
        "/api/auth/assume-tenant", json={"slug": slug}, headers=_CSRF_HEADERS
    )
    assert resp.status_code == 200, (
        f"assume-tenant failed: {resp.status_code} {resp.text}"
    )
    return resp.json()


async def _get_json(client: httpx.AsyncClient, path: str) -> dict:
    resp = await client.get(path)
    assert resp.status_code == 200, f"GET {path}: {resp.status_code} {resp.text}"
    return resp.json()


def _hourly_totals(hourly: dict) -> dict[str, int]:
    metrics = hourly["metrics"]
    assert metrics, "expected at least one hourly bucket"
    return {
        "created": sum(m["investigations_created"] for m in metrics),
        "closed": sum(m["investigations_closed"] for m in metrics),
        "alerts": sum(m["total_alerts"] for m in metrics),
        "max_open_wip": max(m["open_wip"] for m in metrics),
    }


# ---------------------------------------------------------------------------
# 1. Live-incident regression: pinned MSSP session must be tenant-scoped
#    on ALL three surfaces (overview / hourly / investigations list).
# ---------------------------------------------------------------------------


async def test_pinned_mssp_session_scopes_all_metrics_surfaces(
    api_client: httpx.AsyncClient, seeded, mssp_session: AsyncSession
):
    tenant_a, tenant_b = seeded

    # Ground truth from the incident: EVERY investigation belongs to
    # tenant A; tenant B holds zero rows.
    for i, severity in enumerate((9, 6, 2)):
        await _seed_investigation(
            mssp_session, tenant_a.tenant_id, f"2026-9{i:03d}", severity
        )
    await mssp_session.commit()

    await _login(api_client, _MSSP_ADMIN_EMAIL)

    # Pin the session to tenant B (the empty one).
    me = await _assume_tenant(api_client, tenant_b.slug)
    assert me["current_tenant"] == str(tenant_b.tenant_id)

    # Surface 1: overview — must NOT leak the fleet-wide count.
    overview = await _get_json(api_client, "/api/metrics/overview")
    assert overview["open_investigations"] == 0
    assert overview["investigations_created_today"] == 0
    assert overview["pending_reviews"] == 0
    assert overview["severity_breakdown"] == {}

    # Surface 2: hourly — every bucket zero for the empty tenant.
    hourly = await _get_json(api_client, "/api/metrics/hourly")
    assert _hourly_totals(hourly) == {
        "created": 0,
        "closed": 0,
        "alerts": 0,
        "max_open_wip": 0,
    }

    # Surface 3: the investigations list the dashboard links to.
    inv = await _get_json(api_client, "/api/investigations")
    assert inv["total"] == 0
    assert inv["items"] == []

    # Re-pin to tenant A: the same session must now see A's counts on
    # all three surfaces.
    me = await _assume_tenant(api_client, tenant_a.slug)
    assert me["current_tenant"] == str(tenant_a.tenant_id)

    overview = await _get_json(api_client, "/api/metrics/overview")
    assert overview["open_investigations"] == 3
    assert overview["investigations_created_today"] == 3
    assert overview["severity_breakdown"] == {
        "critical": 0,
        "high": 1,
        "medium": 1,
        "low": 1,
    }

    hourly = await _get_json(api_client, "/api/metrics/hourly")
    totals = _hourly_totals(hourly)
    assert totals["created"] == 3
    assert totals["closed"] == 0
    assert totals["max_open_wip"] == 3

    inv = await _get_json(api_client, "/api/investigations")
    assert inv["total"] == 3


# ---------------------------------------------------------------------------
# 2. Cross-tenant behavior preserved: UNPINNED mssp_admin is fleet-wide
#    in BOTH endpoints; a tenant-bound user stays tenant-scoped in both.
# ---------------------------------------------------------------------------


async def test_unpinned_mssp_is_fleet_wide_and_tenant_user_is_scoped(
    api_client: httpx.AsyncClient, seeded, mssp_session: AsyncSession
):
    tenant_a, tenant_b = seeded

    case_a1 = await _seed_investigation(
        mssp_session, tenant_a.tenant_id, "2026-9100", 9
    )
    await _seed_investigation(mssp_session, tenant_a.tenant_id, "2026-9101", 6)
    await _seed_investigation(mssp_session, tenant_b.tenant_id, "2026-9102", 12)
    # A pending HIL review owned by tenant A. Its RLS policy is
    # fail-closed for the app role (no cross-tenant carve-out), so the
    # unpinned fleet view can only count it via the BYPASSRLS path.
    await _seed_pending_review(mssp_session, tenant_a.tenant_id, case_a1)
    await mssp_session.commit()

    # --- Unpinned mssp_admin: fleet-wide on BOTH endpoints. ---
    await _login(api_client, _MSSP_ADMIN_EMAIL)

    overview = await _get_json(api_client, "/api/metrics/overview")
    assert overview["open_investigations"] == 3
    assert overview["investigations_created_today"] == 3
    assert overview["pending_reviews"] == 1
    assert overview["severity_breakdown"] == {
        "critical": 1,
        "high": 1,
        "medium": 1,
        "low": 0,
    }

    # hourly must agree with the overview card next to it (this was the
    # all-zero side of the incident).
    hourly = await _get_json(api_client, "/api/metrics/hourly")
    totals = _hourly_totals(hourly)
    assert totals["created"] == 3
    assert totals["max_open_wip"] == 3

    # Pinning and unpinning returns the session to fleet-wide scope.
    await _assume_tenant(api_client, tenant_b.slug)
    overview = await _get_json(api_client, "/api/metrics/overview")
    assert overview["open_investigations"] == 1
    await _assume_tenant(api_client, None)
    overview = await _get_json(api_client, "/api/metrics/overview")
    assert overview["open_investigations"] == 3

    await _logout(api_client)

    # --- Tenant-bound user: only their tenant, in BOTH endpoints. ---
    await _login(api_client, _TENANT_VIEWER_EMAIL)

    overview = await _get_json(api_client, "/api/metrics/overview")
    assert overview["open_investigations"] == 2
    assert overview["investigations_created_today"] == 2
    assert overview["severity_breakdown"] == {
        "critical": 0,
        "high": 1,
        "medium": 1,
        "low": 0,
    }

    hourly = await _get_json(api_client, "/api/metrics/hourly")
    totals = _hourly_totals(hourly)
    assert totals["created"] == 2
    assert totals["max_open_wip"] == 2

    inv = await _get_json(api_client, "/api/investigations")
    assert inv["total"] == 2
