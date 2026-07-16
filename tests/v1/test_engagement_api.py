"""Engagement declare / list / revoke API (#31).

Two layers: a real declare→list→revoke round-trip against Postgres (proves the route layer,
tenant_context, validation→400, and revoke-excludes-from-default-list), and a role-gate check
(customer viewers cannot declare; analysts pass the gate).
"""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest
from fastapi import HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

os.environ.setdefault("SOCTALK_JWT_SIGNING_KEY", "test-signing-key-32-bytes-plaintext")
os.environ.setdefault("SOCTALK_ADAPTER_SIGNING_KEY", "adapter-signing-key-32-bytes-plaintext")

from soctalk.core.api.ir import (  # noqa: E402
    DeclareEngagementRequest,
    RevokeEngagementRequest,
    declare_engagement_route,
    list_engagements_route,
    revoke_engagement_route,
)

SKIP_INTEGRATION = os.getenv("SKIP_INTEGRATION", "0") == "1"

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(SKIP_INTEGRATION, reason="needs Postgres"),
]

_NOW = datetime.now(UTC)


def _req(session, user_id=None):
    from soctalk.core.tenancy.models import Role, UserType

    identity = {
        "user_id": str(user_id or uuid4()),
        "email": "analyst@mssp.example",
        "user_type": UserType.MSSP.value,
        "role": Role.MSSP_ADMIN.value,
        "tenant_id": None,
        "current_tenant": None,
    }

    class _R:
        class state:  # noqa: N801 — mimics request.state
            user_identity = identity
            db = session

    return _R()


def _payload(**over):
    base = dict(
        name="Q3 external pentest", kind="pentest",
        starts_at=_NOW - timedelta(hours=1), ends_at=_NOW + timedelta(hours=1),
        scope_source_ips=["203.0.113.0/24"], scope_hosts=["web-01"],
        scope_techniques=["T1110"],
    )
    base.update(over)
    return DeclareEngagementRequest(**base)


async def test_declare_list_revoke_roundtrip(mssp_session: AsyncSession, seed_two_tenants):
    t, _ = seed_two_tenants
    req = _req(mssp_session)

    res = await declare_engagement_route(t.tenant_id, _payload(), req)
    await mssp_session.commit()
    eid = res["id"]
    assert eid

    listed = await list_engagements_route(t.tenant_id, req)
    match = [e for e in listed if e.id == eid]
    assert len(match) == 1
    assert match[0].name == "Q3 external pentest"
    assert match[0].revoked_at is None
    assert match[0].declared_test_count == 0

    rev = await revoke_engagement_route(
        t.tenant_id, UUID(eid), RevokeEngagementRequest(reason="engagement complete"), req
    )
    await mssp_session.commit()
    assert rev["ok"] == "revoked"

    # revoked engagement drops out of the default list, but include_revoked shows it
    assert all(e.id != eid for e in await list_engagements_route(t.tenant_id, req))
    assert any(
        e.id == eid for e in await list_engagements_route(t.tenant_id, req, include_revoked=True)
    )


async def test_declare_invalid_scope_returns_400(mssp_session: AsyncSession, seed_two_tenants):
    t, _ = seed_two_tenants
    bad = _payload(scope_source_ips=[], scope_hosts=[], scope_techniques=[])
    with pytest.raises(HTTPException) as ei:
        await declare_engagement_route(t.tenant_id, bad, _req(mssp_session))
    assert ei.value.status_code == 400


async def test_revoke_unknown_returns_404(mssp_session: AsyncSession, seed_two_tenants):
    t, _ = seed_two_tenants
    with pytest.raises(HTTPException) as ei:
        await revoke_engagement_route(
            t.tenant_id, uuid4(), RevokeEngagementRequest(), _req(mssp_session)
        )
    assert ei.value.status_code == 404


def test_declare_route_role_gate():
    """Authorizing an engagement is a SOC-manager capability (separation of duties):
    customer viewers AND analysts are blocked; only mssp_manager (or above) passes the gate.

    No DB — the app runs with a noop DB session, so a passed gate reaches the handler and
    500s on the None session (proof the gate opened); a blocked gate returns 403 first."""
    from fastapi.testclient import TestClient
    from starlette.middleware.base import BaseHTTPMiddleware

    from soctalk.core.api.app_v1 import create_app
    from soctalk.core.tenancy.models import Role, UserType

    class _NoopDB:
        def __init__(self, app):
            self.app = app

        async def __call__(self, scope, receive, send):
            if scope["type"] == "http":
                scope.setdefault("state", {})
                scope["state"]["db"] = None
            await self.app(scope, receive, send)

    def _app_as(identity):
        app = create_app(db_session_middleware=_NoopDB)

        class _Inject(BaseHTTPMiddleware):
            async def dispatch(self, request, call_next):
                request.state.user_identity = identity
                return await call_next(request)

        app.add_middleware(_Inject)
        return app

    tid = str(uuid4())
    body = {
        "name": "x", "kind": "pentest",
        "starts_at": _NOW.isoformat(), "ends_at": (_NOW + timedelta(hours=1)).isoformat(),
        "scope_source_ips": ["203.0.113.0/24"], "scope_hosts": ["h"], "scope_techniques": [],
    }
    viewer = {
        "user_id": str(uuid4()), "email": "v@acme.example",
        "user_type": UserType.TENANT.value, "role": Role.CUSTOMER_VIEWER.value,
        "tenant_id": tid, "current_tenant": None,
    }
    analyst = {
        "user_id": str(uuid4()), "email": "a@mssp.example",
        "user_type": UserType.MSSP.value, "role": Role.ANALYST.value,
        "tenant_id": None, "current_tenant": None,
    }
    manager = {**analyst, "role": Role.MSSP_MANAGER.value, "email": "m@mssp.example"}
    url = f"/api/mssp/tenants/{tid}/engagements"

    # customer viewer — wrong audience/no capability
    cv = TestClient(_app_as(viewer), raise_server_exceptions=False)
    assert cv.post(url, json=body).status_code == 403

    # analyst — an MSSP operator, but authorizing risk is not an analyst capability
    ca = TestClient(_app_as(analyst), raise_server_exceptions=False)
    assert ca.post(url, json=body).status_code == 403

    # mssp_manager — holds AUTHORIZE_ENGAGEMENT; gate opens (handler 500s on the noop DB)
    cm = TestClient(_app_as(manager), raise_server_exceptions=False)
    assert cm.post(url, json=body).status_code != 403
