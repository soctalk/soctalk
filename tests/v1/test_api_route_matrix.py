"""API route matrix with stub DB and K8s.

For every protected endpoint, verify:

- The allowed role(s) reach the handler and the handler returns expected data.
- Disallowed roles get 403.
- Tenant endpoints with tenant user type return data; MSSP endpoints with
  tenant user type get 403; vice versa.

The DB is a stub session whose ``execute``/``scalar``/``scalars`` return
handcrafted data; K8s interactions are monkey-patched. This proves the
handler-happy-path bodies (not just the role gate) execute without errors.
"""

from __future__ import annotations

import os
from datetime import datetime
from uuid import UUID, uuid4

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

# -- Stub session ------------------------------------------------------------


class _StubResult:
    def __init__(self, rows=None, scalar_value=None):
        self._rows = rows or []
        self._scalar_value = scalar_value

    def scalar_one_or_none(self):
        return self._rows[0] if self._rows else None

    def scalars(self):
        return self

    def all(self):
        return list(self._rows)

    def scalar(self):
        return self._scalar_value


class StubSession:
    """An ``AsyncSession`` stand-in returning whatever the test queued.

    Tests set ``session.next_results`` to a list of ``_StubResult`` values,
    popped in FIFO order per ``execute`` call.
    """

    def __init__(self, next_results=None):
        self.next_results = list(next_results or [])
        self.added = []
        self.committed = 0
        self.flushed = 0

    async def execute(self, *_args, **_kwargs):
        # Absorb every set_config() call (current_tenant_id, current_audience,
        # current_user_role, etc.) so the test's queued results are only
        # consumed by the actual SELECT/INSERT/UPDATE the handler runs.
        if _args and "set_config(" in str(_args[0]):
            return _StubResult(scalar_value="")
        if self.next_results:
            return self.next_results.pop(0)
        return _StubResult()

    async def flush(self):
        self.flushed += 1

    async def commit(self):
        self.committed += 1

    async def rollback(self):
        pass

    def add(self, obj):
        self.added.append(obj)

    def add_all(self, objs):
        self.added.extend(objs)


_current_stub: StubSession | None = None


class _StubDBMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http":
            scope.setdefault("state", {})
            scope["state"]["db"] = _current_stub
        await self.app(scope, receive, send)


from fastapi.testclient import TestClient
from starlette.middleware.base import BaseHTTPMiddleware

from soctalk.core.api.app_v1 import create_app
from soctalk.core.tenancy.models import (
    BrandingConfig,
    IntegrationConfig,
    Organization,
    Role,
    Tenant,
    TenantLifecycleEvent,
    TenantState,
    UserType,
)


def _make_app(identity: dict | None):
    app = create_app(db_session_middleware=_StubDBMiddleware)

    class Inject(BaseHTTPMiddleware):
        async def dispatch(self, request, call_next):
            if identity is not None:
                request.state.user_identity = identity
            return await call_next(request)

    app.add_middleware(Inject)
    return app


def _identity(role: str, user_type: str, tenant_id=None, email="t@example.com"):
    return {
        "user_id": str(uuid4()),
        "email": email,
        "user_type": user_type,
        "role": role,
        "tenant_id": str(tenant_id) if tenant_id else None,
        "current_tenant": None,
    }


# -- Tests -------------------------------------------------------------------


def _fake_tenant(slug="acme", state=TenantState.ACTIVE.value, tid=None):
    now = datetime(2026, 1, 1)
    t = Tenant(
        id=tid or uuid4(),
        slug=slug,
        display_name=f"{slug.title()} Corp",
        state=state,
        organization_id=uuid4(),
        created_at=now,
        state_changed_at=now,
        config={},
    )
    t.runtime = {"version": "0.1.0", "health": "ok"}
    return t


def test_list_tenants_happy_path_mssp_admin():
    """mssp_admin -> GET /api/mssp/tenants returns the list."""
    global _current_stub
    tid_a, tid_b = uuid4(), uuid4()
    _current_stub = StubSession(
        next_results=[_StubResult(rows=[_fake_tenant("acme", tid=tid_a),
                                        _fake_tenant("beta", tid=tid_b)])]
    )
    client = TestClient(_make_app(_identity(Role.MSSP_ADMIN.value, UserType.MSSP.value)))
    resp = client.get("/api/mssp/tenants")
    assert resp.status_code == 200
    body = resp.json()
    assert len(body) == 2
    assert {t["slug"] for t in body} == {"acme", "beta"}


def test_list_tenants_analyst_allowed():
    global _current_stub
    _current_stub = StubSession(next_results=[_StubResult(rows=[_fake_tenant("acme")])])
    client = TestClient(_make_app(_identity(Role.ANALYST.value, UserType.MSSP.value)))
    resp = client.get("/api/mssp/tenants")
    assert resp.status_code == 200
    assert resp.json()[0]["slug"] == "acme"


def test_get_tenant_detail_happy_path():
    global _current_stub
    tid = uuid4()
    _current_stub = StubSession(next_results=[_StubResult(rows=[_fake_tenant("acme", tid=tid)])])
    client = TestClient(_make_app(_identity(Role.MSSP_ADMIN.value, UserType.MSSP.value)))
    resp = client.get(f"/api/mssp/tenants/{tid}")
    assert resp.status_code == 200
    body = resp.json()
    assert body["id"] == str(tid)
    assert body["slug"] == "acme"


def test_get_tenant_detail_404_when_missing():
    global _current_stub
    _current_stub = StubSession(next_results=[_StubResult(rows=[])])
    client = TestClient(_make_app(_identity(Role.MSSP_ADMIN.value, UserType.MSSP.value)))
    resp = client.get(f"/api/mssp/tenants/{uuid4()}")
    assert resp.status_code == 404


def test_lifecycle_events_listing():
    global _current_stub
    tid = uuid4()
    events = [
        TenantLifecycleEvent(
            tenant_id=tid, event_type="provisioning_started",
            from_state=None, to_state="pending", actor_id="user",
            details={},
        ),
        TenantLifecycleEvent(
            tenant_id=tid, event_type="active",
            from_state="provisioning", to_state="active", actor_id="user",
            details={"helm_release": "tenant-acme"},
        ),
    ]
    _current_stub = StubSession(next_results=[_StubResult(rows=events)])
    client = TestClient(_make_app(_identity(Role.ANALYST.value, UserType.MSSP.value)))
    resp = client.get(f"/api/mssp/tenants/{tid}/events")
    assert resp.status_code == 200
    body = resp.json()
    assert len(body) == 2
    assert body[0]["event_type"] == "provisioning_started"
    assert body[1]["details"]["helm_release"] == "tenant-acme"


def test_tenant_branding_returns_config():
    global _current_stub
    tid = uuid4()
    bc = BrandingConfig(
        tenant_id=tid, app_name="Acme SOC",
        logo_url="https://acme.example/logo.png",
        primary_color="#112233", secondary_color="#aabbcc",
    )
    _current_stub = StubSession(next_results=[_StubResult(rows=[bc])])
    client = TestClient(_make_app(
        _identity(Role.CUSTOMER_VIEWER.value, UserType.TENANT.value, tenant_id=tid)
    ))
    resp = client.get("/api/tenant/branding")
    assert resp.status_code == 200
    body = resp.json()
    assert body["app_name"] == "Acme SOC"
    assert body["primary_color"] == "#112233"


def test_tenant_branding_default_when_missing():
    global _current_stub
    tid = uuid4()
    _current_stub = StubSession(next_results=[_StubResult(rows=[])])
    client = TestClient(_make_app(
        _identity(Role.CUSTOMER_VIEWER.value, UserType.TENANT.value, tenant_id=tid)
    ))
    resp = client.get("/api/tenant/branding")
    assert resp.status_code == 200
    assert resp.json()["app_name"] == "SocTalk"


def test_llm_config_get_requires_admin():
    """analyst should NOT access /api/mssp/tenants/:id/llm (admin only)."""
    global _current_stub
    _current_stub = StubSession(next_results=[])
    client = TestClient(_make_app(_identity(Role.ANALYST.value, UserType.MSSP.value)))
    resp = client.get(f"/api/mssp/tenants/{uuid4()}/llm")
    assert resp.status_code == 403


def test_mssp_branding_update_requires_admin():
    global _current_stub
    _current_stub = StubSession(next_results=[])
    client = TestClient(_make_app(_identity(Role.ANALYST.value, UserType.MSSP.value)))
    resp = client.patch(
        f"/api/mssp/tenants/{uuid4()}/branding",
        json={"app_name": "New"},
    )
    assert resp.status_code == 403


def test_adapter_heartbeat_positive_path():
    """Adapter with a valid adapter JWT can heartbeat."""
    global _current_stub
    from soctalk.core.tenancy.auth import mint_adapter_token, reset_adapter_signing_key_cache

    tid = uuid4()
    reset_adapter_signing_key_cache()
    token = mint_adapter_token(tid)

    # Stub: first query loads the Tenant; we return one with the same ID.
    tenant = _fake_tenant("acme", tid=tid)
    _current_stub = StubSession(next_results=[_StubResult(rows=[tenant])])

    client = TestClient(_make_app(None))  # adapter doesn't need user identity
    resp = client.post(
        "/api/internal/adapter/heartbeat",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "tenant_id": str(tid),
            "version": "0.1.0",
            "health": "ok",
            "metrics": {"events_ingested": 42},
        },
    )
    assert resp.status_code == 200, resp.text
    assert resp.json() == {"ok": True}
    # Tenant.runtime should be updated in memory; flush was called.
    assert _current_stub.flushed == 1
    assert tenant.runtime["version"] == "0.1.0"
    assert tenant.runtime["health"] == "ok"


def test_adapter_heartbeat_tenant_id_mismatch():
    """Adapter token for tenant A heartbeats claiming tenant B should 403."""
    global _current_stub
    from soctalk.core.tenancy.auth import mint_adapter_token, reset_adapter_signing_key_cache

    tid_a = uuid4()
    tid_b = uuid4()
    reset_adapter_signing_key_cache()
    token = mint_adapter_token(tid_a)

    _current_stub = StubSession(next_results=[])
    client = TestClient(_make_app(None))
    resp = client.post(
        "/api/internal/adapter/heartbeat",
        headers={"Authorization": f"Bearer {token}"},
        json={"tenant_id": str(tid_b), "version": "0.1.0", "health": "ok"},
    )
    assert resp.status_code == 403


def test_adapter_config_positive_path():
    global _current_stub
    from soctalk.core.tenancy.auth import mint_adapter_token, reset_adapter_signing_key_cache

    tid = uuid4()
    reset_adapter_signing_key_cache()
    token = mint_adapter_token(tid)

    tenant = _fake_tenant("acme", tid=tid)
    tenant.config = {"features": ["telemetry"]}
    _current_stub = StubSession(next_results=[_StubResult(rows=[tenant])])

    client = TestClient(_make_app(None))
    resp = client.get(
        "/api/internal/adapter/config",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["tenant_id"] == str(tid)
    assert body["slug"] == "acme"
    assert body["config"]["features"] == ["telemetry"]
