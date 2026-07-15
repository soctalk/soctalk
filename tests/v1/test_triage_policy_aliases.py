"""Triage-policy rename: the deprecated /playbooks routes must stay identical to the
canonical /triage-policies routes (same handlers, same payloads) for one release."""

from __future__ import annotations

import os
from uuid import uuid4

os.environ.setdefault("SOCTALK_JWT_SIGNING_KEY", "test-signing-key-32-bytes-plaintext")
os.environ.setdefault("SOCTALK_ADAPTER_SIGNING_KEY", "adapter-signing-key-32-bytes-plaintext")

from fastapi.testclient import TestClient  # noqa: E402
from starlette.middleware.base import BaseHTTPMiddleware  # noqa: E402

from soctalk.core.api.app_v1 import create_app  # noqa: E402
from soctalk.core.tenancy.models import Role, UserType  # noqa: E402


class _NoopDB:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http":
            scope.setdefault("state", {})
            scope["state"]["db"] = None
        await self.app(scope, receive, send)


def _client():
    app = create_app(db_session_middleware=_NoopDB)
    identity = {
        "user_id": str(uuid4()), "email": "a@mssp.example",
        "user_type": UserType.MSSP.value, "role": Role.ANALYST.value,
        "tenant_id": None, "current_tenant": None,
    }

    class _Inject(BaseHTTPMiddleware):
        async def dispatch(self, request, call_next):
            request.state.user_identity = identity
            return await call_next(request)

    app.add_middleware(_Inject)
    return TestClient(app, raise_server_exceptions=False), app


def test_builtins_alias_matches_canonical():
    """GET /api/mssp/playbooks (deprecated) == GET /api/mssp/triage-policies (canonical).
    Built-ins need no DB, so this exercises the real handler over both routes."""
    client, _ = _client()
    legacy = client.get("/api/mssp/playbooks")
    canonical = client.get("/api/mssp/triage-policies")
    assert legacy.status_code == 200 and canonical.status_code == 200
    assert legacy.json() == canonical.json()
    assert any(p["id"] == "dual-use-privileged-exec" for p in canonical.json())


def test_authored_dto_keeps_deprecated_playbook_id_mirror():
    """The renamed wire field is triage_policy_id; the old playbook_id must still ride
    along (same value) for one release so existing clients keep working."""
    from soctalk.core.api.ir import AuthoredTriagePolicyDTO

    dto = AuthoredTriagePolicyDTO(
        triage_policy_id="pb-x", revision=1, status="shadow", definition={}
    )
    body = dto.model_dump()
    assert body["triage_policy_id"] == "pb-x"
    assert body["playbook_id"] == "pb-x"  # deprecated mirror, remove with /playbooks routes


def test_every_authored_playbook_route_has_a_triage_policy_twin():
    """Each /playbooks route has a /triage-policies twin bound to the SAME handler."""
    _, app = _client()
    by_path = {
        (r.path, tuple(sorted(r.methods))): r.endpoint.__name__
        for r in app.routes
        if hasattr(r, "endpoint") and hasattr(r, "methods")
    }
    playbook_routes = [(p, m) for (p, m) in by_path if "/playbooks" in p]
    assert playbook_routes, "expected legacy /playbooks routes to still exist"
    for path, methods in playbook_routes:
        twin = (path.replace("/playbooks", "/triage-policies"), methods)
        assert twin in by_path, f"missing canonical twin for {path} {methods}"
        assert by_path[twin] == by_path[(path, methods)], (
            f"{path} and its triage-policies twin resolve to different handlers"
        )


def test_deprecated_flag_on_legacy_routes():
    """Legacy /playbooks routes are marked deprecated in the OpenAPI schema."""
    _, app = _client()
    schema = app.openapi()
    legacy = [p for p in schema["paths"] if "/playbooks" in p]
    assert legacy
    for path in legacy:
        for method, op in schema["paths"][path].items():
            if method in ("get", "post", "put", "delete"):
                assert op.get("deprecated") is True, f"{method} {path} not marked deprecated"
