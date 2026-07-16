"""Read-only triage policy governance view (#43/#44) — the GET /api/mssp/triage-policies surface.

No DB: the handler serializes the in-process registry. Covers the built-ins, a file-loaded
shadow triage policy, and the role gate.
"""

from __future__ import annotations

import os
from uuid import uuid4

os.environ.setdefault("SOCTALK_JWT_SIGNING_KEY", "test-signing-key-32-bytes-plaintext")
os.environ.setdefault("SOCTALK_ADAPTER_SIGNING_KEY", "adapter-signing-key-32-bytes-plaintext")

from soctalk.core.api.ir import list_triage_policies_route  # noqa: E402
from soctalk.triage_policy.registry import reset_registry_cache  # noqa: E402


async def test_lists_builtin_playbooks():
    playbooks = await list_triage_policies_route(None)  # handler doesn't touch the request/DB
    by_id = {p.id: p for p in playbooks}

    assert "dual-use-privileged-exec" in by_id
    assert "agent-health-operational" in by_id

    dual = by_id["dual-use-privileged-exec"]
    assert dual.source == "built-in"
    assert dual.status == "active"
    assert "sudo" in dual.applies_to.rule_groups
    assert dual.close_signoff_data_classes == ["pci"]
    assert "CLOSE" not in dual.legal_actions.get("triage", [])  # dual-use never short-closes

    health = by_id["agent-health-operational"]
    assert health.deterministic_disposition == "close_operational"

    # priority-sorted (lower first)
    assert [p.priority for p in playbooks] == sorted(p.priority for p in playbooks)


async def test_endpoint_is_builtins_only_ignores_file_dir(tmp_path, monkeypatch):
    """The endpoint reports built-ins only — it must NOT surface the API process's own
    SOCTALK_PLAYBOOK_DIR files (which no worker necessarily governs by)."""
    (tmp_path / "custom.yaml").write_text(
        "id: custom-shadow-pb\n"
        "priority: 70\n"
        "applies_to:\n"
        "  rule_groups: [custom_group]\n"
    )
    monkeypatch.setenv("SOCTALK_PLAYBOOK_DIR", str(tmp_path))
    reset_registry_cache()
    try:
        playbooks = await list_triage_policies_route(None)
        assert all(p.source == "built-in" for p in playbooks)
        assert "custom-shadow-pb" not in {p.id for p in playbooks}
    finally:
        monkeypatch.delenv("SOCTALK_PLAYBOOK_DIR", raising=False)
        reset_registry_cache()


def test_playbooks_route_role_gate():
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

    viewer = {
        "user_id": str(uuid4()), "email": "v@acme.example",
        "user_type": UserType.TENANT.value, "role": Role.CUSTOMER_VIEWER.value,
        "tenant_id": str(uuid4()), "current_tenant": None,
    }
    analyst = {
        "user_id": str(uuid4()), "email": "a@mssp.example",
        "user_type": UserType.MSSP.value, "role": Role.ANALYST.value,
        "tenant_id": None, "current_tenant": None,
    }
    url = "/api/mssp/playbooks"

    cv = TestClient(_app_as(viewer), raise_server_exceptions=False)
    assert cv.get(url).status_code == 403

    ca = TestClient(_app_as(analyst), raise_server_exceptions=False)
    resp = ca.get(url)
    assert resp.status_code == 200  # no DB needed — analyst reads the registry
    assert any(p["id"] == "dual-use-privileged-exec" for p in resp.json())
