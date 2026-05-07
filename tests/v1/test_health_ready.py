"""Health /ready success path."""

from __future__ import annotations

import os

os.environ.setdefault(
    "SOCTALK_JWT_SIGNING_KEY", "session-key-for-test-only-32-bytes-ok"
)

class _StubSession:
    async def execute(self, *args, **kwargs):
        return self

    def scalar(self):
        return 1


class _StubDBMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http":
            scope.setdefault("state", {})
            scope["state"]["db"] = _StubSession()
        await self.app(scope, receive, send)


from fastapi.testclient import TestClient

from soctalk.core.api.app_v1 import create_app

client = TestClient(create_app(db_session_middleware=_StubDBMiddleware))


def test_health_ready_success():
    resp = client.get("/health/ready")
    assert resp.status_code == 200
    assert resp.json() == {"ok": True}


def test_health_live_always_ok():
    resp = client.get("/health/live")
    assert resp.status_code == 200
    body = resp.json()
    assert body["ok"] is True
    assert body.get("auth_mode") in {"internal", "proxy"}
