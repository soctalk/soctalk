"""Auth + role decorator tests (security-model §5, §6)."""

from __future__ import annotations

from uuid import uuid4

import pytest
from fastapi import FastAPI, HTTPException, Request
from fastapi.testclient import TestClient

from soctalk.core.tenancy.auth import (
    UserIdentity,
    mint_session_token,
    verify_session_token,
)
from soctalk.core.tenancy.decorators import require_role, require_tenant_role
from soctalk.core.tenancy.models import Role, UserType


def test_mint_and_verify_roundtrip():
    identity = UserIdentity(
        user_id=uuid4(),
        email="alice@example.com",
        user_type=UserType.MSSP.value,
        role=Role.MSSP_ADMIN.value,
    )
    token = mint_session_token(identity)
    back = verify_session_token(token)
    assert back is not None
    assert back.user_id == identity.user_id
    assert back.role == identity.role


def test_tampered_token_rejected():
    identity = UserIdentity(
        user_id=uuid4(),
        email="alice@example.com",
        user_type=UserType.MSSP.value,
        role=Role.MSSP_ADMIN.value,
    )
    token = mint_session_token(identity)
    # flip a bit in the signature
    payload, sig = token.split(".", 1)
    tampered = f"{payload}.{('0' if sig[0] != '0' else '1')}{sig[1:]}"
    assert verify_session_token(tampered) is None


@pytest.fixture
def app_with_guards() -> FastAPI:
    app = FastAPI()

    from fastapi import Depends

    @app.get("/mssp-only", dependencies=[Depends(require_role(Role.MSSP_ADMIN))])
    async def mssp_only():
        return {"ok": True}

    @app.get(
        "/tenant-only",
        dependencies=[Depends(require_tenant_role(Role.CUSTOMER_VIEWER))],
    )
    async def tenant_only():
        return {"ok": True}

    return app


def _attach_identity(request: Request, identity: dict | None):
    request.state.user_identity = identity


def test_require_role_rejects_unauthenticated(app_with_guards):
    # Manually inject middleware that sets request.state.user_identity = None
    from starlette.middleware.base import BaseHTTPMiddleware

    class SetIdentity(BaseHTTPMiddleware):
        async def dispatch(self, request, call_next):
            _attach_identity(request, None)
            return await call_next(request)

    app_with_guards.add_middleware(SetIdentity)
    client = TestClient(app_with_guards)
    resp = client.get("/mssp-only")
    assert resp.status_code == 401


def test_require_role_rejects_wrong_role(app_with_guards):
    from starlette.middleware.base import BaseHTTPMiddleware

    class SetIdentity(BaseHTTPMiddleware):
        async def dispatch(self, request, call_next):
            _attach_identity(request, {
                "user_id": str(uuid4()),
                "user_type": UserType.MSSP.value,
                "role": Role.ANALYST.value,  # wrong for /mssp-only
                "tenant_id": None,
            })
            return await call_next(request)

    app_with_guards.add_middleware(SetIdentity)
    client = TestClient(app_with_guards)
    resp = client.get("/mssp-only")
    assert resp.status_code == 403


def test_require_tenant_role_rejects_mssp_user(app_with_guards):
    from starlette.middleware.base import BaseHTTPMiddleware

    class SetIdentity(BaseHTTPMiddleware):
        async def dispatch(self, request, call_next):
            _attach_identity(request, {
                "user_id": str(uuid4()),
                "user_type": UserType.MSSP.value,
                "role": Role.MSSP_ADMIN.value,
                "tenant_id": None,
            })
            return await call_next(request)

    app_with_guards.add_middleware(SetIdentity)
    client = TestClient(app_with_guards)
    resp = client.get("/tenant-only")
    assert resp.status_code == 403


def test_require_tenant_role_accepts_customer_viewer(app_with_guards):
    from starlette.middleware.base import BaseHTTPMiddleware

    class SetIdentity(BaseHTTPMiddleware):
        async def dispatch(self, request, call_next):
            _attach_identity(request, {
                "user_id": str(uuid4()),
                "user_type": UserType.TENANT.value,
                "role": Role.CUSTOMER_VIEWER.value,
                "tenant_id": str(uuid4()),
            })
            return await call_next(request)

    app_with_guards.add_middleware(SetIdentity)
    client = TestClient(app_with_guards)
    resp = client.get("/tenant-only")
    assert resp.status_code == 200
