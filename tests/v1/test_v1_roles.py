"""V1 role-based authz tests.

Injects synthetic identity via request.state and confirms role gates.
"""

from __future__ import annotations

import os
import sys
from uuid import uuid4

os.environ.setdefault("DATABASE_URL_APP", "sqlite+aiosqlite:///:memory:")
os.environ.setdefault("DATABASE_URL_MSSP", "sqlite+aiosqlite:///:memory:")

class _NoopDBMiddleware:
    def __init__(self, app):
        self.app = app
    async def __call__(self, scope, receive, send):
        if scope["type"] == "http":
            scope.setdefault("state", {})
            scope["state"]["db"] = None
        await self.app(scope, receive, send)

from fastapi.testclient import TestClient
from starlette.middleware.base import BaseHTTPMiddleware

from soctalk.core.api.app_v1 import create_app
from soctalk.core.tenancy.models import Role, UserType


def make_app_with_identity(identity: dict):
    app = create_app(db_session_middleware=_NoopDBMiddleware)

    class Inject(BaseHTTPMiddleware):
        async def dispatch(self, request, call_next):
            request.state.user_identity = identity
            return await call_next(request)

    app.add_middleware(Inject)
    return app


def check(label: str, resp, expected: int):
    mark = "OK" if resp.status_code == expected else "FAIL"
    print(f"{mark:<4} {label:<70} {resp.status_code}")
    return resp.status_code == expected


def main() -> int:
    all_ok = True

    tenant_id = str(uuid4())

    def _id(role, utype, tid, email):
        return {
            "user_id": str(uuid4()),
            "email": email,
            "user_type": utype,
            "role": role,
            "tenant_id": tid,
            "current_tenant": None,
        }

    mssp_admin = _id(Role.MSSP_ADMIN.value, UserType.MSSP.value, None, "admin@mssp.example")
    analyst = _id(Role.ANALYST.value, UserType.MSSP.value, None, "analyst@mssp.example")
    customer_viewer = _id(Role.CUSTOMER_VIEWER.value, UserType.TENANT.value, tenant_id, "v@acme.example")
    customer_no_tid = _id(Role.CUSTOMER_VIEWER.value, UserType.TENANT.value, None, "v@acme.example")

    # Tenants routes require MSSP-side role.
    c_admin = TestClient(make_app_with_identity(mssp_admin))
    c_analyst = TestClient(make_app_with_identity(analyst))
    c_viewer = TestClient(make_app_with_identity(customer_viewer))
    c_viewer_bad = TestClient(make_app_with_identity(customer_no_tid))

    # 1. mssp_admin can list tenants (reaches handler, DB=None -> 500; we only
    #    want to prove role gate lets it past. 500 is proof the gate opened.)
    all_ok &= check(
        "mssp_admin -> GET /api/mssp/tenants (gate opens, DB 500)",
        c_admin.get("/api/mssp/tenants"),
        500,
    )

    # 2. analyst can list (same reason).
    all_ok &= check(
        "analyst -> GET /api/mssp/tenants",
        c_analyst.get("/api/mssp/tenants"),
        500,
    )

    # 3. analyst CANNOT create tenant (create requires platform/mssp admin).
    all_ok &= check(
        "analyst -> POST /api/mssp/tenants (expect 403)",
        c_analyst.post(
            "/api/mssp/tenants",
            json={"slug": "acme", "display_name": "Acme"},
        ),
        403,
    )

    # 4. customer_viewer cannot hit any /api/mssp/*.
    all_ok &= check(
        "customer_viewer -> GET /api/mssp/tenants (expect 403)",
        c_viewer.get("/api/mssp/tenants"),
        403,
    )

    # 5. customer_viewer CAN hit /api/tenant/branding (DB None -> 500 but gate
    #    opens; proves user_type=tenant + role passes require_tenant_role).
    all_ok &= check(
        "customer_viewer -> GET /api/tenant/branding (gate opens)",
        c_viewer.get("/api/tenant/branding"),
        500,
    )

    # 6. customer_viewer without tenant_id gets 400 from require_tenant_role.
    all_ok &= check(
        "customer_viewer without tenant_id -> /api/tenant/branding (400)",
        c_viewer_bad.get("/api/tenant/branding"),
        400,
    )

    # 7. mssp_admin cannot hit /api/tenant/branding (tenant-only endpoint).
    all_ok &= check(
        "mssp_admin -> GET /api/tenant/branding (expect 403)",
        c_admin.get("/api/tenant/branding"),
        403,
    )

    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
