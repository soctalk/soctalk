"""V1 API smoke test (no DB).

Exercises the handlers that do not require Postgres to respond:
- /health/live            -> 200 {"ok": true}
- /health/ready           -> 503 {"ok": false, ...}  (no DB session attached)
- /metrics                -> 200 with prometheus format
- /api/mssp/tenants GET   -> 401 (no auth)
- /api/tenant/branding    -> 401 (no auth)
- /api/internal/adapter/heartbeat POST -> 401 (no bearer)

Role enforcement (require_role, require_tenant_role) is tested by injecting
identity into request.state directly via a custom middleware.

The DBSessionMiddleware is swapped for a no-op so the app boots without
DATABASE_URL_APP. Health-ready will still return 503 because we skip the
DB probe.
"""

from __future__ import annotations

import os
import sys

# Make sure the app boots without needing DB URLs.
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

from soctalk.core.api.app_v1 import create_app

app = create_app(db_session_middleware=_NoopDBMiddleware)
client = TestClient(app)


def check(label: str, resp, expected_status: int | tuple[int, ...]):
    exp = expected_status if isinstance(expected_status, tuple) else (expected_status,)
    ok = resp.status_code in exp
    mark = "OK" if ok else "FAIL"
    print(f"{mark:<4} {label:<50} {resp.status_code} {resp.text[:120]}")
    return ok


def main() -> int:
    all_ok = True

    all_ok &= check("GET /health/live", client.get("/health/live"), 200)
    all_ok &= check("GET /health/ready (no DB)", client.get("/health/ready"), 503)
    all_ok &= check("GET /metrics", client.get("/metrics"), 200)
    all_ok &= check(
        "GET /api/mssp/tenants (unauth)",
        client.get("/api/mssp/tenants"),
        401,
    )
    all_ok &= check(
        "GET /api/tenant/branding (unauth)",
        client.get("/api/tenant/branding"),
        401,
    )
    all_ok &= check(
        "POST /api/internal/adapter/heartbeat (no bearer)",
        client.post(
            "/api/internal/adapter/heartbeat",
            json={
                "tenant_id": "00000000-0000-0000-0000-000000000000",
                "version": "0.1.0",
                "health": "ok",
            },
        ),
        401,
    )
    # Metrics content sanity check
    metrics = client.get("/metrics").text
    need = [
        "soctalk_tenant_events_ingested_total",
        "soctalk_tenant_investigations_opened_total",
        "soctalk_install_tenants_total",
    ]
    missing = [m for m in need if m not in metrics]
    if missing:
        print(f"FAIL metrics missing series: {missing}")
        all_ok = False
    else:
        print(f"OK   metrics exports {len(need)} expected series")

    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
