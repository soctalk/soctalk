"""Liveness / readiness probes for SocTalk API.

- ``GET /health/live``: process is running (200).
- ``GET /health/ready``: 200 only if DB reachable; **503** on failure
  so Kubernetes readiness probes mark unready pods correctly.
"""

from __future__ import annotations

from fastapi import APIRouter, Request, Response, status
from sqlalchemy import text

from soctalk.core.auth.config import get_auth_mode

router = APIRouter(tags=["health"])


@router.get("/health/live")
async def live() -> dict:
    return {"ok": True, "auth_mode": get_auth_mode().value}


@router.get("/health/ready")
async def ready(request: Request, response: Response) -> dict:
    """Return 200 when DB is reachable; 503 otherwise."""
    session = getattr(request.state, "db", None)
    if session is None:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        return {"ok": False, "reason": "no db session"}
    try:
        await session.execute(text("SELECT 1"))
    except Exception as e:  # noqa: BLE001
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        return {"ok": False, "reason": f"db probe failed: {e}"}
    return {"ok": True}
