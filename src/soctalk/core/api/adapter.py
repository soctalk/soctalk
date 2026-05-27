"""Adapter-facing internal API.

The tenant adapter (per-tenant sidecar in the tenant namespace) calls these
endpoints to report health, fetch current config, and deliver heartbeats.

Authentication: tenant-bound adapter token signed by SocTalk.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from uuid import UUID

import structlog
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from soctalk.core.ir.triage import triage_event
from soctalk.core.tenancy.context import tenant_context
from soctalk.core.tenancy.models import Tenant

logger = structlog.get_logger()

router = APIRouter(prefix="/api/internal/adapter", tags=["internal-adapter"])


class HeartbeatPayload(BaseModel):
    tenant_id: UUID
    version: str
    health: str  # "ok" | "degraded" | "failing"
    metrics: dict | None = None


def _db(request: Request) -> AsyncSession:
    session = getattr(request.state, "db", None)
    if session is None:
        raise HTTPException(500, "db session not attached to request")
    return session


def _verify_adapter_jwt(request: Request) -> UUID:
    """Extract and verify the adapter JWT; return the tenant_id from claims.

    Adapter tokens are verified with a key separate from the user session key.
    """
    from soctalk.core.tenancy.auth import verify_adapter_token

    auth = request.headers.get("Authorization", "")
    if not auth.lower().startswith("bearer "):
        raise HTTPException(401, "adapter JWT required")
    token = auth.split(" ", 1)[1].strip()
    identity = verify_adapter_token(token)
    if identity is None:
        raise HTTPException(401, "invalid adapter token")
    if identity.tenant_id is None:
        raise HTTPException(400, "adapter token missing tenant_id")
    return identity.tenant_id


@router.post("/heartbeat")
async def heartbeat(payload: HeartbeatPayload, request: Request) -> dict:
    authed_tid = _verify_adapter_jwt(request)
    if authed_tid != payload.tenant_id:
        raise HTTPException(403, "adapter token tenant_id mismatch")

    session = _db(request)
    tenant = (await session.execute(
        select(Tenant).where(Tenant.id == payload.tenant_id)
    )).scalar_one_or_none()
    if tenant is None:
        raise HTTPException(404, "tenant not found")

    # Update runtime snapshot.
    runtime = dict(tenant.runtime)
    runtime.update({
        "version": payload.version,
        "health": payload.health,
        "last_heartbeat": datetime.now(timezone.utc).isoformat(),
        "metrics_snapshot": payload.metrics or {},
    })
    tenant.runtime = runtime
    await session.flush()

    # Observability gauge.
    from soctalk.core.observability.metrics import tenant_adapter_heartbeat_age

    tenant_adapter_heartbeat_age.labels(tenant_id=str(tenant.id)).set(0)
    return {"ok": True}


class IngestedIOC(BaseModel):
    type: str = Field(..., max_length=32)
    value: str = Field(..., max_length=2048)


class AdapterEvent(BaseModel):
    """One Wazuh (or equivalent) event forwarded by the tenant adapter.

    Kept minimal for ingestion — the adapter is expected to pre-normalise
    Wazuh JSON into this shape. Unknown fields on the adapter side can
    travel in ``raw`` for audit but are not indexed.
    """

    source_event_id: str = Field(..., max_length=128)
    source: str = Field(default="wazuh", max_length=32)
    rule_id: str | None = Field(default=None, max_length=64)
    severity: int = Field(ge=0, le=15)
    asset_ids: list[str] = Field(default_factory=list)
    initial_iocs: list[IngestedIOC] = Field(default_factory=list)
    ts: datetime | None = None
    description: str | None = Field(default=None, max_length=1024)
    title: str | None = Field(default=None, max_length=255)
    raw: dict[str, Any] | None = None


class IngestBatch(BaseModel):
    tenant_id: UUID
    events: list[AdapterEvent] = Field(..., max_length=500)


@router.post("/events")
async def ingest_events(payload: IngestBatch, request: Request) -> dict[str, Any]:
    """Wazuh → native IR ingest.

    Adapter posts a batch; each event runs through the triage pipeline,
    which coalesces bursts into alerts, auto-closes high-confidence FPs,
    and promotes the rest into cases. Writes are wrapped in
    ``tenant_context`` so RLS WITH CHECK passes for the app-role session.
    """

    authed_tid = _verify_adapter_jwt(request)
    if authed_tid != payload.tenant_id:
        raise HTTPException(403, "adapter token tenant_id mismatch")

    db = _db(request)
    results: list[dict[str, Any]] = []
    async with tenant_context(db, payload.tenant_id):
        for ev in payload.events:
            outcome = await triage_event(
                db,
                tenant_id=payload.tenant_id,
                source=ev.source,
                rule_id=ev.rule_id,
                severity=ev.severity,
                asset_ids=list(ev.asset_ids),
                initial_iocs=[i.model_dump() for i in ev.initial_iocs],
                source_event_id=ev.source_event_id,
                ts=ev.ts or datetime.now(timezone.utc),
                description=ev.description,
                title=ev.title,
            )
            results.append(outcome)
    return {"ingested": len(results), "outcomes": results}


@router.get("/config")
async def fetch_config(request: Request) -> dict:
    """Adapter pulls a minimal tenant config snapshot for local caches."""
    tid = _verify_adapter_jwt(request)
    session = _db(request)
    tenant = (await session.execute(
        select(Tenant).where(Tenant.id == tid)
    )).scalar_one_or_none()
    if tenant is None:
        raise HTTPException(404, "tenant not found")
    return {
        "tenant_id": str(tenant.id),
        "slug": tenant.slug,
        "display_name": tenant.display_name,
        "state": tenant.state,
        "config": tenant.config,
    }
