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
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from soctalk.core.ir.triage import triage_event
from soctalk.core.tenancy.context import tenant_context
from soctalk.core.tenancy.models import Tenant
from soctalk_wire import SCHEMA_VERSION as WIRE_SCHEMA_VERSION
from soctalk_wire import IngestBatch, redact_text

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


@router.post("/events")
async def ingest_events(payload: IngestBatch, request: Request) -> dict[str, Any]:
    """Wazuh → native IR ingest.

    The batch is validated against the shared ``soctalk_wire`` schema. Each
    event runs through the triage pipeline, which now reserves an
    idempotency key in ``alert_source_events`` first (a replay no-ops),
    coalesces bursts into alerts, auto-closes high-confidence FPs, and
    promotes the rest into cases. Writes are wrapped in ``tenant_context``
    so RLS WITH CHECK passes for the app-role session.

    Following the Netflix Dispatch "filter action" pattern, the response
    reports the disposition of EVERY event — including ``duplicate`` and
    ``skipped_schema`` — so a consumer can account for coverage rather than
    infer it from a bare count. ``schema_version`` on the batch drives
    additive-only handling: a higher-than-supported version is processed
    best-effort (unknown fields already ignored by the model) with a warning.
    """

    authed_tid = _verify_adapter_jwt(request)
    if authed_tid != payload.tenant_id:
        raise HTTPException(403, "adapter token tenant_id mismatch")

    if payload.schema_version > WIRE_SCHEMA_VERSION:
        logger.warning(
            "adapter_batch_newer_schema",
            tenant_id=str(payload.tenant_id),
            batch_schema_version=payload.schema_version,
            supported=WIRE_SCHEMA_VERSION,
        )

    db = _db(request)
    results: list[dict[str, Any]] = []
    counts: dict[str, int] = {}
    # Defense-in-depth: re-run redaction server-side over every text path.
    # New adapters already redact (markers no-op on re-run); PRE-redaction
    # adapters deployed before this change would otherwise persist raw
    # secrets — this closes that window before anything is stored.
    async with tenant_context(db, payload.tenant_id):
        for ev in payload.events:
            desc = redact_text(ev.description)
            title = redact_text(ev.title)
            full_log = redact_text(ev.full_log)
            evidence = {
                "observed_at": ev.observed_at,
                "full_log": full_log,
                "entities": [e.model_dump() for e in ev.entities],
                "mitre": ev.mitre.model_dump() if ev.mitre else {},
                "rule_groups": list(ev.rule_groups),
                "decoder": ev.decoder,
                "template_hash": ev.template_hash,
                "template_version": ev.template_version,
                "redaction_version": ev.redaction_version,
                "schema_version": payload.schema_version,
                "batch_seq": payload.batch_seq,
            }
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
                description=desc,
                title=title,
                evidence=evidence,
            )
            results.append(outcome)
            counts[outcome.get("action", "unknown")] = (
                counts.get(outcome.get("action", "unknown"), 0) + 1
            )
    return {
        "ingested": len(results),
        "action_counts": counts,
        "outcomes": results,
    }


class CheckpointBody(BaseModel):
    tenant_id: UUID
    source: str = Field(default="wazuh", max_length=32)
    cursor_ts: str | None = Field(default=None, max_length=64)
    cursor_event_id: str | None = Field(default=None, max_length=128)
    batch_seq: int | None = Field(default=None, ge=0)
    # Alertmanager-style loss accounting: total events the adapter shed to
    # its rate limiter since boot, so a quiet period is distinguishable
    # from a dropped one on the control-plane side.
    dropped_total: int | None = Field(default=None, ge=0)


@router.get("/checkpoint")
async def get_checkpoint(request: Request, source: str = "wazuh") -> dict:
    """Durable ingest cursor (issue #17 fix 6). Restart-safe: the adapter
    resumes from here instead of an in-memory cursor that resets on pod
    replacement."""
    tid = _verify_adapter_jwt(request)
    db = _db(request)
    async with tenant_context(db, tid):
        row = (
            await db.execute(
                text(
                    "SELECT cursor_ts, cursor_event_id, batch_seq, dropped_total "
                    "FROM adapter_checkpoints WHERE tenant_id = :t AND source = :s"
                ),
                {"t": str(tid), "s": source},
            )
        ).mappings().first()
    if row is None:
        return {"tenant_id": str(tid), "source": source, "cursor_ts": None,
                "cursor_event_id": None, "batch_seq": 0, "dropped_total": 0}
    return {"tenant_id": str(tid), "source": source, **dict(row)}


@router.put("/checkpoint")
async def put_checkpoint(payload: CheckpointBody, request: Request) -> dict:
    authed_tid = _verify_adapter_jwt(request)
    if authed_tid != payload.tenant_id:
        raise HTTPException(403, "adapter token tenant_id mismatch")
    db = _db(request)
    async with tenant_context(db, payload.tenant_id):
        await db.execute(
            text(
                """
                INSERT INTO adapter_checkpoints
                  (tenant_id, source, cursor_ts, cursor_event_id, batch_seq,
                   dropped_total, updated_at)
                VALUES (:t, :s, :cts, :ceid, COALESCE(:bseq, 0),
                        COALESCE(:dropped, 0), now())
                ON CONFLICT (tenant_id, source) DO UPDATE SET
                    -- Monotonic cursor: a delayed/stale writer must never move
                    -- the durable cursor backward (ISO-8601 sorts lexically, so
                    -- GREATEST on the text is a valid time comparison). Only
                    -- overwrite the event-id tie-breaker when the timestamp
                    -- actually advances.
                    cursor_ts = GREATEST(
                        adapter_checkpoints.cursor_ts, EXCLUDED.cursor_ts
                    ),
                    cursor_event_id = CASE
                        WHEN EXCLUDED.cursor_ts >= adapter_checkpoints.cursor_ts
                        THEN EXCLUDED.cursor_event_id
                        ELSE adapter_checkpoints.cursor_event_id
                    END,
                    batch_seq = GREATEST(adapter_checkpoints.batch_seq, EXCLUDED.batch_seq),
                    dropped_total = GREATEST(adapter_checkpoints.dropped_total, EXCLUDED.dropped_total),
                    updated_at = now()
                """
            ),
            {
                "t": str(payload.tenant_id),
                "s": payload.source,
                "cts": payload.cursor_ts,
                "ceid": payload.cursor_event_id,
                "bseq": payload.batch_seq,
                "dropped": payload.dropped_total,
            },
        )
    return {"ok": True}


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
