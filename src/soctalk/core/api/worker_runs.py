"""Runs-worker-facing internal API.

The per-tenant L2 runs-worker calls these endpoints to claim active
investigation_runs, extend the lease while a graph invocation is in flight, and
post the terminal result. L1 owns workflow state; the worker only
executes locally and reports back over this protocol.

Authentication: tenant-bound runs-worker token signed by SocTalk.
Same signing key as the adapter token, distinguished by user_type +
scope claims.
"""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import UUID, uuid4

import structlog
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from soctalk.core.tenancy.context import tenant_context

logger = structlog.get_logger()

router = APIRouter(prefix="/api/internal/worker", tags=["internal-worker"])

LEASE_TTL_SECONDS = 60


def _tenant_daily_token_cap() -> int:
    """Per-tenant rolling 24h token ceiling enforced at claim time.

    Acts as a circuit breaker against runaway alert volume — independent
    of the per-run cap which can be defeated by a flood of cheap runs.
    Default ``10_000_000`` (10M tokens, ~$50 at Sonnet mixed rates).
    Override via ``SOCTALK_TENANT_DAILY_TOKEN_CAP``.
    """
    raw = os.getenv("SOCTALK_TENANT_DAILY_TOKEN_CAP", "")
    try:
        v = int(raw) if raw else 10_000_000
    except ValueError:
        v = 10_000_000
    return v if v > 0 else 10_000_000


def _tenant_daily_dollar_cap() -> float:
    """Per-tenant rolling 24h dollar ceiling.

    Companion to the token cap — whichever bites first stops claims for
    the rest of the UTC day. Default ``50.0``. Override via
    ``SOCTALK_TENANT_DAILY_DOLLAR_CAP``.
    """
    raw = os.getenv("SOCTALK_TENANT_DAILY_DOLLAR_CAP", "")
    try:
        v = float(raw) if raw else 50.0
    except ValueError:
        v = 50.0
    return v if v > 0 else 50.0


def _db(request: Request) -> AsyncSession:
    session = getattr(request.state, "db", None)
    if session is None:
        raise HTTPException(500, "db session not attached to request")
    return session


def _verify_worker_jwt(request: Request) -> UUID:
    from soctalk.core.tenancy.auth import verify_worker_token

    auth = request.headers.get("Authorization", "")
    if not auth.lower().startswith("bearer "):
        raise HTTPException(401, "worker JWT required")
    token = auth.split(" ", 1)[1].strip()
    identity = verify_worker_token(token)
    if identity is None:
        raise HTTPException(401, "invalid worker token")
    if identity.tenant_id is None:
        raise HTTPException(400, "worker token missing tenant_id")
    return identity.tenant_id


class ClaimedRun(BaseModel):
    run_id: UUID
    investigation_id: UUID
    tokens_used: int
    tokens_budget: int
    dollars_used: float = 0.0
    dollars_budget: float = 0.0
    lease_id: UUID
    lease_expires_at: datetime
    alert: dict[str, Any]


class HeartbeatPayload(BaseModel):
    lease_id: UUID
    tokens_used: int = Field(ge=0)
    # ``None`` preserves the stored value (see CompletePayload).
    dollars_used: float | None = Field(default=None, ge=0.0)


class CompletePayload(BaseModel):
    lease_id: UUID
    status: str = Field(pattern=r"^(completed|halted_budget|failed)$")
    tokens_used: int = Field(ge=0)
    # ``None`` (or absent) means "the caller didn't track $; preserve
    # whatever the DB has". Important during mixed-version rolling
    # upgrades where the prior heartbeat may have persisted real spend.
    dollars_used: float | None = Field(default=None, ge=0.0)
    last_error: str | None = Field(default=None, max_length=4096)
    disposition: str | None = Field(
        default=None, pattern=r"^(close_fp|escalate|leave_open)$"
    )
    verdict_summary: str | None = Field(default=None, max_length=1024)
    verdict_confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    findings: list[str] = Field(default_factory=list)
    enrichments: dict[str, Any] = Field(default_factory=dict)


@router.post("/runs/claim", response_model=ClaimedRun | None)
async def claim_run(request: Request) -> ClaimedRun | None:
    """Claim the oldest active run for the caller's tenant.

    Returns ``null`` (HTTP 200) when nothing is available — keeps the
    worker loop simple. Uses ``FOR UPDATE SKIP LOCKED`` so multiple
    replicas can poll without contention.
    """
    tenant_id = _verify_worker_jwt(request)
    worker_label = request.headers.get("X-Worker-Id") or "runs-worker"
    db = _db(request)

    async with tenant_context(db, tenant_id):
        # Circuit breaker: refuse to claim new runs once the tenant has
        # blown through its rolling 24h spend ceiling. This is the only
        # guard that bites *across* runs — the per-run cap can't see a
        # flood of cheap runs adding up.
        #
        # Window keyed on *when the spend happened*, not when the row
        # was inserted. Precedence:
        #   1. ``ended_at`` — set when the run completes/fails.
        #   2. ``lease_expires_at`` — refreshed by every heartbeat
        #      (currently ~30s cadence). For long-running active runs
        #      this is the only timestamp that stays current; without
        #      it, a run that has been live for >24h would fall outside
        #      the window and let its accumulated spend dodge the cap.
        #   3. ``claimed_at`` — for runs claimed but no heartbeat yet.
        #   4. ``started_at`` — last-resort, queued/unclaimed rows
        #      (where tokens_used is 0 anyway, so harmless).
        daily = (
            await db.execute(
                text(
                    """
                    SELECT COALESCE(SUM(tokens_used), 0)::bigint AS tokens,
                           COALESCE(SUM(dollars_used), 0)::float AS dollars
                    FROM investigation_runs
                    WHERE tenant_id = :t
                      AND COALESCE(ended_at, lease_expires_at, claimed_at, started_at)
                          >= now() - interval '24 hours'
                    """
                ),
                {"t": str(tenant_id)},
            )
        ).mappings().first()
        token_cap = _tenant_daily_token_cap()
        dollar_cap = _tenant_daily_dollar_cap()
        if daily is not None and (
            int(daily["tokens"]) >= token_cap
            or float(daily["dollars"]) >= dollar_cap
        ):
            logger.warning(
                "tenant_daily_cap_hit",
                tenant_id=str(tenant_id),
                tokens_24h=int(daily["tokens"]),
                token_cap=token_cap,
                dollars_24h=round(float(daily["dollars"]), 4),
                dollar_cap=dollar_cap,
            )
            return None

        row = (
            await db.execute(
                text(
                    """
                    SELECT id, investigation_id, tokens_used, tokens_budget,
                           dollars_used, dollars_budget
                    FROM investigation_runs
                    WHERE tenant_id = :t
                      AND status = 'active'
                      AND (claimed_at IS NULL
                           OR lease_expires_at < now())
                    ORDER BY started_at ASC
                    FOR UPDATE SKIP LOCKED
                    LIMIT 1
                    """
                ),
                {"t": str(tenant_id)},
            )
        ).mappings().first()
        if row is None:
            return None

        lease_id = uuid4()
        lease_expires = datetime.now(timezone.utc) + timedelta(
            seconds=LEASE_TTL_SECONDS
        )
        await db.execute(
            text(
                """
                UPDATE investigation_runs
                   SET claimed_by = :w,
                       claimed_at = now(),
                       lease_id = :lid,
                       lease_expires_at = :exp
                 WHERE id = :id
                """
            ),
            {
                "w": worker_label[:64],
                "lid": str(lease_id),
                "exp": lease_expires,
                "id": str(row["id"]),
            },
        )

        alert = (
            await db.execute(
                text(
                    """
                    SELECT id, source, rule_id, severity, signature,
                           source_event_ids, asset_ids, initial_iocs,
                           ai_assessment
                    FROM alerts
                    WHERE investigation_id = :c
                    ORDER BY first_event_at DESC
                    LIMIT 1
                    """
                ),
                {"c": str(row["investigation_id"])},
            )
        ).mappings().first()
        if alert is None:
            return ClaimedRun(
                run_id=row["id"],
                investigation_id=row["investigation_id"],
                tokens_used=row["tokens_used"],
                tokens_budget=row["tokens_budget"],
                dollars_used=float(row["dollars_used"] or 0.0),
                dollars_budget=float(row["dollars_budget"] or 0.0),
                lease_id=lease_id,
                lease_expires_at=lease_expires,
                alert={
                    "id": str(row["id"]),
                    "rule": {"id": "n/a", "level": 0},
                },
            )

        alert_payload = {
            "id": str(alert["id"]),
            "rule": {
                "id": alert["rule_id"] or "?",
                "level": int(alert["severity"] or 0),
            },
            "signature": alert["signature"],
            "description": alert["ai_assessment"],
            "source_event_ids": list(alert["source_event_ids"] or []),
            "asset_ids": list(alert["asset_ids"] or []),
            "initial_iocs": list(alert["initial_iocs"] or []),
        }

    return ClaimedRun(
        run_id=row["id"],
        investigation_id=row["investigation_id"],
        tokens_used=row["tokens_used"],
        tokens_budget=row["tokens_budget"],
        dollars_used=float(row["dollars_used"] or 0.0),
        dollars_budget=float(row["dollars_budget"] or 0.0),
        lease_id=lease_id,
        lease_expires_at=lease_expires,
        alert=alert_payload,
    )


@router.post("/runs/{run_id}/heartbeat")
async def heartbeat_run(
    run_id: UUID, payload: HeartbeatPayload, request: Request
) -> dict[str, Any]:
    """Extend the lease and persist current ``tokens_used`` + ``dollars_used``.

    Persisting both at heartbeat time is what keeps the per-run dollar
    cap honest across worker crashes: if the lease expires mid-run and
    a different worker picks the run back up, it must see the spend
    that was already incurred or it can blow through the cap a second
    time at no further cost to the runaway customer.
    """
    tenant_id = _verify_worker_jwt(request)
    db = _db(request)
    new_expiry = datetime.now(timezone.utc) + timedelta(
        seconds=LEASE_TTL_SECONDS
    )
    async with tenant_context(db, tenant_id):
        result = await db.execute(
            text(
                """
                UPDATE investigation_runs
                   SET tokens_used = :u,
                       dollars_used = COALESCE(:d, dollars_used),
                       lease_expires_at = :exp
                 WHERE id = :id
                   AND tenant_id = :t
                   AND lease_id = :lid
                   AND status = 'active'
                """
            ),
            {
                "u": payload.tokens_used,
                "d": payload.dollars_used,
                "exp": new_expiry,
                "id": str(run_id),
                "t": str(tenant_id),
                "lid": str(payload.lease_id),
            },
        )
        if result.rowcount == 0:
            raise HTTPException(409, "lease expired or run not active")
    return {"ok": True, "lease_expires_at": new_expiry.isoformat()}


@router.post("/runs/{run_id}/complete")
async def complete_run(
    run_id: UUID, payload: CompletePayload, request: Request
) -> dict[str, Any]:
    """Mark the run terminal and optionally apply the verdict to the investigation.

    Idempotent on (run_id, lease_id). When ``disposition`` is supplied
    the parent ``cases`` row transitions atomically with the case_run:

      - ``close_fp`` → ``cases.status='auto_closed_fp'``, ``closed_at=now()``
      - ``escalate`` → leaves ``cases.status='active'``, sets ``severity``
        to at least 12 so the row sorts to the top of the MSSP queue
      - ``leave_open`` (or omitted) → no change to the investigation
    """
    tenant_id = _verify_worker_jwt(request)
    db = _db(request)
    investigation_id: UUID | None = None
    case_changed = False
    async with tenant_context(db, tenant_id):
        row = (
            await db.execute(
                text(
                    """
                    UPDATE investigation_runs
                       SET status = :s,
                           tokens_used = :u,
                           dollars_used = COALESCE(:d, dollars_used),
                           last_error = :e,
                           ended_at = now(),
                           lease_id = NULL,
                           lease_expires_at = NULL,
                           claimed_at = NULL,
                           claimed_by = NULL
                     WHERE id = :id
                       AND tenant_id = :t
                       AND lease_id = :lid
                       AND status = 'active'
                    RETURNING investigation_id
                    """
                ),
                {
                    "s": payload.status,
                    "u": payload.tokens_used,
                    "d": payload.dollars_used,
                    "e": payload.last_error,
                    "id": str(run_id),
                    "t": str(tenant_id),
                    "lid": str(payload.lease_id),
                },
            )
        ).mappings().first()
        if row is None:
            raise HTTPException(409, "lease expired or run not active")
        investigation_id = row["investigation_id"]

        if payload.status == "completed" and payload.disposition == "close_fp":
            r = await db.execute(
                text(
                    """
                    UPDATE investigations
                       SET status = 'auto_closed_fp',
                           closed_at = now(),
                           close_reason = COALESCE(:reason, close_reason),
                           updated_at = now()
                     WHERE id = :c
                       AND tenant_id = :t
                       AND status = 'active'
                    """
                ),
                {
                    "reason": payload.verdict_summary,
                    "c": str(investigation_id),
                    "t": str(tenant_id),
                },
            )
            case_changed = (r.rowcount or 0) > 0
        elif payload.status == "completed" and payload.disposition == "escalate":
            # Event-sourced HIL request: appends the canonical event
            # AND performs the V1-schema side effects (severity bump +
            # pending_reviews queue row) in the same transaction. See
            # ``soctalk.core.ir.review_events`` for the why behind
            # not using the legacy projector.
            from soctalk.core.ir.review_events import (
                record_human_review_requested,
            )

            await record_human_review_requested(
                db,
                investigation_id=investigation_id,
                tenant_id=tenant_id,
                reason=payload.verdict_summary,
                verdict_decision="escalate",
                verdict_confidence=payload.verdict_confidence,
                findings=payload.findings,
                enrichments=payload.enrichments,
            )
            case_changed = True
    logger.info(
        "case_run_completed",
        run_id=str(run_id),
        investigation_id=str(investigation_id) if investigation_id else None,
        tenant_id=str(tenant_id),
        status=payload.status,
        tokens_used=payload.tokens_used,
        disposition=payload.disposition,
        case_changed=case_changed,
    )
    return {"ok": True, "case_changed": case_changed}


async def reap_expired_leases(db: AsyncSession) -> int:
    """Reset stale claims so a crashed worker doesn't strand a run.

    Called periodically by the L1 lease-reaper background task.
    """
    result = await db.execute(
        text(
            """
            UPDATE investigation_runs
               SET claimed_by = NULL,
                   claimed_at = NULL,
                   lease_id = NULL,
                   lease_expires_at = NULL
             WHERE status = 'active'
               AND lease_expires_at IS NOT NULL
               AND lease_expires_at < now()
            """
        )
    )
    return result.rowcount or 0
