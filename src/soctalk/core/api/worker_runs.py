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


async def _record_verdict_memo(
    db, tenant_id, investigation_id, *, decision: str, confidence: float
) -> None:
    """Cache the run's verdict keyed on the investigation's alert shape
    (issue #29). Pulls the shape from the primary alert's latest source
    event; no-op if there's no template to key on."""
    from soctalk.core.ir.memoization import record_verdict, shape_key

    row = (
        await db.execute(
            text(
                """
                SELECT a.source AS source, se.decoder AS decoder,
                       se.template_hash AS template_hash,
                       se.template_version AS template_version
                FROM alerts a
                LEFT JOIN LATERAL (
                    SELECT decoder, template_hash, template_version
                    FROM alert_source_events
                    WHERE alert_id = a.id
                    ORDER BY (template_hash IS NOT NULL) DESC, ingested_at DESC
                    LIMIT 1
                ) se ON true
                WHERE a.investigation_id = :c
                ORDER BY a.severity DESC, a.first_event_at DESC
                LIMIT 1
                """
            ),
            {"c": str(investigation_id)},
        )
    ).mappings().first()
    if row is None:
        return
    key = shape_key(
        source=row["source"], decoder=row["decoder"],
        template_hash=row["template_hash"], template_version=row["template_version"],
    )
    if key is None:
        return
    await record_verdict(
        db, tenant_id=tenant_id, key=key, decision=decision,
        confidence=confidence, template_hash=row["template_hash"],
    )



# Tenant daily spend cap helpers moved to ``soctalk.core.cost`` so the
# chat handler can enforce the same ceiling. Re-export for back-compat.
from soctalk.core.cost import (  # noqa: E402
    assert_tenant_daily_cap_ok,
    tenant_daily_dollar_cap as _tenant_daily_dollar_cap,
    tenant_daily_token_cap as _tenant_daily_token_cap,
)


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
    # ``alert`` is the primary (highest-severity) alert — kept for backward
    # compat. ``alerts`` is the full correlated set (issue #26): one run
    # reasons over every alert #27 grouped onto the investigation.
    alert: dict[str, Any]
    alerts: list[dict[str, Any]] = Field(default_factory=list)


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
        # blown through its rolling 24h spend ceiling. Shared with the
        # chat path via ``soctalk.core.cost.assert_tenant_daily_cap_ok``
        # so a busy chat session can't dodge the worker's cap and a
        # flood of runs can't dodge the chat handler's cap.
        if await assert_tenant_daily_cap_ok(
            db, tenant_id, source="worker_claim"
        ) is None:
            return None

        row = (
            await db.execute(
                text(
                    """
                    SELECT r.id, r.investigation_id, r.tokens_used, r.tokens_budget,
                           r.dollars_used, r.dollars_budget
                    FROM investigation_runs r
                    JOIN investigations i ON i.id = r.investigation_id
                                         AND i.tenant_id = r.tenant_id
                    WHERE r.tenant_id = :t
                      AND r.status = 'active'
                      AND r.not_before <= now()
                      AND (r.claimed_at IS NULL
                           OR r.lease_expires_at < now())
                      -- Don't claim a run whose investigation was closed out
                      -- from under it (e.g. merged away by an analyst,
                      -- review finding #4).
                      AND i.status = 'active'
                    ORDER BY r.started_at ASC
                    FOR UPDATE OF r SKIP LOCKED
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
                    SELECT a.id, a.source, a.rule_id, a.severity, a.signature,
                           a.source_event_ids, a.asset_ids, a.initial_iocs,
                           a.ai_assessment, a.description,
                           se.mitre AS mitre, se.rule_groups AS rule_groups,
                           se.entities AS entities
                    FROM alerts a
                    LEFT JOIN LATERAL (
                        SELECT mitre, rule_groups, entities
                        FROM alert_source_events
                        WHERE alert_id = a.id
                        -- Prefer a source event that actually carries rule
                        -- semantics: a later empty/coalesced v1 event must
                        -- not hide the MITRE/entities of an earlier one.
                        ORDER BY (mitre <> '{}'::jsonb OR entities <> '[]'::jsonb) DESC,
                                 ingested_at DESC
                        LIMIT 1
                    ) se ON true
                    WHERE a.investigation_id = :c
                    ORDER BY a.severity DESC, a.first_event_at DESC
                    """
                ),
                {"c": str(row["investigation_id"])},
            )
        ).mappings().all()
        if not alert:
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

        alert_payloads = [
            {
                "id": str(a["id"]),
                "rule": {"id": a["rule_id"] or "?", "level": int(a["severity"] or 0)},
                "signature": a["signature"],
                # #17 fix 3: prefer the dedicated description column; fall back
                # to ai_assessment for rows written before v1_0018.
                "description": a["description"] or a["ai_assessment"],
                "source_event_ids": list(a["source_event_ids"] or []),
                "asset_ids": list(a["asset_ids"] or []),
                "initial_iocs": list(a["initial_iocs"] or []),
                # #17 fix 2/T6: rule semantics from the evidence store.
                "mitre": a["mitre"] or {},
                "rule_groups": list(a["rule_groups"] or []),
                "entities": list(a["entities"] or []),
            }
            for a in alert
        ]

    return ClaimedRun(
        run_id=row["id"],
        investigation_id=row["investigation_id"],
        tokens_used=row["tokens_used"],
        tokens_budget=row["tokens_budget"],
        dollars_used=float(row["dollars_used"] or 0.0),
        dollars_budget=float(row["dollars_budget"] or 0.0),
        lease_id=lease_id,
        lease_expires_at=lease_expires,
        alert=alert_payloads[0],
        alerts=alert_payloads,
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
            # Write the reopen signature/window alongside the close so an
            # LLM-dismissed FP stays resurrectable by _check_and_reopen()
            # when the same entities show up again — same contract as the
            # rules-based auto_close_alert() path. Same transaction as the
            # close update; the WHERE status='active' guard means we never
            # stamp reopen fields onto an investigation someone else closed.
            from soctalk.core.ir.policies import effective_policy
            from soctalk.core.ir.triage import build_reopen_fields_for_investigation

            policy = await effective_policy(db, tenant_id)
            reopen_sig, reopen_until = await build_reopen_fields_for_investigation(
                db,
                tenant_id=tenant_id,
                investigation_id=investigation_id,
                reopen_window_days=policy.get("reopen_window_days", 30),
            )
            r = await db.execute(
                text(
                    """
                    UPDATE investigations
                       SET status = 'auto_closed_fp',
                           closed_at = now(),
                           close_reason = COALESCE(:reason, close_reason),
                           reopen_signature = CAST(:sig AS JSONB),
                           reopen_window_until = :reopen_until,
                           updated_at = now()
                     WHERE id = :c
                       AND tenant_id = :t
                       AND status = 'active'
                    """
                ),
                {
                    "reason": payload.verdict_summary,
                    "sig": reopen_sig,
                    "reopen_until": reopen_until,
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

        # Verdict memoization write (issue #29): cache this run's verdict
        # keyed on the investigation's alert shape, so a future recurrence
        # of the same shape can be closed by reference. Only meaningful when
        # the run produced a disposition + confidence.
        if (
            payload.status == "completed"
            and payload.disposition in ("close_fp", "escalate")
            and payload.verdict_confidence is not None
        ):
            await _record_verdict_memo(
                db, tenant_id, investigation_id,
                decision="close" if payload.disposition == "close_fp" else "escalate",
                confidence=float(payload.verdict_confidence),
            )

        # Follow-up run (review finding #2): if alerts correlated onto this
        # investigation WHILE the run was executing, they were invisible to
        # the snapshot the graph reasoned over. If the investigation is still
        # active (this run didn't close it) and evidence arrived, start a
        # fresh run over the now-complete alert set and clear the flag. The
        # just-completed run is terminal, so the single-active-run index
        # permits the new one.
        if payload.status == "completed":
            from soctalk.core.ir.runtime import start_run

            fu = (await db.execute(
                text("SELECT has_new_evidence, status FROM investigations "
                     "WHERE id = :c AND tenant_id = :t"),
                {"c": str(investigation_id), "t": str(tenant_id)},
            )).mappings().first()
            if fu and fu["has_new_evidence"] and fu["status"] == "active":
                await db.execute(
                    text("UPDATE investigations SET has_new_evidence = false "
                         "WHERE id = :c AND tenant_id = :t"),
                    {"c": str(investigation_id), "t": str(tenant_id)},
                )
                await start_run(db, tenant_id, investigation_id)
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
