"""Bridge endpoints for the canonical ``frontend/`` UI.

The legacy SocTalk dashboard expected ``/api/investigations`` against the
single-tenant ``Investigation`` event-sourcing tables. The V1 multi-tenant
install replaces those with ``cases`` + ``investigation_runs``. This module maps
V1 records into the legacy ``InvestigationSummary``/``Investigation``
shape so ``frontend/`` works against the V1 backend without a rewrite.

Tenant scoping flows from the session:

  * ``mssp_admin`` / ``mssp_analyst`` see all tenants (audience='mssp',
    no ``app.current_tenant_id`` set).
  * ``tenant_*`` roles are pinned to their session tenant via the
    request middleware's ``set_request_db_context``; RLS enforces.
  * ``customer_viewer`` sees only customer-safe content (no verdict
    reasoning, no token spend) — gated UI-side via ``isCustomerScope``.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from fastapi import APIRouter, HTTPException, Request, Query
from pydantic import BaseModel
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from soctalk.core.tenancy.auth import current_identity


router = APIRouter(prefix="/api/investigations", tags=["investigations-bridge"])


class InvestigationSummary(BaseModel):
    id: str
    title: str | None
    status: str
    phase: str
    created_at: str
    updated_at: str
    closed_at: str | None
    alert_count: int
    observable_count: int
    malicious_count: int
    suspicious_count: int
    clean_count: int
    max_severity: str | None
    verdict_decision: str | None
    thehive_case_id: str | None
    # Tenant attribution for the cross-tenant MSSP view: which customer
    # this investigation belongs to. Always populated from RLS-visible
    # rows; the UI hides the column when the session is pinned to a
    # single tenant.
    tenant_id: str | None = None
    tenant_slug: str | None = None
    tenant_display_name: str | None = None


class Investigation(InvestigationSummary):
    time_to_triage_seconds: float | None
    time_to_verdict_seconds: float | None
    verdict_confidence: float | None
    verdict_reasoning: str | None
    threat_actor: str | None
    tags: list[str]
    tokens_used: int | None
    tokens_budget: int | None
    disposition: str | None


class InvestigationList(BaseModel):
    items: list[InvestigationSummary]
    total: int
    page: int
    page_size: int


def _db(request: Request) -> AsyncSession:
    s = getattr(request.state, "db", None)
    if s is None:
        raise HTTPException(500, "db session not attached")
    return s


def _phase_from_status(status: str) -> str:
    # Map IR investigation status onto the legacy ``phase`` field. The legacy UI
    # uses phase as a coarse pipeline marker (triage / analysis /
    # verdict / closed); IR has a richer status set we collapse.
    if status in ("active",):
        return "analysis"
    if status in ("auto_closed_fp", "closed_fp", "closed", "closed_tp"):
        return "closed"
    return status


def _wazuh_severity_label(level: int | None) -> str | None:
    if level is None:
        return None
    if level >= 12:
        return "critical"
    if level >= 8:
        return "high"
    if level >= 5:
        return "medium"
    return "low"


def _disposition(case_status: str, run_status: str | None) -> str | None:
    if case_status in ("auto_closed_fp", "closed_fp"):
        return "close_fp"
    if case_status in ("closed_tp", "escalated"):
        return "escalate"
    if run_status == "halted_budget":
        return "halted_budget"
    if run_status == "failed":
        return "failed"
    return None


@router.get("", response_model=InvestigationList)
async def list_investigations(
    request: Request,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=500),
    status: str | None = None,
    phase: str | None = None,
    severity: str | None = None,
) -> InvestigationList:
    identity = current_identity(request)
    if identity is None:
        raise HTTPException(401, "authentication required")

    db = _db(request)
    where_clauses: list[str] = []
    params: dict[str, Any] = {}
    if status:
        where_clauses.append("c.status = :status")
        params["status"] = status
    if severity:
        sev_map = {"low": (0, 4), "medium": (5, 7), "high": (8, 11), "critical": (12, 15)}
        if severity in sev_map:
            lo, hi = sev_map[severity]
            where_clauses.append("c.severity BETWEEN :sev_lo AND :sev_hi")
            params["sev_lo"] = lo
            params["sev_hi"] = hi
    if phase:
        if phase == "closed":
            where_clauses.append(
                "c.status IN ('auto_closed_fp','closed_fp','closed','closed_tp')"
            )
        elif phase == "analysis":
            where_clauses.append("c.status = 'active'")
    where_sql = ("WHERE " + " AND ".join(where_clauses)) if where_clauses else ""

    rows = (
        await db.execute(
            text(
                f"""
                SELECT c.id, c.short_id, c.title, c.status, c.severity,
                       c.opened_at, c.updated_at, c.closed_at, c.summary,
                       c.close_reason,
                       c.tenant_id,
                       t.slug AS tenant_slug,
                       t.display_name AS tenant_display_name,
                       (
                         SELECT count(*) FROM alerts a WHERE a.investigation_id = c.id
                       ) AS alert_count,
                       (
                         SELECT coalesce(sum(jsonb_array_length(a.initial_iocs)), 0)
                         FROM alerts a WHERE a.investigation_id = c.id
                       ) AS observable_count,
                       (
                         SELECT cr.tokens_used FROM investigation_runs cr
                         WHERE cr.investigation_id = c.id
                         ORDER BY cr.started_at DESC LIMIT 1
                       ) AS tokens_used,
                       (
                         SELECT cr.status FROM investigation_runs cr
                         WHERE cr.investigation_id = c.id
                         ORDER BY cr.started_at DESC LIMIT 1
                       ) AS run_status
                FROM investigations c
                LEFT JOIN tenants t ON t.id = c.tenant_id
                {where_sql}
                ORDER BY c.opened_at DESC
                LIMIT :limit OFFSET :offset
                """
            ),
            {**params, "limit": page_size, "offset": (page - 1) * page_size},
        )
    ).mappings().all()

    total = (
        await db.execute(text(f"SELECT count(*) FROM investigations c {where_sql}"), params)
    ).scalar_one()

    items = [
        InvestigationSummary(
            id=str(r["id"]),
            title=r["title"] or r["short_id"],
            status=r["status"],
            phase=_phase_from_status(r["status"]),
            created_at=r["opened_at"].isoformat(),
            updated_at=r["updated_at"].isoformat(),
            closed_at=r["closed_at"].isoformat() if r["closed_at"] else None,
            alert_count=int(r["alert_count"] or 0),
            observable_count=int(r["observable_count"] or 0),
            malicious_count=0,
            suspicious_count=0,
            clean_count=0,
            max_severity=_wazuh_severity_label(int(r["severity"] or 0)),
            verdict_decision=_disposition(r["status"], r["run_status"]),
            thehive_case_id=None,
            tenant_id=str(r["tenant_id"]) if r["tenant_id"] else None,
            tenant_slug=r["tenant_slug"],
            tenant_display_name=r["tenant_display_name"],
        )
        for r in rows
    ]
    return InvestigationList(items=items, total=int(total), page=page, page_size=page_size)


@router.get("/{investigation_id}", response_model=Investigation)
async def get_investigation(investigation_id: UUID, request: Request) -> Investigation:
    identity = current_identity(request)
    if identity is None:
        raise HTTPException(401, "authentication required")

    db = _db(request)
    row = (
        await db.execute(
            text(
                """
                SELECT c.id, c.short_id, c.title, c.status, c.severity,
                       c.opened_at, c.updated_at, c.closed_at, c.summary,
                       c.close_reason
                FROM investigations c WHERE c.id = :id
                """
            ),
            {"id": str(investigation_id)},
        )
    ).mappings().first()
    if row is None:
        raise HTTPException(404, "investigation not found")

    run = (
        await db.execute(
            text(
                """
                SELECT id, status, tokens_used, tokens_budget,
                       started_at, ended_at, last_error
                FROM investigation_runs WHERE investigation_id = :c
                ORDER BY started_at DESC LIMIT 1
                """
            ),
            {"c": str(investigation_id)},
        )
    ).mappings().first()

    counts = (
        await db.execute(
            text(
                """
                SELECT count(*) AS alert_count,
                       coalesce(sum(jsonb_array_length(initial_iocs)), 0) AS ioc_count
                FROM alerts WHERE investigation_id = :c
                """
            ),
            {"c": str(investigation_id)},
        )
    ).mappings().first()

    closed_at = row["closed_at"]
    opened_at = row["opened_at"]
    ttv = (
        (closed_at - opened_at).total_seconds()
        if closed_at and opened_at
        else None
    )

    disposition = _disposition(
        row["status"], run["status"] if run else None
    )
    verdict_decision = (
        "escalate"
        if disposition == "escalate"
        else "close" if disposition == "close_fp"
        else None
    )

    # Verdict reasoning, summary text, and per-run token spend are
    # MSSP-side operational data. Gate them on the user being any
    # tenant-side principal (customer_viewer or tenant_admin) — keying
    # off ``user_type`` rather than a single role name so future tenant
    # roles are covered automatically.
    user_type_str = (
        identity.user_type.value
        if hasattr(identity.user_type, "value")
        else str(identity.user_type)
    )
    is_customer = user_type_str == "tenant"

    return Investigation(
        id=str(row["id"]),
        title=row["title"] or row["short_id"],
        status=row["status"],
        phase=_phase_from_status(row["status"]),
        created_at=opened_at.isoformat(),
        updated_at=row["updated_at"].isoformat(),
        closed_at=closed_at.isoformat() if closed_at else None,
        alert_count=int(counts["alert_count"] or 0),
        observable_count=int(counts["ioc_count"] or 0),
        malicious_count=0,
        suspicious_count=0,
        clean_count=0,
        max_severity=_wazuh_severity_label(int(row["severity"] or 0)),
        verdict_decision=verdict_decision,
        thehive_case_id=None,
        time_to_triage_seconds=None,
        time_to_verdict_seconds=ttv,
        verdict_confidence=None,
        verdict_reasoning=None if is_customer else (row["close_reason"] or row["summary"]),
        threat_actor=None,
        tags=[],
        tokens_used=None if is_customer else (int(run["tokens_used"]) if run else None),
        tokens_budget=None if is_customer else (int(run["tokens_budget"]) if run else None),
        disposition=disposition,
    )


class TimelineEvent(BaseModel):
    id: str
    investigation_id: str
    event_type: str
    timestamp: str
    data: dict[str, Any]


class EventTimelineResponse(BaseModel):
    events: list[TimelineEvent]
    total: int


@router.get("/{investigation_id}/events", response_model=EventTimelineResponse)
async def get_events(
    investigation_id: UUID,
    request: Request,
    limit: int = Query(100, ge=1, le=500),
) -> EventTimelineResponse:
    identity = current_identity(request)
    if identity is None:
        raise HTTPException(401, "authentication required")

    db = _db(request)
    rows = (
        await db.execute(
            text(
                """
                SELECT event_id, kind, payload, created_at
                FROM investigation_events
                WHERE investigation_id = :c
                ORDER BY seq DESC
                LIMIT :limit
                """
            ),
            {"c": str(investigation_id), "limit": limit},
        )
    ).mappings().all()
    events = [
        TimelineEvent(
            id=str(r["event_id"]),
            investigation_id=str(investigation_id),
            event_type=r["kind"],
            timestamp=r["created_at"].isoformat(),
            data=dict(r["payload"]) if r["payload"] else {},
        )
        for r in rows
    ]
    return EventTimelineResponse(events=events, total=len(events))
