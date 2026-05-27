"""Empty-default stubs for legacy single-tenant API surfaces.

The canonical V1 frontend was lifted from the single-tenant SocTalk
codebase and still calls a handful of routes that haven't been bridged
to the V1 cases/investigation_runs model: ``/api/events/stream`` (SSE),
``/api/review/*``, ``/api/analytics/*``, ``/api/audit/*``,
``/api/settings``. Until those bridges land we return empty/default
shapes so the pages render without an error banner.

Auth: every route here is gated by the same session middleware; an
unauthenticated request gets the layout's pre-login probe handling
(401 → user=null on the SPA).

Side-effecting routes (POST /review/{id}/approve, etc.) intentionally
404 — they're disabled until the real bridge lands.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from soctalk.core.tenancy.auth import current_identity


# All stubs sit behind the same session middleware as the rest of the
# canonical-frontend bridges. The middleware *attaches* identity but
# does not reject unauthenticated requests on its own — every router
# handler is responsible for the gate. Hang ``current_identity`` on
# the router so an unauthenticated GET hits 401 here instead of
# tunneling all the way through to a stub response (especially the
# long-lived /api/events/stream SSE).
router = APIRouter(tags=["legacy-stubs"], dependencies=[Depends(current_identity)])


# ---------------------------------------------------------------------------
# /api/events/stream — SSE heartbeat
# ---------------------------------------------------------------------------


@router.get("/api/events/stream")
async def events_stream(request: Request) -> StreamingResponse:
    """Open-ended SSE stream that emits a ``ping`` every 25s.

    The frontend's ``initSSE`` opens an EventSource against this path on
    every authenticated page. Returning a real SSE stream (instead of
    404) keeps the layout's "Live"/"Offline" badge accurate and lets us
    layer real events on later without a frontend change.

    Connection-pool note: the request goes through ``DBSessionMiddleware``
    which holds an ``AsyncSession`` open for the request lifetime — for
    a long-lived stream that means the session lingers indefinitely and
    multi-tab users would drain the pool. The auth dependency
    (``current_identity``) ran before this handler, so we explicitly
    close the session before entering the yield loop and let the
    middleware's ``finally`` find an already-closed session (no-op).
    """

    db = getattr(request.state, "db", None)
    if db is not None:
        try:
            await db.close()
        except Exception:  # noqa: BLE001
            pass

    async def gen():
        # Emit one initial ``open`` so the client flips to Connected.
        yield "event: ping\n" + "data: {}\n\n"
        try:
            while True:
                if await request.is_disconnected():
                    break
                await asyncio.sleep(25)
                yield "event: ping\n" + "data: {}\n\n"
        except asyncio.CancelledError:
            return

    headers = {
        "Cache-Control": "no-cache",
        "Connection": "keep-alive",
        "X-Accel-Buffering": "no",
    }
    return StreamingResponse(gen(), media_type="text/event-stream", headers=headers)


# ---------------------------------------------------------------------------
# /api/review/pending — bridged to the V1 pending_reviews table
# ---------------------------------------------------------------------------


class _PendingReviewItem(BaseModel):
    id: str
    investigation_id: str
    status: str
    title: str
    description: str
    max_severity: str
    alert_count: int
    malicious_count: int = 0
    suspicious_count: int = 0
    clean_count: int = 0
    findings: list[str] = []
    enrichments: dict[str, Any] = {}
    misp_context: dict[str, Any] | None = None
    ai_decision: str | None = None
    ai_confidence: float | None = None
    ai_assessment: str | None = None
    ai_recommendation: str | None = None
    timeout_seconds: int = 3600
    created_at: str
    expires_at: str | None = None


class _PendingReviewList(BaseModel):
    items: list[_PendingReviewItem] = []
    total: int = 0
    page: int = 1
    page_size: int = 50
    has_more: bool = False


@router.get("/api/review/pending", response_model=_PendingReviewList)
async def review_pending(
    request: Request,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
) -> _PendingReviewList:
    """List pending HIL reviews from the V1 pending_reviews table.

    Role-aware tenant scoping:
      - MSSP / platform admins → BYPASSRLS session, cross-tenant view.
      - Tenant-scoped users → app-role session with ``tenant_context``,
        RLS restricts the SELECT to their own tenant.
    """
    from sqlalchemy import text

    from soctalk.core.tenancy.context import tenant_context
    from soctalk.core.tenancy.db import (
        get_app_sessionmaker,
        get_mssp_sessionmaker,
    )

    identity = current_identity(request)
    offset = (page - 1) * page_size
    count_sql = text(
        "SELECT count(*) FROM pending_reviews WHERE status = 'pending'"
    )
    list_sql = text(
        """
        SELECT id::text, investigation_id::text, status, title, description,
               max_severity, alert_count, malicious_count, suspicious_count,
               clean_count, findings, enrichments, misp_context, ai_decision,
               ai_confidence, ai_assessment, ai_recommendation,
               timeout_seconds, created_at, expires_at
        FROM pending_reviews
        WHERE status = 'pending'
        ORDER BY created_at DESC
        OFFSET :off LIMIT :lim
        """
    )

    if identity.role in _MSSP_LEVEL_ROLES:
        sm = get_mssp_sessionmaker()
        async with sm() as s:
            total = (await s.execute(count_sql)).scalar_one()
            rows = (
                await s.execute(list_sql, {"off": offset, "lim": page_size})
            ).mappings().all()
    else:
        if identity.tenant_id is None:
            return _PendingReviewList(
                items=[], total=0, page=page, page_size=page_size, has_more=False
            )
        sm = get_app_sessionmaker()
        async with sm() as s:
            async with tenant_context(s, identity.tenant_id):
                total = (await s.execute(count_sql)).scalar_one()
                rows = (
                    await s.execute(list_sql, {"off": offset, "lim": page_size})
                ).mappings().all()

    def _iso(value: Any) -> str | None:
        if value is None:
            return None
        if hasattr(value, "isoformat"):
            return value.isoformat()
        return str(value)

    items = [
        _PendingReviewItem(
            id=r["id"],
            investigation_id=r["investigation_id"],
            status=r["status"],
            title=r["title"],
            description=r["description"],
            max_severity=r["max_severity"],
            alert_count=int(r["alert_count"] or 0),
            malicious_count=int(r["malicious_count"] or 0),
            suspicious_count=int(r["suspicious_count"] or 0),
            clean_count=int(r["clean_count"] or 0),
            findings=list(r["findings"] or []),
            enrichments=dict(r["enrichments"] or {}),
            misp_context=(dict(r["misp_context"]) if r["misp_context"] else None),
            ai_decision=r["ai_decision"],
            ai_confidence=(
                float(r["ai_confidence"]) if r["ai_confidence"] is not None else None
            ),
            ai_assessment=r["ai_assessment"],
            ai_recommendation=r["ai_recommendation"],
            timeout_seconds=int(r["timeout_seconds"] or 3600),
            created_at=_iso(r["created_at"]) or "",
            expires_at=_iso(r["expires_at"]),
        )
        for r in rows
    ]
    return _PendingReviewList(
        items=items,
        total=int(total or 0),
        page=page,
        page_size=page_size,
        has_more=(offset + len(items)) < int(total or 0),
    )


class _ReviewActionResponse(BaseModel):
    success: bool = True
    review_id: str
    new_status: str
    investigation_id: str


_MSSP_LEVEL_ROLES = {"platform_admin", "mssp_admin"}


async def _resolve_pending_review(
    review_id: str, identity: "UserIdentity"
) -> dict[str, Any]:
    """Resolve a review with role-aware tenant scoping.

    MSSP-level roles (``platform_admin``, ``mssp_admin``) see all
    tenants' rows via the BYPASSRLS MSSP session. Tenant-level roles
    (``analyst``, ``tenant_admin``, ``customer_viewer``) are scoped to
    their own ``tenant_id`` via the RLS-subject app session with
    ``tenant_context`` set.

    Raises HTTP 404 if the review is not found within the caller's
    tenant scope (i.e. cross-tenant lookups by tenant users fail with
    the same code path as truly missing rows — never disclose
    existence across tenants).
    """
    from fastapi import HTTPException
    from sqlalchemy import text

    from soctalk.core.tenancy.context import tenant_context
    from soctalk.core.tenancy.db import (
        get_app_sessionmaker,
        get_mssp_sessionmaker,
    )

    sql = (
        "SELECT id::text, investigation_id::text, tenant_id::text, status "
        "FROM pending_reviews WHERE id = :rid"
    )
    if identity.role in _MSSP_LEVEL_ROLES:
        sm = get_mssp_sessionmaker()
        async with sm() as s:
            r = (
                await s.execute(text(sql), {"rid": review_id})
            ).mappings().first()
    else:
        if identity.tenant_id is None:
            raise HTTPException(403, "tenant scope required")
        sm = get_app_sessionmaker()
        async with sm() as s:
            async with tenant_context(s, identity.tenant_id):
                r = (
                    await s.execute(text(sql), {"rid": review_id})
                ).mappings().first()
    if r is None:
        raise HTTPException(404, "review not found")
    return dict(r)


async def _apply_review_decision(
    review_id: str,
    investigation_id: str,
    tenant_id: str | None,
    identity: "UserIdentity",
    decision: str,
    feedback: str | None,
) -> _ReviewActionResponse:
    """Common path for approve/reject/request-info.

    Routes through ``record_human_decision_received`` which appends
    the canonical ``HUMAN_DECISION_RECEIVED`` event to the event log
    and performs the V1-schema side effects (pending_reviews status
    flip, investigation close on reject) in one transaction.
    """
    from uuid import UUID

    from soctalk.core.ir.review_events import (
        _DECISION_TO_REVIEW_STATUS,
        record_human_decision_received,
    )
    from soctalk.core.tenancy.context import tenant_context
    from soctalk.core.tenancy.db import (
        get_app_sessionmaker,
        get_mssp_sessionmaker,
    )

    tenant_uuid = UUID(tenant_id) if tenant_id else None
    if identity.role in _MSSP_LEVEL_ROLES:
        sm = get_mssp_sessionmaker()
        async with sm() as s:
            await record_human_decision_received(
                s,
                review_id=UUID(review_id),
                investigation_id=UUID(investigation_id),
                tenant_id=tenant_uuid,
                decision=decision,
                feedback=feedback,
                reviewer=identity.email,
            )
            await s.commit()
    else:
        sm = get_app_sessionmaker()
        async with sm() as s:
            async with tenant_context(s, identity.tenant_id):
                await record_human_decision_received(
                    s,
                    review_id=UUID(review_id),
                    investigation_id=UUID(investigation_id),
                    tenant_id=tenant_uuid,
                    decision=decision,
                    feedback=feedback,
                    reviewer=identity.email,
                )
                await s.commit()
    return _ReviewActionResponse(
        success=True,
        review_id=review_id,
        new_status=_DECISION_TO_REVIEW_STATUS.get(decision, decision),
        investigation_id=investigation_id,
    )


class _ApproveBody(BaseModel):
    feedback: str | None = None


@router.post("/api/review/{review_id}/approve", response_model=_ReviewActionResponse)
async def review_approve(
    review_id: str, body: _ApproveBody, request: Request
) -> _ReviewActionResponse:
    """Analyst approved the AI verdict — investigation stays escalated."""
    from fastapi import HTTPException

    identity = current_identity(request)
    review = await _resolve_pending_review(review_id, identity)
    if review["status"] != "pending":
        raise HTTPException(409, f"review already {review['status']}")
    return await _apply_review_decision(
        review_id, review["investigation_id"], review["tenant_id"], identity,
        "approve", body.feedback,
    )


@router.post("/api/review/{review_id}/reject", response_model=_ReviewActionResponse)
async def review_reject(
    review_id: str, body: _ApproveBody, request: Request
) -> _ReviewActionResponse:
    """Analyst overrode the AI verdict — close as false positive."""
    from fastapi import HTTPException

    identity = current_identity(request)
    review = await _resolve_pending_review(review_id, identity)
    if review["status"] != "pending":
        raise HTTPException(409, f"review already {review['status']}")
    return await _apply_review_decision(
        review_id, review["investigation_id"], review["tenant_id"], identity,
        "reject", body.feedback,
    )


class _RequestInfoBody(BaseModel):
    questions: list[str] = []


@router.post("/api/review/{review_id}/request-info", response_model=_ReviewActionResponse)
async def review_request_info(
    review_id: str, body: _RequestInfoBody, request: Request
) -> _ReviewActionResponse:
    """Analyst requested additional information — investigation stays open."""
    from fastapi import HTTPException

    identity = current_identity(request)
    review = await _resolve_pending_review(review_id, identity)
    if review["status"] != "pending":
        raise HTTPException(409, f"review already {review['status']}")
    feedback = "Questions: " + " | ".join(body.questions) if body.questions else None
    return await _apply_review_decision(
        review_id, review["investigation_id"], review["tenant_id"], identity,
        "more_info", feedback,
    )


class _ExpireBody(BaseModel):
    reason: str | None = None


@router.post("/api/review/{review_id}/expire", response_model=_ReviewActionResponse)
async def review_expire(
    review_id: str, body: _ExpireBody, request: Request
) -> _ReviewActionResponse:
    """Retire a pending review without an analyst verdict.

    Used for operator-driven cleanup (stale or duplicate queue items) and
    for the future timeout-driven expiration job. Distinct from
    approve/reject/request-info: emits ``HUMAN_REVIEW_EXPIRED`` rather
    than ``HUMAN_DECISION_RECEIVED``, so the audit trail shows the row
    was retired administratively, not adjudicated.

    Authorization: MSSP-level roles (platform_admin, mssp_admin) can
    expire any tenant's review. Tenant-scoped roles can only expire
    their own; ``_resolve_pending_review`` enforces both via the same
    role-aware session pattern used by the other actions.
    """
    from uuid import UUID

    from fastapi import HTTPException

    from soctalk.core.ir.review_events import record_human_review_expired
    from soctalk.core.tenancy.context import tenant_context
    from soctalk.core.tenancy.db import (
        get_app_sessionmaker,
        get_mssp_sessionmaker,
    )

    identity = current_identity(request)
    review = await _resolve_pending_review(review_id, identity)
    if review["status"] != "pending":
        raise HTTPException(409, f"review already {review['status']}")

    tenant_uuid = UUID(review["tenant_id"]) if review["tenant_id"] else None
    if tenant_uuid is None:
        raise HTTPException(500, "review missing tenant_id")

    if identity.role in _MSSP_LEVEL_ROLES:
        sm = get_mssp_sessionmaker()
        async with sm() as s:
            await record_human_review_expired(
                s,
                review_id=UUID(review_id),
                investigation_id=UUID(review["investigation_id"]),
                tenant_id=tenant_uuid,
                reason=body.reason,
                reviewer=identity.email,
            )
            await s.commit()
    else:
        sm = get_app_sessionmaker()
        async with sm() as s:
            async with tenant_context(s, identity.tenant_id):
                await record_human_review_expired(
                    s,
                    review_id=UUID(review_id),
                    investigation_id=UUID(review["investigation_id"]),
                    tenant_id=tenant_uuid,
                    reason=body.reason,
                    reviewer=identity.email,
                )
                await s.commit()
    return _ReviewActionResponse(
        success=True,
        review_id=review_id,
        new_status="expired",
        investigation_id=review["investigation_id"],
    )


# ---------------------------------------------------------------------------
# /api/analytics/* — empty defaults
# ---------------------------------------------------------------------------


def _empty_kpis() -> dict[str, Any]:
    return {
        "auto_close_rate": 0.0,
        "escalation_rate": 0.0,
        "human_override_rate": 0.0,
        "mean_time_to_decision_seconds": None,
        "total_investigations": 0,
        "auto_closed_count": 0,
        "escalated_count": 0,
        "human_reviewed_count": 0,
        "avg_ai_confidence": None,
        "high_confidence_rate": 0.0,
    }


def _empty_ai_behavior() -> dict[str, Any]:
    return {
        "confidence_distribution": [],
        "decision_trends": [],
        "escalation_breakdown": [],
        "avg_confidence_by_decision": {},
    }


def _empty_human_review() -> dict[str, Any]:
    return {
        "total_reviews": 0,
        "approved": 0,
        "rejected": 0,
        "info_requested": 0,
        "expired": 0,
        "pending": 0,
        "approval_rate": 0.0,
        "rejection_rate": 0.0,
        "avg_review_time_seconds": None,
        "ai_agreed_count": 0,
        "ai_overridden_count": 0,
        "override_rate": 0.0,
    }


def _empty_outcomes() -> dict[str, Any]:
    return {
        "total_closed": 0,
        "avg_resolution_time_seconds": None,
        "p50_resolution_time_seconds": None,
        "p90_resolution_time_seconds": None,
        "closed_as_false_positive": 0,
        "closed_as_true_positive": 0,
        "closed_as_suspicious": 0,
        "reopen_rate": 0.0,
    }


@router.get("/api/analytics/summary")
async def analytics_summary(days: int = Query(7, ge=1, le=90)) -> dict[str, Any]:
    now = datetime.now(timezone.utc).isoformat()
    return {
        "period_start": now,
        "period_end": now,
        "executive_kpis": _empty_kpis(),
        "ai_behavior": _empty_ai_behavior(),
        "human_review": _empty_human_review(),
        "outcomes": _empty_outcomes(),
    }


@router.get("/api/analytics/kpis")
async def analytics_kpis(days: int = Query(7, ge=1, le=90)) -> dict[str, Any]:
    return _empty_kpis()


@router.get("/api/analytics/ai-behavior")
async def analytics_ai_behavior(days: int = Query(7, ge=1, le=90)) -> dict[str, Any]:
    return _empty_ai_behavior()


@router.get("/api/analytics/human-review")
async def analytics_human_review(days: int = Query(7, ge=1, le=90)) -> dict[str, Any]:
    return _empty_human_review()


@router.get("/api/analytics/outcomes")
async def analytics_outcomes(days: int = Query(7, ge=1, le=90)) -> dict[str, Any]:
    return _empty_outcomes()


# ---------------------------------------------------------------------------
# /api/audit/* — empty list + event types
# ---------------------------------------------------------------------------


async def _audit_session_for(identity: "UserIdentity"):
    """Return a session + scoping context appropriate for the caller.

    MSSP-level roles use the BYPASSRLS session so they see every
    tenant's audit trail. Tenant-level roles use the RLS-subject
    session with ``tenant_context`` so their audit query is naturally
    scoped to their own tenant_id by the events_tenant_isolation
    policy on the ``events`` table.

    Yields ``(session, needs_commit)`` — read-only here so the caller
    never commits, but the shape mirrors the write helpers above for
    readability.
    """
    from soctalk.core.tenancy.context import tenant_context
    from soctalk.core.tenancy.db import get_app_sessionmaker, get_mssp_sessionmaker

    if identity.role in _MSSP_LEVEL_ROLES:
        sm = get_mssp_sessionmaker()
        async with sm() as s:
            yield s
    else:
        sm = get_app_sessionmaker()
        async with sm() as s:
            async with tenant_context(s, identity.tenant_id):
                yield s


@router.get("/api/audit/event-types")
async def audit_event_types(request: Request) -> dict[str, list[str]]:
    """Distinct event types present in the audit log — drives the UI filter."""
    from sqlalchemy import text as _t

    identity = current_identity(request)
    async for s in _audit_session_for(identity):
        rows = (
            await s.execute(_t("SELECT DISTINCT event_type FROM events ORDER BY event_type"))
        ).all()
        return {"event_types": [r[0] for r in rows]}


@router.get("/api/audit")
async def audit_list(
    request: Request,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=500),
    event_type: str | None = None,
    aggregate_type: str | None = None,
    start_date: str | None = None,
    end_date: str | None = None,
    investigation_id: str | None = None,
) -> dict[str, Any]:
    """Paginated audit log query against the ``events`` table.

    Filters are AND-composed; missing filters are dropped from the
    WHERE. ``total`` is a separate COUNT(*) over the same predicate so
    the frontend pager works. Tenant scoping is handled by either
    BYPASSRLS (MSSP) or the events RLS policy (tenant).
    """
    from sqlalchemy import text as _t

    identity = current_identity(request)
    conds: list[str] = []
    params: dict[str, Any] = {}
    if event_type:
        conds.append("event_type = :et")
        params["et"] = event_type
    if aggregate_type:
        conds.append("aggregate_type = :at")
        params["at"] = aggregate_type
    if investigation_id:
        conds.append("aggregate_id::text = :aid")
        params["aid"] = investigation_id
    if start_date:
        conds.append("timestamp >= :sd")
        params["sd"] = start_date
    if end_date:
        conds.append("timestamp <= :ed")
        params["ed"] = end_date
    where = (" WHERE " + " AND ".join(conds)) if conds else ""

    offset = (page - 1) * page_size
    params["lim"] = page_size
    params["off"] = offset

    async for s in _audit_session_for(identity):
        total = (
            await s.execute(_t(f"SELECT COUNT(*) FROM events{where}"), params)
        ).scalar_one()
        rows = (
            await s.execute(
                _t(
                    f"""
                    SELECT id::text, aggregate_id::text, aggregate_type, event_type,
                           version, timestamp, data
                    FROM events{where}
                    ORDER BY timestamp DESC
                    LIMIT :lim OFFSET :off
                    """
                ),
                params,
            )
        ).mappings().all()
        items = [
            {
                "id": r["id"],
                "aggregate_id": r["aggregate_id"],
                "aggregate_type": r["aggregate_type"],
                "event_type": r["event_type"],
                "version": int(r["version"]),
                "timestamp": (
                    r["timestamp"].isoformat() if r["timestamp"] else None
                ),
                "data": r["data"],
            }
            for r in rows
        ]
        return {
            "items": items,
            "total": int(total or 0),
            "page": page,
            "page_size": page_size,
            "has_more": (offset + len(items)) < int(total or 0),
        }


@router.get("/api/audit/stats")
async def audit_stats(
    request: Request, hours: int = Query(24, ge=1, le=720)
) -> dict[str, Any]:
    """Aggregate counters for the audit dashboard."""
    from sqlalchemy import text as _t

    identity = current_identity(request)
    # ``hours`` is already bounded to [1, 720] by Query(...). Construct
    # the interval via ``make_interval`` rather than ``(:h)::interval``
    # because asyncpg can't cast a bind param to ``interval`` directly
    # (server-side parser sees ``$1`` before it has a target type).
    params = {"h": int(hours)}
    async for s in _audit_session_for(identity):
        total = (
            await s.execute(
                _t(
                    "SELECT COUNT(*) FROM events "
                    "WHERE timestamp >= now() - make_interval(hours => :h)"
                ),
                params,
            )
        ).scalar_one()
        uniq = (
            await s.execute(
                _t(
                    "SELECT COUNT(DISTINCT aggregate_id) FROM events "
                    "WHERE timestamp >= now() - make_interval(hours => :h)"
                ),
                params,
            )
        ).scalar_one()
        by_type = (
            await s.execute(
                _t(
                    "SELECT event_type, COUNT(*) FROM events "
                    "WHERE timestamp >= now() - make_interval(hours => :h) "
                    "GROUP BY event_type"
                ),
                params,
            )
        ).all()
        by_hour = (
            await s.execute(
                _t(
                    "SELECT date_trunc('hour', timestamp) AS h, COUNT(*) "
                    "FROM events "
                    "WHERE timestamp >= now() - make_interval(hours => :h) "
                    "GROUP BY h ORDER BY h"
                ),
                params,
            )
        ).all()
        return {
            "period_hours": hours,
            "total_events": int(total or 0),
            "unique_investigations": int(uniq or 0),
            "events_by_type": {r[0]: int(r[1]) for r in by_type},
            "events_by_hour": {
                (r[0].isoformat() if r[0] else ""): int(r[1]) for r in by_hour
            },
        }


@router.get("/api/audit/investigation/{investigation_id}")
async def audit_investigation(
    investigation_id: str,
    request: Request,
    limit: int = Query(200, ge=1, le=2000),
) -> dict[str, Any]:
    """Per-investigation event timeline for the case-detail audit tab."""
    from sqlalchemy import text as _t

    identity = current_identity(request)
    async for s in _audit_session_for(identity):
        inv = (
            await s.execute(
                _t(
                    "SELECT title, status, created_at FROM investigations "
                    "WHERE id::text = :id"
                ),
                {"id": investigation_id},
            )
        ).mappings().first()
        rows = (
            await s.execute(
                _t(
                    """
                    SELECT id::text, aggregate_type, event_type, version,
                           timestamp, data
                    FROM events
                    WHERE aggregate_id::text = :id
                    ORDER BY version ASC
                    LIMIT :lim
                    """
                ),
                {"id": investigation_id, "lim": limit},
            )
        ).mappings().all()
        events = [
            {
                "id": r["id"],
                "aggregate_type": r["aggregate_type"],
                "event_type": r["event_type"],
                "version": int(r["version"]),
                "timestamp": (
                    r["timestamp"].isoformat() if r["timestamp"] else None
                ),
                "data": r["data"],
            }
            for r in rows
        ]
        return {
            "investigation_id": investigation_id,
            "title": inv["title"] if inv else None,
            "status": inv["status"] if inv else "unknown",
            "phase": "unknown",
            "created_at": (
                inv["created_at"].isoformat()
                if inv and inv["created_at"]
                else datetime.now(timezone.utc).isoformat()
            ),
            "events": events,
            "total_events": len(events),
        }


# ---------------------------------------------------------------------------
# /api/settings — minimal read-only snapshot
# ---------------------------------------------------------------------------


@router.get("/api/settings")
async def settings_get() -> dict[str, Any]:
    """Read-only settings snapshot.

    The full settings UX edits MCP integration credentials in the legacy
    single-tenant install; in V1 those live in per-tenant
    IntegrationConfig (see /api/llm/* and the MSSP tenants UI). We
    return a non-empty shape with everything ``readonly=True`` so the
    page renders the read-only view rather than an error.
    """

    return {
        "id": "v1-readonly",
        "readonly": True,
        "sources": {},
        "llm_provider": "openai",
        "llm_fast_model": "gpt-4o-mini",
        "llm_reasoning_model": "gpt-4o",
        "llm_temperature": 0.2,
        "llm_max_tokens": 4096,
        "llm_anthropic_base_url": None,
        "llm_openai_base_url": None,
        "llm_openai_organization": None,
        "anthropic_api_key_configured": False,
        "openai_api_key_configured": False,
        "llm_keys_conflict": False,
        "wazuh_enabled": False,
        "wazuh_url": None,
        "wazuh_verify_ssl": True,
        "wazuh_credentials_configured": False,
        "cortex_enabled": False,
        "cortex_url": None,
        "cortex_verify_ssl": True,
        "cortex_api_key_configured": False,
        "thehive_enabled": False,
        "thehive_url": None,
        "thehive_organisation": None,
        "thehive_verify_ssl": True,
        "thehive_api_key_configured": False,
        "misp_enabled": False,
        "misp_url": None,
        "misp_verify_ssl": True,
        "misp_api_key_configured": False,
        "slack_enabled": False,
        "slack_channel": None,
        "slack_notify_on_escalation": False,
        "slack_notify_on_verdict": False,
        "slack_webhook_configured": False,
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }


__all__ = ["router"]
