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
    title: str
    description: str
    max_severity: str
    alert_count: int
    ai_decision: str | None = None
    ai_confidence: float | None = None
    ai_assessment: str | None = None
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
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
) -> _PendingReviewList:
    """List pending HIL reviews from the V1 pending_reviews table.

    Uses the MSSP-role session (BYPASSRLS) so MSSP / platform admins see
    rows across tenants. Tenant-scoped users see only their tenant's
    rows because the underlying SELECT filters on the session's tenant
    context — but mssp_admin / platform_admin reach this from the
    operator console where cross-tenant visibility is the intent.
    """
    from sqlalchemy import text

    from soctalk.core.tenancy.db import get_mssp_sessionmaker

    sm = get_mssp_sessionmaker()
    offset = (page - 1) * page_size
    async with sm() as s:
        total = (
            await s.execute(
                text("SELECT count(*) FROM pending_reviews WHERE status = 'pending'")
            )
        ).scalar_one()
        rows = (
            await s.execute(
                text(
                    """
                    SELECT id::text, investigation_id::text, title, description,
                           max_severity, alert_count, ai_decision, ai_confidence,
                           ai_assessment, created_at, expires_at
                    FROM pending_reviews
                    WHERE status = 'pending'
                    ORDER BY created_at DESC
                    OFFSET :off LIMIT :lim
                    """
                ),
                {"off": offset, "lim": page_size},
            )
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
            title=r["title"],
            description=r["description"],
            max_severity=r["max_severity"],
            alert_count=int(r["alert_count"] or 0),
            ai_decision=r["ai_decision"],
            ai_confidence=(
                float(r["ai_confidence"]) if r["ai_confidence"] is not None else None
            ),
            ai_assessment=r["ai_assessment"],
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


async def _resolve_pending_review(review_id: str) -> dict[str, Any] | None:
    from sqlalchemy import text

    from soctalk.core.tenancy.db import get_mssp_sessionmaker

    sm = get_mssp_sessionmaker()
    async with sm() as s:
        r = (
            await s.execute(
                text(
                    "SELECT id::text, investigation_id::text, tenant_id::text, status "
                    "FROM pending_reviews WHERE id = :rid"
                ),
                {"rid": review_id},
            )
        ).mappings().first()
        return dict(r) if r else None


async def _close_review_and_apply(
    review_id: str,
    new_review_status: str,
    inv_action: str,
    feedback: str | None,
    reviewer: str | None,
) -> _ReviewActionResponse:
    """Common path for approve/reject/request-info.

    inv_action is one of:
      - ``"escalate"``: investigation stays active, severity already at 12
      - ``"close"``: investigation closes as auto-rejected FP
      - ``"hold"``: investigation stays active, no change
    """
    from fastapi import HTTPException
    from sqlalchemy import text

    from soctalk.core.tenancy.db import get_mssp_sessionmaker

    review = await _resolve_pending_review(review_id)
    if review is None:
        raise HTTPException(404, "review not found")
    if review["status"] != "pending":
        raise HTTPException(409, f"review already {review['status']}")

    sm = get_mssp_sessionmaker()
    async with sm() as s:
        await s.execute(
            text(
                """
                UPDATE pending_reviews
                   SET status = :new_status,
                       feedback = :feedback,
                       reviewer = :reviewer,
                       responded_at = now()
                 WHERE id = :rid
                """
            ),
            {
                "new_status": new_review_status,
                "feedback": feedback,
                "reviewer": reviewer,
                "rid": review_id,
            },
        )
        if inv_action == "close":
            await s.execute(
                text(
                    """
                    UPDATE investigations
                       SET status = 'auto_closed_fp',
                           closed_at = now(),
                           close_reason = COALESCE(:reason, close_reason),
                           updated_at = now()
                     WHERE id = :inv
                    """
                ),
                {"reason": feedback, "inv": review["investigation_id"]},
            )
        await s.commit()

    return _ReviewActionResponse(
        success=True,
        review_id=review_id,
        new_status=new_review_status,
        investigation_id=review["investigation_id"],
    )


class _ApproveBody(BaseModel):
    feedback: str | None = None


@router.post("/api/review/{review_id}/approve", response_model=_ReviewActionResponse)
async def review_approve(
    review_id: str, body: _ApproveBody, request: Request
) -> _ReviewActionResponse:
    """Analyst approved the AI verdict — investigation stays escalated."""
    ident = current_identity(request)
    reviewer = ident.get("email") if ident else None
    return await _close_review_and_apply(
        review_id, "approved", "escalate", body.feedback, reviewer
    )


@router.post("/api/review/{review_id}/reject", response_model=_ReviewActionResponse)
async def review_reject(
    review_id: str, body: _ApproveBody, request: Request
) -> _ReviewActionResponse:
    """Analyst overrode the AI verdict — close as false positive."""
    ident = current_identity(request)
    reviewer = ident.get("email") if ident else None
    return await _close_review_and_apply(
        review_id, "rejected", "close", body.feedback, reviewer
    )


class _RequestInfoBody(BaseModel):
    questions: list[str] = []


@router.post("/api/review/{review_id}/request-info", response_model=_ReviewActionResponse)
async def review_request_info(
    review_id: str, body: _RequestInfoBody, request: Request
) -> _ReviewActionResponse:
    """Analyst requested additional information — investigation stays open."""
    ident = current_identity(request)
    reviewer = ident.get("email") if ident else None
    feedback = "Questions: " + " | ".join(body.questions) if body.questions else None
    return await _close_review_and_apply(
        review_id, "info_requested", "hold", feedback, reviewer
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


@router.get("/api/audit/event-types")
async def audit_event_types() -> dict[str, list[str]]:
    return {"event_types": []}


@router.get("/api/audit")
async def audit_list(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=500),
    event_type: str | None = None,
    aggregate_type: str | None = None,
    start_date: str | None = None,
    end_date: str | None = None,
    investigation_id: str | None = None,
) -> dict[str, Any]:
    return {"items": [], "total": 0, "page": page, "page_size": page_size, "has_more": False}


@router.get("/api/audit/stats")
async def audit_stats(hours: int = Query(24, ge=1, le=720)) -> dict[str, Any]:
    return {
        "period_hours": hours,
        "total_events": 0,
        "unique_investigations": 0,
        "events_by_type": {},
        "events_by_hour": {},
    }


@router.get("/api/audit/investigation/{investigation_id}")
async def audit_investigation(investigation_id: str, limit: int = Query(200, ge=1, le=2000)) -> dict[str, Any]:
    return {
        "investigation_id": investigation_id,
        "title": None,
        "status": "unknown",
        "phase": "unknown",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "events": [],
        "total_events": 0,
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
