"""API surface for native AI-led incident response.

Cases, events, proposals, alerts, integrations.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from soctalk.core.ir.campaign import (
    declare_engagement,
    list_engagements,
    revoke_engagement,
)
from soctalk.core.ir.events import EventKind, append_event
from soctalk.core.ir.runtime import (
    approve_proposal,
    consume_new_events,
    reject_proposal,
)
from soctalk.core.tenancy.auth import current_identity
from soctalk.core.tenancy.context import tenant_context
from soctalk.core.tenancy.decorators import require_role, require_tenant_role
from soctalk.core.tenancy.models import Role

mssp_investigations_router = APIRouter(prefix="/api/mssp/investigations", tags=["ir-mssp"])
tenant_investigations_router = APIRouter(prefix="/api/tenant/investigations", tags=["ir-tenant"])
alerts_router = APIRouter(prefix="/api/mssp/alerts", tags=["ir-alerts"])
proposals_router = APIRouter(prefix="/api/mssp/proposals", tags=["ir-proposals"])
integrations_router = APIRouter(
    prefix="/api/mssp/tenants", tags=["ir-integrations"]
)
engagements_router = APIRouter(prefix="/api/mssp/tenants", tags=["ir-engagements"])


# ---------------------------------------------------------------------------
# Shapes
# ---------------------------------------------------------------------------


class CaseSummary(BaseModel):
    id: str
    short_id: str
    title: str
    status: str
    severity: int
    opened_at: datetime
    closed_at: datetime | None
    assignee_user_id: str | None
    tenant_id: str


class CaseRunDTO(BaseModel):
    id: str
    status: str
    tokens_used: int
    tokens_budget: int
    dollars_used: float
    dollars_budget: float
    started_at: datetime
    ended_at: datetime | None
    last_error: str | None


class CaseDetail(CaseSummary):
    summary: str | None
    reopen_window_until: datetime | None
    facts: dict[str, Any]
    related_cases: list[dict[str, Any]]
    active_run: CaseRunDTO | None = None


class CustomerCaseFacts(BaseModel):
    """Customer-safe projection of investigation_facts.

    Explicitly omits MSSP-internal fields: hypotheses (internal
    reasoning), active_directives (MSSP policy), active_policies
    (MSSP configuration), and confidence scores. Only the timeline
    summary survives, and only entries whose source is not MSSP-only.
    """

    timeline_summary: list[dict[str, Any]] = Field(default_factory=list)


class CustomerCaseSummary(BaseModel):
    """Customer-view list row. Deliberately NOT a subclass of
    ``CaseSummary`` — that shape includes ``assignee_user_id`` and
    ``tenant_id``, which are MSSP-internal routing metadata that the
    customer portal should never see on the wire."""

    id: str
    short_id: str
    title: str
    status: str
    severity: int
    opened_at: datetime
    closed_at: datetime | None


class CustomerCaseDetail(CustomerCaseSummary):
    """Customer-view projection — narrower than the MSSP CaseDetail."""

    summary: str | None
    facts: CustomerCaseFacts


class CaseEventDTO(BaseModel):
    event_id: str
    seq: int
    kind: str
    payload: dict[str, Any]
    visibility: str
    created_at: datetime


class AnalystMessageRequest(BaseModel):
    body: str = Field(..., min_length=1, max_length=16_000)


class FactsCorrectionRequest(BaseModel):
    path: str = Field(..., min_length=1, max_length=255)
    value: Any


class ProposalDTO(BaseModel):
    id: str
    investigation_id: str
    action_type: str
    params: dict[str, Any]
    rationale: str
    blast_radius: str | None
    capability_class: str
    status: str
    created_at: datetime


class ProposalDecisionRequest(BaseModel):
    reason: str = Field(..., min_length=1, max_length=2000)


class AlertDTO(BaseModel):
    id: str
    tenant_id: str
    source: str
    rule_id: str | None
    severity: int
    event_count: int
    ai_assessment: str | None
    ai_confidence: float | None
    status: str
    investigation_id: str | None
    first_event_at: datetime
    last_event_at: datetime


class IntegrationsDTO(BaseModel):
    thehive_export_enabled: bool
    thehive_url: str | None
    misp_ingest_enabled: bool
    misp_url: str | None
    auto_close_enabled: bool


class IntegrationsPatch(BaseModel):
    thehive_export_enabled: bool | None = None
    thehive_url: str | None = None
    misp_ingest_enabled: bool | None = None
    misp_url: str | None = None
    auto_close_enabled: bool | None = None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _db(request: Request) -> AsyncSession:
    session = getattr(request.state, "db", None)
    if session is None:
        raise HTTPException(500, "db session not attached to request")
    return session


async def _resolve_case_tenant(db: AsyncSession, investigation_id: UUID) -> UUID:
    """Resolve an investigation's tenant_id. MSSP audience can read across tenants,
    so this lookup succeeds even with ``app.current_tenant_id`` unset.
    The caller is then responsible for wrapping mutations in
    ``tenant_context(db, tenant_id)`` so WITH CHECK passes."""

    row = (
        await db.execute(
            text("SELECT tenant_id FROM investigations WHERE id = :id"),
            {"id": str(investigation_id)},
        )
    ).scalar_one_or_none()
    if row is None:
        raise HTTPException(404, "investigation not found")
    return UUID(str(row))


async def _case_detail(
    db: AsyncSession, investigation_id: UUID, tenant_filter: UUID | None = None
) -> CaseDetail:
    """Load an investigation + facts + related links. RLS handles audience filtering."""

    case_row_q = text(
        "SELECT id, tenant_id, short_id, title, status, severity, "
        "       opened_at, closed_at, assignee_user_id, summary, "
        "       reopen_window_until "
        "FROM investigations WHERE id = :id"
    )
    row = (
        await db.execute(case_row_q, {"id": str(investigation_id)})
    ).mappings().first()
    if row is None:
        raise HTTPException(404, "investigation not found")
    if tenant_filter and UUID(str(row["tenant_id"])) != tenant_filter:
        raise HTTPException(404, "investigation not found")

    # Fold new events into the projection before reading it. The write
    # needs an explicit tenant context so the projection upsert's WITH
    # CHECK passes (MSSP audience alone permits reads, not writes).
    tid = UUID(str(row["tenant_id"]))
    async with tenant_context(db, tid):
        await consume_new_events(db, tid, investigation_id)

    facts_row = (
        await db.execute(
            text(
                "SELECT hypotheses, active_directives, active_policies, "
                "       timeline_summary, applied_seq "
                "FROM investigation_facts WHERE investigation_id = :id"
            ),
            {"id": str(investigation_id)},
        )
    ).mappings().first()
    facts = dict(facts_row) if facts_row else {
        "hypotheses": [], "active_directives": [],
        "active_policies": [], "timeline_summary": [], "applied_seq": 0,
    }

    related = [
        {
            "to_investigation_id": str(r["to_investigation_id"]),
            "link_kind": r["link_kind"],
            "confidence": r["confidence"],
        }
        for r in (
            await db.execute(
                text(
                    "SELECT to_investigation_id, link_kind, confidence "
                    "FROM investigation_links WHERE from_investigation_id = :c"
                ),
                {"c": str(investigation_id)},
            )
        ).mappings().all()
    ]

    run_row = (
        await db.execute(
            text(
                "SELECT id, status, tokens_used, tokens_budget, "
                "       dollars_used, dollars_budget, "
                "       started_at, ended_at, last_error "
                "FROM investigation_runs WHERE investigation_id = :c "
                "ORDER BY started_at DESC LIMIT 1"
            ),
            {"c": str(investigation_id)},
        )
    ).mappings().first()
    active_run = (
        CaseRunDTO(
            id=str(run_row["id"]),
            status=run_row["status"],
            tokens_used=int(run_row["tokens_used"] or 0),
            tokens_budget=int(run_row["tokens_budget"] or 0),
            dollars_used=float(run_row["dollars_used"] or 0),
            dollars_budget=float(run_row["dollars_budget"] or 0),
            started_at=run_row["started_at"],
            ended_at=run_row["ended_at"],
            last_error=run_row["last_error"],
        )
        if run_row is not None
        else None
    )

    return CaseDetail(
        id=str(row["id"]),
        short_id=row["short_id"],
        title=row["title"],
        status=row["status"],
        severity=row["severity"],
        opened_at=row["opened_at"],
        closed_at=row["closed_at"],
        assignee_user_id=str(row["assignee_user_id"]) if row["assignee_user_id"] else None,
        tenant_id=str(row["tenant_id"]),
        summary=row["summary"],
        reopen_window_until=row["reopen_window_until"],
        facts=facts,
        related_cases=related,
        active_run=active_run,
    )


# ---------------------------------------------------------------------------
# MSSP investigation routes
# ---------------------------------------------------------------------------


@mssp_investigations_router.get(
    "",
    response_model=list[CaseSummary],
    dependencies=[Depends(require_role(Role.PLATFORM_ADMIN, Role.MSSP_ADMIN, Role.ANALYST))],
)
async def list_cases_mssp(
    request: Request,
    tenant_id: str | None = None,
    status: str | None = None,
    severity_min: int | None = None,
    limit: int = 100,
) -> list[CaseSummary]:
    db = _db(request)
    clauses = []
    params: dict[str, Any] = {"lim": limit}
    if tenant_id:
        clauses.append("tenant_id = :t")
        params["t"] = tenant_id
    if status:
        clauses.append("status = :s")
        params["s"] = status
    if severity_min is not None:
        clauses.append("severity >= :sm")
        params["sm"] = severity_min
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    rows = (
        await db.execute(
            text(
                f"SELECT id, tenant_id, short_id, title, status, severity, "
                f"       opened_at, closed_at, assignee_user_id "
                f"FROM investigations {where} "
                f"ORDER BY opened_at DESC LIMIT :lim"
            ),
            params,
        )
    ).mappings().all()
    return [
        CaseSummary(
            id=str(r["id"]),
            short_id=r["short_id"],
            title=r["title"],
            status=r["status"],
            severity=r["severity"],
            opened_at=r["opened_at"],
            closed_at=r["closed_at"],
            assignee_user_id=str(r["assignee_user_id"]) if r["assignee_user_id"] else None,
            tenant_id=str(r["tenant_id"]),
        )
        for r in rows
    ]


@mssp_investigations_router.get(
    "/{investigation_id}",
    response_model=CaseDetail,
    dependencies=[Depends(require_role(Role.PLATFORM_ADMIN, Role.MSSP_ADMIN, Role.ANALYST))],
)
async def get_case_mssp(investigation_id: UUID, request: Request) -> CaseDetail:
    db = _db(request)
    return await _case_detail(db, investigation_id)


@mssp_investigations_router.get(
    "/{investigation_id}/events",
    response_model=list[CaseEventDTO],
    dependencies=[Depends(require_role(Role.PLATFORM_ADMIN, Role.MSSP_ADMIN, Role.ANALYST))],
)
async def list_case_events_mssp(investigation_id: UUID, request: Request) -> list[CaseEventDTO]:
    db = _db(request)
    rows = (
        await db.execute(
            text(
                "SELECT event_id, seq, kind, payload, visibility, created_at "
                "FROM investigation_events WHERE investigation_id = :c ORDER BY seq ASC"
            ),
            {"c": str(investigation_id)},
        )
    ).mappings().all()
    return [
        CaseEventDTO(
            event_id=str(r["event_id"]),
            seq=r["seq"],
            kind=r["kind"],
            payload=dict(r["payload"]) if r["payload"] else {},
            visibility=r["visibility"],
            created_at=r["created_at"],
        )
        for r in rows
    ]


@mssp_investigations_router.post(
    "/{investigation_id}/messages",
    dependencies=[Depends(require_role(Role.PLATFORM_ADMIN, Role.MSSP_ADMIN, Role.ANALYST))],
)
async def post_analyst_message(
    investigation_id: UUID, payload: AnalystMessageRequest, request: Request
) -> dict[str, str]:
    db = _db(request)
    identity = current_identity(request)
    tid = await _resolve_case_tenant(db, investigation_id)

    async with tenant_context(db, tid):
        event_id = await append_event(
            db,
            tenant_id=tid,
            investigation_id=investigation_id,
            run_id=None,
            kind=EventKind.ANALYST_MESSAGE,
            payload={
                "body": payload.body,
                "author_user_id": str(identity.user_id),
                "author_email": identity.email,
            },
            producer=f"user:{identity.user_id}",
        )
    return {"event_id": str(event_id)}


@mssp_investigations_router.patch(
    "/{investigation_id}/facts",
    dependencies=[Depends(require_role(Role.PLATFORM_ADMIN, Role.MSSP_ADMIN, Role.ANALYST))],
)
async def patch_case_facts(
    investigation_id: UUID, payload: FactsCorrectionRequest, request: Request
) -> dict[str, str]:
    db = _db(request)
    identity = current_identity(request)
    tid = await _resolve_case_tenant(db, investigation_id)

    async with tenant_context(db, tid):
        event_id = await append_event(
            db,
            tenant_id=tid,
            investigation_id=investigation_id,
            run_id=None,
            kind=EventKind.ANALYST_CORRECTION,
            payload={
                "path": payload.path,
                "value": payload.value,
                "author_user_id": str(identity.user_id),
            },
            producer=f"user:{identity.user_id}",
        )
        # Fold into the projection immediately so the next GET reflects it.
        await consume_new_events(db, tid, investigation_id)
    return {"event_id": str(event_id)}


# ---------------------------------------------------------------------------
# Tenant investigation routes (customer-viewer etc.; RLS handles the filtering)
# ---------------------------------------------------------------------------


@tenant_investigations_router.get(
    "",
    response_model=list[CustomerCaseSummary],
    dependencies=[Depends(require_tenant_role())],
)
async def list_cases_tenant(
    request: Request, limit: int = 50
) -> list[CustomerCaseSummary]:
    db = _db(request)
    # Only columns the customer is allowed to see. assignee_user_id and
    # tenant_id are MSSP routing metadata and stay on the MSSP side.
    rows = (
        await db.execute(
            text(
                "SELECT id, short_id, title, status, severity, "
                "       opened_at, closed_at "
                "FROM investigations ORDER BY opened_at DESC LIMIT :lim"
            ),
            {"lim": limit},
        )
    ).mappings().all()
    return [
        CustomerCaseSummary(
            id=str(r["id"]),
            short_id=r["short_id"],
            title=r["title"],
            status=r["status"],
            severity=r["severity"],
            opened_at=r["opened_at"],
            closed_at=r["closed_at"],
        )
        for r in rows
    ]


@tenant_investigations_router.get(
    "/{investigation_id}",
    response_model=CustomerCaseDetail,
    dependencies=[Depends(require_tenant_role())],
)
async def get_case_tenant(investigation_id: UUID, request: Request) -> CustomerCaseDetail:
    """Customer-facing investigation view. Returns a narrower projection than the
    MSSP endpoint: no hypotheses, no active directives, no policies, no
    related-investigation graph. Only the timeline summary + basic investigation metadata.

    Even if the investigation row itself were misclassified, the response shape
    here does not carry MSSP-internal facts — customer portal cannot
    leak them through this endpoint regardless."""

    db = _db(request)
    identity = current_identity(request)
    full = await _case_detail(db, investigation_id, tenant_filter=identity.tenant_id)
    return CustomerCaseDetail(
        id=full.id,
        short_id=full.short_id,
        title=full.title,
        status=full.status,
        severity=full.severity,
        opened_at=full.opened_at,
        closed_at=full.closed_at,
        summary=full.summary,
        facts=CustomerCaseFacts(
            timeline_summary=list(full.facts.get("timeline_summary", []) or []),
        ),
    )


# ---------------------------------------------------------------------------
# Proposals
# ---------------------------------------------------------------------------


@proposals_router.get(
    "",
    response_model=list[ProposalDTO],
    dependencies=[Depends(require_role(Role.PLATFORM_ADMIN, Role.MSSP_ADMIN, Role.ANALYST))],
)
async def list_pending_proposals(request: Request) -> list[ProposalDTO]:
    db = _db(request)
    rows = (
        await db.execute(
            text(
                "SELECT id, investigation_id, action_type, params, rationale, "
                "       blast_radius, capability_class, status, created_at "
                "FROM proposals WHERE status = 'proposed' "
                "ORDER BY created_at ASC"
            )
        )
    ).mappings().all()
    return [
        ProposalDTO(
            id=str(r["id"]),
            investigation_id=str(r["investigation_id"]),
            action_type=r["action_type"],
            params=dict(r["params"]) if r["params"] else {},
            rationale=r["rationale"],
            blast_radius=r["blast_radius"],
            capability_class=r["capability_class"],
            status=r["status"],
            created_at=r["created_at"],
        )
        for r in rows
    ]


@proposals_router.post(
    "/{proposal_id}/approve",
    dependencies=[Depends(require_role(Role.PLATFORM_ADMIN, Role.MSSP_ADMIN, Role.ANALYST))],
)
async def approve_proposal_route(
    proposal_id: UUID,
    payload: ProposalDecisionRequest,
    request: Request,
) -> dict[str, str]:
    db = _db(request)
    identity = current_identity(request)
    # Resolve the tenant from the proposal so RLS WITH CHECK passes on
    # the writes inside approve_proposal.
    tid_row = (
        await db.execute(
            text("SELECT tenant_id FROM proposals WHERE id = :id"),
            {"id": str(proposal_id)},
        )
    ).scalar_one_or_none()
    if tid_row is None:
        raise HTTPException(404, "proposal not found")
    tid = UUID(str(tid_row))

    async with tenant_context(db, tid):
        try:
            await approve_proposal(
                db,
                proposal_id=proposal_id,
                approver_user_id=identity.user_id,
                reason=payload.reason,
            )
        except ValueError as exc:
            raise HTTPException(400, str(exc))
    return {"ok": "approved"}


@proposals_router.post(
    "/{proposal_id}/reject",
    dependencies=[Depends(require_role(Role.PLATFORM_ADMIN, Role.MSSP_ADMIN, Role.ANALYST))],
)
async def reject_proposal_route(
    proposal_id: UUID,
    payload: ProposalDecisionRequest,
    request: Request,
) -> dict[str, str]:
    db = _db(request)
    identity = current_identity(request)
    tid_row = (
        await db.execute(
            text("SELECT tenant_id FROM proposals WHERE id = :id"),
            {"id": str(proposal_id)},
        )
    ).scalar_one_or_none()
    if tid_row is None:
        raise HTTPException(404, "proposal not found")
    tid = UUID(str(tid_row))

    async with tenant_context(db, tid):
        try:
            await reject_proposal(
                db,
                proposal_id=proposal_id,
                approver_user_id=identity.user_id,
                reason=payload.reason,
            )
        except ValueError as exc:
            raise HTTPException(400, str(exc))
    return {"ok": "rejected"}


# ---------------------------------------------------------------------------
# Alerts
# ---------------------------------------------------------------------------


@alerts_router.get(
    "",
    response_model=list[AlertDTO],
    dependencies=[Depends(require_role(Role.PLATFORM_ADMIN, Role.MSSP_ADMIN, Role.ANALYST))],
)
async def list_alerts(
    request: Request,
    status: str | None = None,
    assessment: str | None = None,
    limit: int = 200,
) -> list[AlertDTO]:
    db = _db(request)
    clauses: list[str] = []
    params: dict[str, Any] = {"lim": limit}
    if status:
        clauses.append("status = :s")
        params["s"] = status
    if assessment:
        clauses.append("ai_assessment = :a")
        params["a"] = assessment
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    rows = (
        await db.execute(
            text(
                f"SELECT id, tenant_id, source, rule_id, severity, event_count, "
                f"       ai_assessment, ai_confidence, status, investigation_id, "
                f"       first_event_at, last_event_at "
                f"FROM alerts {where} "
                f"ORDER BY last_event_at DESC LIMIT :lim"
            ),
            params,
        )
    ).mappings().all()
    return [
        AlertDTO(
            id=str(r["id"]),
            tenant_id=str(r["tenant_id"]),
            source=r["source"],
            rule_id=r["rule_id"],
            severity=r["severity"],
            event_count=r["event_count"],
            ai_assessment=r["ai_assessment"],
            ai_confidence=r["ai_confidence"],
            status=r["status"],
            investigation_id=str(r["investigation_id"]) if r["investigation_id"] else None,
            first_event_at=r["first_event_at"],
            last_event_at=r["last_event_at"],
        )
        for r in rows
    ]


# ---------------------------------------------------------------------------
# Integrations (per tenant)
# ---------------------------------------------------------------------------


@integrations_router.get(
    "/{tenant_id}/integrations",
    response_model=IntegrationsDTO,
    dependencies=[Depends(require_role(Role.PLATFORM_ADMIN, Role.MSSP_ADMIN))],
)
async def get_integrations(tenant_id: UUID, request: Request) -> IntegrationsDTO:
    db = _db(request)
    row = (
        await db.execute(
            text(
                "SELECT thehive_export_enabled, thehive_url, "
                "       misp_ingest_enabled, misp_url, auto_close_enabled "
                "FROM integration_configs WHERE tenant_id = :t"
            ),
            {"t": str(tenant_id)},
        )
    ).mappings().first()
    if row is None:
        # Default config for a tenant not yet configured.
        return IntegrationsDTO(
            thehive_export_enabled=False,
            thehive_url=None,
            misp_ingest_enabled=False,
            misp_url=None,
            auto_close_enabled=True,
        )
    return IntegrationsDTO(
        thehive_export_enabled=row["thehive_export_enabled"],
        thehive_url=row["thehive_url"],
        misp_ingest_enabled=row["misp_ingest_enabled"],
        misp_url=row["misp_url"],
        auto_close_enabled=row["auto_close_enabled"],
    )


@integrations_router.patch(
    "/{tenant_id}/integrations",
    response_model=IntegrationsDTO,
    dependencies=[Depends(require_role(Role.PLATFORM_ADMIN, Role.MSSP_ADMIN))],
)
async def patch_integrations(
    tenant_id: UUID, payload: IntegrationsPatch, request: Request
) -> IntegrationsDTO:
    db = _db(request)
    sets: list[str] = []
    params: dict[str, Any] = {"t": str(tenant_id)}
    for attr in (
        "thehive_export_enabled",
        "thehive_url",
        "misp_ingest_enabled",
        "misp_url",
        "auto_close_enabled",
    ):
        value = getattr(payload, attr)
        if value is not None:
            sets.append(f"{attr} = :{attr}")
            params[attr] = value
    if not sets:
        return await get_integrations(tenant_id, request)

    # Writes on integration_configs are tenant-scoped; wrap so WITH CHECK
    # passes for MSSP callers whose middleware left current_tenant_id unset.
    async with tenant_context(db, tenant_id):
        # Upsert pattern: ensure a row exists for the tenant, then update.
        await db.execute(
            text(
                "INSERT INTO integration_configs (tenant_id) VALUES (:t) "
                "ON CONFLICT (tenant_id) DO NOTHING"
            ),
            {"t": str(tenant_id)},
        )
        await db.execute(
            text(
                f"UPDATE integration_configs SET {', '.join(sets)} "
                f"WHERE tenant_id = :t"
            ),
            params,
        )
    return await get_integrations(tenant_id, request)


# ---------------------------------------------------------------------------
# Engagements (declared pentest / red-team windows) — #31
# ---------------------------------------------------------------------------


class DeclareEngagementRequest(BaseModel):
    name: str
    kind: str = "pentest"
    starts_at: datetime
    ends_at: datetime
    scope_source_ips: list[str] = Field(default_factory=list)
    scope_hosts: list[str] = Field(default_factory=list)
    scope_techniques: list[str] = Field(default_factory=list)


class RevokeEngagementRequest(BaseModel):
    reason: str | None = None


class EngagementDTO(BaseModel):
    id: str
    name: str
    kind: str
    starts_at: datetime
    ends_at: datetime
    scope_source_ips: list[str]
    scope_hosts: list[str]
    scope_techniques: list[str]
    revoked_at: datetime | None
    created_at: datetime
    declared_test_count: int
    out_of_scope_count: int


def _engagement_dto(row: dict[str, Any]) -> EngagementDTO:
    return EngagementDTO(
        id=str(row["id"]),
        name=row["name"],
        kind=row["kind"],
        starts_at=row["starts_at"],
        ends_at=row["ends_at"],
        scope_source_ips=list(row["scope_source_ips"] or []),
        scope_hosts=list(row["scope_hosts"] or []),
        scope_techniques=list(row["scope_techniques"] or []),
        revoked_at=row["revoked_at"],
        created_at=row["created_at"],
        declared_test_count=int(row["declared_test_count"] or 0),
        out_of_scope_count=int(row["out_of_scope_count"] or 0),
    )


@engagements_router.get(
    "/{tenant_id}/engagements",
    response_model=list[EngagementDTO],
    dependencies=[Depends(require_role(Role.PLATFORM_ADMIN, Role.MSSP_ADMIN, Role.ANALYST))],
)
async def list_engagements_route(
    tenant_id: UUID, request: Request, include_revoked: bool = False
) -> list[EngagementDTO]:
    db = _db(request)
    async with tenant_context(db, tenant_id):
        rows = await list_engagements(
            db, tenant_id=tenant_id, include_revoked=include_revoked
        )
    return [_engagement_dto(r) for r in rows]


@engagements_router.post(
    "/{tenant_id}/engagements",
    dependencies=[Depends(require_role(Role.PLATFORM_ADMIN, Role.MSSP_ADMIN, Role.ANALYST))],
)
async def declare_engagement_route(
    tenant_id: UUID, payload: DeclareEngagementRequest, request: Request
) -> dict[str, str]:
    db = _db(request)
    identity = current_identity(request)
    async with tenant_context(db, tenant_id):
        try:
            eid = await declare_engagement(
                db, tenant_id=tenant_id, name=payload.name, kind=payload.kind,
                starts_at=payload.starts_at, ends_at=payload.ends_at,
                scope_source_ips=payload.scope_source_ips,
                scope_hosts=payload.scope_hosts,
                scope_techniques=payload.scope_techniques,
                created_by=identity.user_id,
            )
        except ValueError as exc:
            raise HTTPException(400, str(exc))
    return {"id": eid}


@engagements_router.post(
    "/{tenant_id}/engagements/{engagement_id}/revoke",
    dependencies=[Depends(require_role(Role.PLATFORM_ADMIN, Role.MSSP_ADMIN, Role.ANALYST))],
)
async def revoke_engagement_route(
    tenant_id: UUID, engagement_id: UUID,
    payload: RevokeEngagementRequest, request: Request,
) -> dict[str, str]:
    db = _db(request)
    identity = current_identity(request)
    async with tenant_context(db, tenant_id):
        ok = await revoke_engagement(
            db, tenant_id=tenant_id, engagement_id=engagement_id,
            revoked_by=identity.user_id, reason=payload.reason,
        )
    if not ok:
        raise HTTPException(404, "engagement not found or already revoked")
    return {"ok": "revoked"}


__all__ = [
    "alerts_router",
    "engagements_router",
    "integrations_router",
    "mssp_investigations_router",
    "proposals_router",
    "tenant_investigations_router",
]
