"""API surface for native AI-led incident response.

Cases, events, proposals, alerts, integrations.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field, computed_field
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
from soctalk.core.observability.audit import log_audit
from soctalk.core.tenancy.auth import current_identity
from soctalk.core.tenancy.context import tenant_context
from soctalk.core.tenancy.decorators import (
    require_permission,
    require_permission_any,
    require_role,
    require_tenant_role,
)
from soctalk.core.tenancy.models import Role, UserType
from soctalk.core.tenancy.permissions import (
    PRIVILEGED_CAPABILITY_CLASSES,
    Permission,
    has_permission,
)
from soctalk.response.authoring import (
    ResponsePlaybookConflictError,
    ResponsePlaybookValidationError,
)
from soctalk.response.authoring import get_authored as get_authored_response
from soctalk.response.authoring import list_authored as list_authored_response
from soctalk.response.authoring import retire_authored as retire_authored_response
from soctalk.response.authoring import set_authored_status as set_authored_status_response
from soctalk.response.authoring import to_yaml as to_yaml_response
from soctalk.response.authoring import upsert_authored as upsert_authored_response
from soctalk.triage_policy.authoring import (
    TriagePolicyConflictError,
    TriagePolicyValidationError,
    get_authored,
    list_authored,
    retire_authored,
    set_authored_status,
    to_yaml,
    upsert_authored,
)
from soctalk.triage_policy.registry import BUILTIN_TRIAGE_POLICIES

mssp_investigations_router = APIRouter(prefix="/api/mssp/investigations", tags=["ir-mssp"])
tenant_investigations_router = APIRouter(prefix="/api/tenant/investigations", tags=["ir-tenant"])
alerts_router = APIRouter(prefix="/api/mssp/alerts", tags=["ir-alerts"])
proposals_router = APIRouter(prefix="/api/mssp/proposals", tags=["ir-proposals"])
integrations_router = APIRouter(
    prefix="/api/mssp/tenants", tags=["ir-integrations"]
)
engagements_router = APIRouter(prefix="/api/mssp/tenants", tags=["ir-engagements"])
playbooks_router = APIRouter(prefix="/api/mssp/playbooks", tags=["ir-playbooks"])
triage_policies_router = APIRouter(
    prefix="/api/mssp/triage-policies", tags=["ir-triage-policies"]
)
authored_playbooks_router = APIRouter(prefix="/api/mssp/tenants", tags=["ir-playbooks"])
authored_response_playbooks_router = APIRouter(
    prefix="/api/mssp/tenants", tags=["ir-response-playbooks"]
)


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
    dependencies=[Depends(require_role(Role.PLATFORM_ADMIN, Role.MSSP_ADMIN, Role.MSSP_MANAGER, Role.ANALYST))],
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
    dependencies=[Depends(require_role(Role.PLATFORM_ADMIN, Role.MSSP_ADMIN, Role.MSSP_MANAGER, Role.ANALYST))],
)
async def get_case_mssp(investigation_id: UUID, request: Request) -> CaseDetail:
    db = _db(request)
    return await _case_detail(db, investigation_id)


@mssp_investigations_router.get(
    "/{investigation_id}/events",
    response_model=list[CaseEventDTO],
    dependencies=[Depends(require_role(Role.PLATFORM_ADMIN, Role.MSSP_ADMIN, Role.MSSP_MANAGER, Role.ANALYST))],
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
    dependencies=[Depends(require_role(Role.PLATFORM_ADMIN, Role.MSSP_ADMIN, Role.MSSP_MANAGER, Role.ANALYST))],
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
    dependencies=[Depends(require_role(Role.PLATFORM_ADMIN, Role.MSSP_ADMIN, Role.MSSP_MANAGER, Role.ANALYST))],
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
# Tenant operate routes (co-managed SOC — tenant_analyst triages its OWN cases).
# Tenant is pinned from the TOKEN (never a request param); the investigation is
# verified to belong to that tenant inside ``tenant_context`` (RLS hides foreign
# rows → 404), so a tenant operator can only ever act on its own tenant's cases.
# ---------------------------------------------------------------------------


async def _assert_own_investigation(db: AsyncSession, investigation_id: UUID) -> None:
    """Fail closed (404) unless ``investigation_id`` is visible in the CURRENT
    ``tenant_context`` — i.e. belongs to the caller's tenant. Must be called
    INSIDE ``tenant_context(db, caller_tid)``."""
    seen = (
        await db.execute(
            text("SELECT 1 FROM investigations WHERE id = :id"),
            {"id": str(investigation_id)},
        )
    ).scalar_one_or_none()
    if seen is None:
        raise HTTPException(404, "investigation not found")


@tenant_investigations_router.post(
    "/{investigation_id}/messages",
    dependencies=[
        Depends(require_permission(Permission.TENANT_TRIAGE_INVESTIGATION, audience="tenant"))
    ],
)
async def tenant_post_analyst_message(
    investigation_id: UUID, payload: AnalystMessageRequest, request: Request
) -> dict[str, str]:
    db = _db(request)
    identity = current_identity(request)
    tid = _caller_tenant(request)
    async with tenant_context(db, tid):
        await _assert_own_investigation(db, investigation_id)
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


@tenant_investigations_router.patch(
    "/{investigation_id}/facts",
    dependencies=[
        Depends(require_permission(Permission.TENANT_TRIAGE_INVESTIGATION, audience="tenant"))
    ],
)
async def tenant_patch_case_facts(
    investigation_id: UUID, payload: FactsCorrectionRequest, request: Request
) -> dict[str, str]:
    db = _db(request)
    identity = current_identity(request)
    tid = _caller_tenant(request)
    async with tenant_context(db, tid):
        await _assert_own_investigation(db, investigation_id)
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
        await consume_new_events(db, tid, investigation_id)
    return {"event_id": str(event_id)}


# ---------------------------------------------------------------------------
# Proposals
# ---------------------------------------------------------------------------


@proposals_router.get(
    "",
    response_model=list[ProposalDTO],
    dependencies=[Depends(require_role(Role.PLATFORM_ADMIN, Role.MSSP_ADMIN, Role.MSSP_MANAGER, Role.ANALYST))],
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


# Proposal decisions are shared: the MSSP analyst OR a co-managed-SOC tenant operator.
_APPROVE_PROPOSAL_GUARD = require_permission_any(
    (Permission.APPROVE_PROPOSAL, "mssp"),
    (Permission.TENANT_APPROVE_PROPOSAL, "tenant"),
)


def _may_approve_privileged(identity: Any) -> bool:
    """Whether the caller may sign off a WRITE_EXTERNAL (high-blast) proposal — a
    SOC-manager-tier decision on BOTH audiences (separation of duties)."""
    if identity.user_type == UserType.TENANT.value:
        return has_permission(identity.role, Permission.TENANT_APPROVE_PRIVILEGED_PROPOSAL)
    return has_permission(identity.role, Permission.APPROVE_PRIVILEGED_PROPOSAL)


@proposals_router.post(
    "/{proposal_id}/approve",
    dependencies=[Depends(_APPROVE_PROPOSAL_GUARD)],
)
async def approve_proposal_route(
    proposal_id: UUID,
    payload: ProposalDecisionRequest,
    request: Request,
) -> dict[str, str]:
    db = _db(request)
    identity = current_identity(request)
    is_tenant = identity.user_type == UserType.TENANT.value

    async def _do(tid: UUID) -> None:
        # Approving a proposal enqueues+dispatches its action. Standard/read/sandbox actions
        # are analyst-approvable; anything that writes to an external system (isolate/block/
        # ticket) is a privileged sign-off — SOC-manager tier only (separation of duties),
        # enforced identically for MSSP and tenant operators. capability_class is read from
        # the DB row (never the request), so it can't be forged.
        row = (
            await db.execute(
                text("SELECT capability_class FROM proposals WHERE id = :id"),
                {"id": str(proposal_id)},
            )
        ).mappings().first()
        if row is None:
            raise HTTPException(404, "proposal not found")
        if str(row["capability_class"]) in PRIVILEGED_CAPABILITY_CLASSES and not _may_approve_privileged(
            identity
        ):
            raise HTTPException(
                403, "approving an external-write action requires the SOC-manager role"
            )
        try:
            await approve_proposal(
                db,
                proposal_id=proposal_id,
                approver_user_id=identity.user_id,
                reason=payload.reason,
            )
        except ValueError as exc:
            raise HTTPException(400, str(exc))

    if is_tenant:
        # Tenant operator: tenant pinned from the TOKEN; the proposal lookup + privileged
        # check + write all run inside the caller's own tenant_context (RLS hides foreign
        # proposals → 404, and grants own-tenant mssp_only visibility so the operator can act).
        tid = _caller_tenant(request)
        async with tenant_context(db, tid):
            await _do(tid)
    else:
        # MSSP fleet caller: resolve the tenant from the proposal (cross-tenant read), then
        # wrap the write in that tenant's context so RLS WITH CHECK passes.
        tid_row = (
            await db.execute(
                text("SELECT tenant_id FROM proposals WHERE id = :id"),
                {"id": str(proposal_id)},
            )
        ).scalar_one_or_none()
        if tid_row is None:
            raise HTTPException(404, "proposal not found")
        async with tenant_context(db, UUID(str(tid_row))):
            await _do(UUID(str(tid_row)))
    return {"ok": "approved"}


@proposals_router.post(
    "/{proposal_id}/reject",
    dependencies=[Depends(_APPROVE_PROPOSAL_GUARD)],
)
async def reject_proposal_route(
    proposal_id: UUID,
    payload: ProposalDecisionRequest,
    request: Request,
) -> dict[str, str]:
    db = _db(request)
    identity = current_identity(request)
    is_tenant = identity.user_type == UserType.TENANT.value

    async def _do() -> None:
        seen = (
            await db.execute(
                text("SELECT 1 FROM proposals WHERE id = :id"),
                {"id": str(proposal_id)},
            )
        ).scalar_one_or_none()
        if seen is None:
            raise HTTPException(404, "proposal not found")
        try:
            await reject_proposal(
                db,
                proposal_id=proposal_id,
                approver_user_id=identity.user_id,
                reason=payload.reason,
            )
        except ValueError as exc:
            raise HTTPException(400, str(exc))

    if is_tenant:
        async with tenant_context(db, _caller_tenant(request)):
            await _do()
    else:
        tid_row = (
            await db.execute(
                text("SELECT tenant_id FROM proposals WHERE id = :id"),
                {"id": str(proposal_id)},
            )
        ).scalar_one_or_none()
        if tid_row is None:
            raise HTTPException(404, "proposal not found")
        async with tenant_context(db, UUID(str(tid_row))):
            await _do()
    return {"ok": "rejected"}


# ---------------------------------------------------------------------------
# Alerts
# ---------------------------------------------------------------------------


@alerts_router.get(
    "",
    response_model=list[AlertDTO],
    dependencies=[Depends(require_role(Role.PLATFORM_ADMIN, Role.MSSP_ADMIN, Role.MSSP_MANAGER, Role.ANALYST))],
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
    dependencies=[Depends(require_permission(Permission.VIEW_ENGAGEMENTS, audience="mssp"))],
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
    dependencies=[Depends(require_permission(Permission.AUTHORIZE_ENGAGEMENT, audience="mssp"))],
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
    dependencies=[Depends(require_permission(Permission.AUTHORIZE_ENGAGEMENT, audience="mssp"))],
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


# ---------------------------------------------------------------------------
# Tenant self-service engagements — a tenant declares its OWN authorized activity
# (e.g. a pentest window + scope) so the SOC deconflicts it. The tenant_id comes from
# the caller's token, never a path param, so a tenant can only ever touch its own org.
# ---------------------------------------------------------------------------

tenant_engagements_router = APIRouter(prefix="/api/tenant", tags=["tenant-engagements"])


def _caller_tenant(request: Request) -> UUID:
    identity = current_identity(request)
    tid = identity.tenant_id
    if not tid:
        raise HTTPException(400, "tenant_id missing from token")
    return tid if isinstance(tid, UUID) else UUID(str(tid))


@tenant_engagements_router.get(
    "/engagements",
    response_model=list[EngagementDTO],
    dependencies=[
        Depends(require_permission(Permission.TENANT_VIEW_ENGAGEMENTS, audience="tenant"))
    ],
)
async def tenant_list_engagements_route(
    request: Request, include_revoked: bool = False
) -> list[EngagementDTO]:
    tid = _caller_tenant(request)
    db = _db(request)
    async with tenant_context(db, tid):
        rows = await list_engagements(db, tenant_id=tid, include_revoked=include_revoked)
    return [_engagement_dto(r) for r in rows]


@tenant_engagements_router.post(
    "/engagements",
    dependencies=[
        Depends(require_permission(Permission.TENANT_AUTHORIZE_ENGAGEMENT, audience="tenant"))
    ],
)
async def tenant_declare_engagement_route(
    payload: DeclareEngagementRequest, request: Request
) -> dict[str, str]:
    tid = _caller_tenant(request)
    db = _db(request)
    identity = current_identity(request)
    async with tenant_context(db, tid):
        try:
            eid = await declare_engagement(
                db, tenant_id=tid, name=payload.name, kind=payload.kind,
                starts_at=payload.starts_at, ends_at=payload.ends_at,
                scope_source_ips=payload.scope_source_ips,
                scope_hosts=payload.scope_hosts,
                scope_techniques=payload.scope_techniques,
                created_by=identity.user_id,
            )
        except ValueError as exc:
            raise HTTPException(400, str(exc))
    return {"id": eid}


@tenant_engagements_router.post(
    "/engagements/{engagement_id}/revoke",
    dependencies=[
        Depends(require_permission(Permission.TENANT_AUTHORIZE_ENGAGEMENT, audience="tenant"))
    ],
)
async def tenant_revoke_engagement_route(
    engagement_id: UUID, payload: RevokeEngagementRequest, request: Request
) -> dict[str, str]:
    tid = _caller_tenant(request)
    db = _db(request)
    identity = current_identity(request)
    async with tenant_context(db, tid):
        ok = await revoke_engagement(
            db, tenant_id=tid, engagement_id=engagement_id,
            revoked_by=identity.user_id, reason=payload.reason,
        )
    if not ok:
        raise HTTPException(404, "engagement not found or already revoked")
    return {"ok": "revoked"}


# ---------------------------------------------------------------------------
# Triage policies (read-only governance view) — #43/#44
# ---------------------------------------------------------------------------


class TriagePolicyGuardrailDTO(BaseModel):
    when: dict[str, Any]
    effect: str
    to: str
    reason: str


class TriagePolicyMatchDTO(BaseModel):
    rule_groups: list[str]
    rule_ids: list[str]
    authorization_tracks: list[str]


class TriagePolicyDTO(BaseModel):
    id: str
    version: int
    tenant: str
    status: str  # active | shadow
    priority: int
    source: str  # built-in | file
    applies_to: TriagePolicyMatchDTO
    required_steps: list[str]
    decision_modules: list[str]
    deterministic_disposition: str | None
    legal_actions: dict[str, list[str]]
    close_signoff_data_classes: list[str]
    guardrails: list[TriagePolicyGuardrailDTO]


@triage_policies_router.get(
    "",
    response_model=list[TriagePolicyDTO],
    dependencies=[Depends(require_role(Role.PLATFORM_ADMIN, Role.MSSP_ADMIN, Role.MSSP_MANAGER, Role.ANALYST))],
)
@playbooks_router.get(
    "",
    response_model=list[TriagePolicyDTO],
    dependencies=[Depends(require_role(Role.PLATFORM_ADMIN, Role.MSSP_ADMIN, Role.MSSP_MANAGER, Role.ANALYST))],
    deprecated=True,
)
async def list_triage_policies_route(request: Request) -> list[TriagePolicyDTO]:
    """The compiled-in (built-in) triage policies that govern triage. Deliberately
    scoped to built-ins: file triage policies (``SOCTALK_PLAYBOOK_DIR``) load per-PROCESS
    in the runs-worker, so the API can't truthfully report which govern — listing
    the API process's own files would show triage policies that no worker enforces (and
    hide tenant-scoped ones that do). Read-only; built-ins are vetted code."""
    return [
        TriagePolicyDTO(
            id=pb.id,
            version=pb.version,
            tenant=pb.tenant,
            status=pb.status,
            priority=pb.priority,
            source="built-in",
            applies_to=TriagePolicyMatchDTO(
                rule_groups=list(pb.applies_to.rule_groups),
                rule_ids=list(pb.applies_to.rule_ids),
                authorization_tracks=list(pb.applies_to.authorization_tracks),
            ),
            required_steps=list(pb.required_steps),
            decision_modules=list(pb.decision_modules),
            deterministic_disposition=pb.deterministic_disposition,
            legal_actions={k: list(v) for k, v in pb.legal_actions.items()},
            close_signoff_data_classes=list(pb.close_signoff_data_classes),
            guardrails=[
                TriagePolicyGuardrailDTO(when=g.when, effect=g.effect, to=g.to, reason=g.reason)
                for g in pb.guardrails
            ],
        )
        for pb in sorted(BUILTIN_TRIAGE_POLICIES, key=lambda p: p.priority)
    ]


# --- authored triage policies (DB-backed shadow/draft + export) ---


class AuthoredTriagePolicyRequest(BaseModel):
    definition: dict[str, Any]
    status: str = "shadow"  # draft | shadow (authoring lifecycle; never active)


class AuthoredTriagePolicyDTO(BaseModel):
    triage_policy_id: str
    revision: int
    status: str
    definition: dict[str, Any]

    @computed_field  # type: ignore[prop-decorator]
    @property
    def playbook_id(self) -> str:
        """Deprecated wire mirror of ``triage_policy_id`` — kept one release for
        clients still reading the old field. Remove alongside the /playbooks routes."""
        return self.triage_policy_id


def _authored_dto(row: dict[str, Any]) -> AuthoredTriagePolicyDTO:
    return AuthoredTriagePolicyDTO(
        triage_policy_id=row["triage_policy_id"],
        revision=row["revision"],
        status=row["status"],
        definition=dict(row["definition"]),
    )


@authored_playbooks_router.get(
    "/{tenant_id}/triage-policies",
    response_model=list[AuthoredTriagePolicyDTO],
    dependencies=[Depends(require_role(Role.PLATFORM_ADMIN, Role.MSSP_ADMIN, Role.MSSP_MANAGER, Role.ANALYST))],
)
@authored_playbooks_router.get(
    "/{tenant_id}/playbooks",
    response_model=list[AuthoredTriagePolicyDTO],
    dependencies=[Depends(require_role(Role.PLATFORM_ADMIN, Role.MSSP_ADMIN, Role.MSSP_MANAGER, Role.ANALYST))],
    deprecated=True,
)
async def list_authored_triage_policies_route(
    tenant_id: UUID, request: Request
) -> list[AuthoredTriagePolicyDTO]:
    db = _db(request)
    async with tenant_context(db, tenant_id):
        rows = await list_authored(db, tenant_id=tenant_id)
    return [_authored_dto(r) for r in rows]


@authored_playbooks_router.post(
    "/{tenant_id}/triage-policies",
    response_model=AuthoredTriagePolicyDTO,
    dependencies=[Depends(require_role(Role.PLATFORM_ADMIN, Role.MSSP_ADMIN))],
)
@authored_playbooks_router.post(
    "/{tenant_id}/playbooks",
    response_model=AuthoredTriagePolicyDTO,
    dependencies=[Depends(require_role(Role.PLATFORM_ADMIN, Role.MSSP_ADMIN))],
    deprecated=True,
)
async def create_authored_triage_policy_route(
    tenant_id: UUID, payload: AuthoredTriagePolicyRequest, request: Request
) -> AuthoredTriagePolicyDTO:
    db = _db(request)
    identity = current_identity(request)
    async with tenant_context(db, tenant_id):
        pid = str(payload.definition.get("id") or "")
        if pid and await get_authored(db, tenant_id=tenant_id, triage_policy_id=pid) is not None:
            raise HTTPException(409, f"triage policy '{pid}' already exists — use PUT to edit")
        try:
            result = await upsert_authored(
                db, tenant_id=tenant_id, definition=payload.definition,
                status=payload.status, created_by=identity.user_id,
            )
        except TriagePolicyValidationError as exc:
            raise HTTPException(400, str(exc))
        except TriagePolicyConflictError as exc:
            raise HTTPException(409, str(exc))
        await log_audit(
            db, action="ir.triage_policy.authored_created",
            actor_principal="analyst", actor_id=str(identity.user_id),
            tenant_id=tenant_id, resource_type="triage_policy", resource_id=result["triage_policy_id"],
        )
    return _authored_dto(result)


@authored_playbooks_router.put(
    "/{tenant_id}/triage-policies/{triage_policy_id}",
    response_model=AuthoredTriagePolicyDTO,
    dependencies=[Depends(require_role(Role.PLATFORM_ADMIN, Role.MSSP_ADMIN))],
)
@authored_playbooks_router.put(
    "/{tenant_id}/playbooks/{triage_policy_id}",
    response_model=AuthoredTriagePolicyDTO,
    dependencies=[Depends(require_role(Role.PLATFORM_ADMIN, Role.MSSP_ADMIN))],
    deprecated=True,
)
async def update_authored_triage_policy_route(
    tenant_id: UUID, triage_policy_id: str, payload: AuthoredTriagePolicyRequest, request: Request
) -> AuthoredTriagePolicyDTO:
    db = _db(request)
    identity = current_identity(request)
    if str(payload.definition.get("id") or "") != triage_policy_id:
        raise HTTPException(400, "definition.id must match the triage policy id in the path")
    async with tenant_context(db, tenant_id):
        prior = await get_authored(db, tenant_id=tenant_id, triage_policy_id=triage_policy_id)
        if prior is None:
            raise HTTPException(404, "triage policy not found")
        try:
            result = await upsert_authored(
                db, tenant_id=tenant_id, definition=payload.definition,
                status=payload.status, created_by=identity.user_id,
            )
            # Editing an ACTIVE triage policy must not silently drop it to shadow (the old
            # ConfigMap would keep governing until an unrelated reconcile, then vanish).
            # Keep it governing on the new definition + roll it out.
            if prior["status"] == "active":
                result = await set_authored_status(
                    db, tenant_id=tenant_id, triage_policy_id=triage_policy_id, status="active",
                    created_by=identity.user_id,
                )
        except TriagePolicyValidationError as exc:
            raise HTTPException(400, str(exc))
        except TriagePolicyConflictError as exc:
            raise HTTPException(409, str(exc))
        await log_audit(
            db, action="ir.triage_policy.authored_updated",
            actor_principal="analyst", actor_id=str(identity.user_id),
            tenant_id=tenant_id, resource_type="triage_policy", resource_id=triage_policy_id,
            notes=f"revision {result['revision']}",
        )
        if prior["status"] == "active":
            await _enqueue_triage_policy_reconcile(db, tenant_id)
    return _authored_dto(result)


@authored_playbooks_router.delete(
    "/{tenant_id}/triage-policies/{triage_policy_id}",
    dependencies=[Depends(require_role(Role.PLATFORM_ADMIN, Role.MSSP_ADMIN))],
)
@authored_playbooks_router.delete(
    "/{tenant_id}/playbooks/{triage_policy_id}",
    dependencies=[Depends(require_role(Role.PLATFORM_ADMIN, Role.MSSP_ADMIN))],
    deprecated=True,
)
async def retire_authored_triage_policy_route(
    tenant_id: UUID, triage_policy_id: str, request: Request
) -> dict[str, str]:
    db = _db(request)
    identity = current_identity(request)
    async with tenant_context(db, tenant_id):
        prior = await get_authored(db, tenant_id=tenant_id, triage_policy_id=triage_policy_id)
        ok = await retire_authored(
            db, tenant_id=tenant_id, triage_policy_id=triage_policy_id, retired_by=identity.user_id,
        )
        if not ok:
            raise HTTPException(404, "triage policy not found or already retired")
        await log_audit(
            db, action="ir.triage_policy.authored_retired",
            actor_principal="analyst", actor_id=str(identity.user_id),
            tenant_id=tenant_id, resource_type="triage_policy", resource_id=triage_policy_id,
        )
        # Retiring a governing triage policy must stop it governing.
        if prior is not None and prior["status"] == "active":
            await _enqueue_triage_policy_reconcile(db, tenant_id)
    return {"ok": "retired"}


async def _enqueue_triage_policy_reconcile(db: AsyncSession, tenant_id: UUID) -> None:
    """Queue a tenant reconcile so an activation/deactivation re-renders the ConfigMap and
    rolls the worker (rollout is the activation gate, same as an LLM-key rotation). No-op for
    non-ACTIVE tenants (no live worker); the active-job unique index makes it idempotent."""
    from sqlalchemy import select

    from soctalk.core.tenancy.models import ProvisioningJob, Tenant, TenantState

    state = (
        await db.execute(select(Tenant.state).where(Tenant.id == tenant_id))
    ).scalar_one_or_none()
    if state != TenantState.ACTIVE.value:
        return
    existing = (
        await db.execute(
            select(ProvisioningJob).where(
                ProvisioningJob.tenant_id == tenant_id,
                ProvisioningJob.kind == "tenant.reconcile",
                ProvisioningJob.status.in_(["pending", "in_flight"]),
            )
        )
    ).scalar_one_or_none()
    if existing is None:
        db.add(ProvisioningJob(tenant_id=tenant_id, kind="tenant.reconcile", status="pending"))


async def _set_authored_and_reconcile(
    tenant_id: UUID, triage_policy_id: str, status: str, request: Request, action: str
) -> AuthoredTriagePolicyDTO:
    db = _db(request)
    identity = current_identity(request)
    async with tenant_context(db, tenant_id):
        try:
            result = await set_authored_status(
                db, tenant_id=tenant_id, triage_policy_id=triage_policy_id, status=status,
                created_by=identity.user_id,
            )
        except TriagePolicyValidationError as exc:
            raise HTTPException(400, str(exc))
        except TriagePolicyConflictError as exc:
            raise HTTPException(409, str(exc))
        if result is None:
            raise HTTPException(404, "triage policy not found or retired")
        await log_audit(
            db, action=action, actor_principal="analyst", actor_id=str(identity.user_id),
            tenant_id=tenant_id, resource_type="triage_policy", resource_id=triage_policy_id,
        )
        await _enqueue_triage_policy_reconcile(db, tenant_id)
    return _authored_dto(result)


@authored_playbooks_router.post(
    "/{tenant_id}/triage-policies/{triage_policy_id}/activate",
    response_model=AuthoredTriagePolicyDTO,
    dependencies=[Depends(require_role(Role.PLATFORM_ADMIN, Role.MSSP_ADMIN))],
)
@authored_playbooks_router.post(
    "/{tenant_id}/playbooks/{triage_policy_id}/activate",
    response_model=AuthoredTriagePolicyDTO,
    dependencies=[Depends(require_role(Role.PLATFORM_ADMIN, Role.MSSP_ADMIN))],
    deprecated=True,
)
async def activate_authored_triage_policy_route(
    tenant_id: UUID, triage_policy_id: str, request: Request
) -> AuthoredTriagePolicyDTO:
    """Activate an authored triage policy so it governs triage. Materialized into the tenant's
    triage policy ConfigMap on the queued reconcile (rollout is the activation gate)."""
    return await _set_authored_and_reconcile(
        tenant_id, triage_policy_id, "active", request, "ir.triage_policy.authored_activated"
    )


@authored_playbooks_router.post(
    "/{tenant_id}/triage-policies/{triage_policy_id}/deactivate",
    response_model=AuthoredTriagePolicyDTO,
    dependencies=[Depends(require_role(Role.PLATFORM_ADMIN, Role.MSSP_ADMIN))],
)
@authored_playbooks_router.post(
    "/{tenant_id}/playbooks/{triage_policy_id}/deactivate",
    response_model=AuthoredTriagePolicyDTO,
    dependencies=[Depends(require_role(Role.PLATFORM_ADMIN, Role.MSSP_ADMIN))],
    deprecated=True,
)
async def deactivate_authored_triage_policy_route(
    tenant_id: UUID, triage_policy_id: str, request: Request
) -> AuthoredTriagePolicyDTO:
    """Deactivate (back to shadow) — the reconcile drops it from the ConfigMap."""
    return await _set_authored_and_reconcile(
        tenant_id, triage_policy_id, "shadow", request, "ir.triage_policy.authored_deactivated"
    )


@authored_playbooks_router.get(
    "/{tenant_id}/triage-policies/{triage_policy_id}/export",
    dependencies=[Depends(require_role(Role.PLATFORM_ADMIN, Role.MSSP_ADMIN, Role.MSSP_MANAGER, Role.ANALYST))],
)
@authored_playbooks_router.get(
    "/{tenant_id}/playbooks/{triage_policy_id}/export",
    dependencies=[Depends(require_role(Role.PLATFORM_ADMIN, Role.MSSP_ADMIN, Role.MSSP_MANAGER, Role.ANALYST))],
    deprecated=True,
)
async def export_authored_triage_policy_route(
    tenant_id: UUID, triage_policy_id: str, request: Request
) -> dict[str, str]:
    """Export the authored definition as YAML for git / worker rollout (activation)."""
    db = _db(request)
    async with tenant_context(db, tenant_id):
        row = await get_authored(db, tenant_id=tenant_id, triage_policy_id=triage_policy_id)
    if row is None:
        raise HTTPException(404, "triage policy not found")
    return {
        "triage_policy_id": triage_policy_id,
        "playbook_id": triage_policy_id,  # deprecated mirror, one release
        "yaml": to_yaml(dict(row["definition"])),
    }


# ---------------------------------------------------------------------------
# Authored response playbooks (DB-backed, live activation) — #49 phase 2
#
# Unlike triage policies (which export to YAML for a worker rollout), an authored
# response playbook activates LIVE: the response dispatcher runs on L1 with DB
# access, so 'active' rows govern immediately with no reconcile/rollout.
# ---------------------------------------------------------------------------


class AuthoredResponsePlaybookRequest(BaseModel):
    definition: dict[str, Any]
    status: str = "shadow"  # draft | shadow (create/edit lifecycle; activate via route)


class AuthoredResponsePlaybookDTO(BaseModel):
    response_playbook_id: str
    revision: int
    status: str
    definition: dict[str, Any]


def _authored_response_dto(row: dict[str, Any]) -> AuthoredResponsePlaybookDTO:
    return AuthoredResponsePlaybookDTO(
        response_playbook_id=row["response_playbook_id"],
        revision=row["revision"],
        status=row["status"],
        definition=dict(row["definition"]),
    )


@authored_response_playbooks_router.get(
    "/{tenant_id}/response-playbooks",
    response_model=list[AuthoredResponsePlaybookDTO],
    dependencies=[Depends(require_role(Role.PLATFORM_ADMIN, Role.MSSP_ADMIN, Role.MSSP_MANAGER, Role.ANALYST))],
)
async def list_authored_response_playbooks_route(
    tenant_id: UUID, request: Request
) -> list[AuthoredResponsePlaybookDTO]:
    db = _db(request)
    async with tenant_context(db, tenant_id):
        rows = await list_authored_response(db, tenant_id=tenant_id)
    return [_authored_response_dto(r) for r in rows]


@authored_response_playbooks_router.post(
    "/{tenant_id}/response-playbooks",
    response_model=AuthoredResponsePlaybookDTO,
    dependencies=[Depends(require_role(Role.PLATFORM_ADMIN, Role.MSSP_ADMIN))],
)
async def create_authored_response_playbook_route(
    tenant_id: UUID, payload: AuthoredResponsePlaybookRequest, request: Request
) -> AuthoredResponsePlaybookDTO:
    db = _db(request)
    identity = current_identity(request)
    async with tenant_context(db, tenant_id):
        pid = str(payload.definition.get("id") or "")
        if pid and await get_authored_response(
            db, tenant_id=tenant_id, response_playbook_id=pid
        ) is not None:
            raise HTTPException(409, f"response playbook '{pid}' already exists — use PUT")
        try:
            result = await upsert_authored_response(
                db, tenant_id=tenant_id, definition=payload.definition,
                status=payload.status, created_by=identity.user_id,
            )
        except ResponsePlaybookValidationError as exc:
            raise HTTPException(400, str(exc))
        except ResponsePlaybookConflictError as exc:
            raise HTTPException(409, str(exc))
        await log_audit(
            db, action="ir.response_playbook.authored_created",
            actor_principal="analyst", actor_id=str(identity.user_id),
            tenant_id=tenant_id, resource_type="response_playbook",
            resource_id=result["response_playbook_id"],
        )
    return _authored_response_dto(result)


@authored_response_playbooks_router.put(
    "/{tenant_id}/response-playbooks/{response_playbook_id}",
    response_model=AuthoredResponsePlaybookDTO,
    dependencies=[Depends(require_role(Role.PLATFORM_ADMIN, Role.MSSP_ADMIN))],
)
async def update_authored_response_playbook_route(
    tenant_id: UUID, response_playbook_id: str,
    payload: AuthoredResponsePlaybookRequest, request: Request,
) -> AuthoredResponsePlaybookDTO:
    db = _db(request)
    identity = current_identity(request)
    if str(payload.definition.get("id") or "") != response_playbook_id:
        raise HTTPException(400, "definition.id must match the id in the path")
    async with tenant_context(db, tenant_id):
        prior = await get_authored_response(
            db, tenant_id=tenant_id, response_playbook_id=response_playbook_id
        )
        if prior is None:
            raise HTTPException(404, "response playbook not found")
        try:
            result = await upsert_authored_response(
                db, tenant_id=tenant_id, definition=payload.definition,
                status=payload.status, created_by=identity.user_id,
            )
            # Editing an ACTIVE playbook keeps it governing on the new definition
            # (it re-validates on the activate call) — no silent drop to shadow.
            if prior["status"] == "active":
                result = await set_authored_status_response(
                    db, tenant_id=tenant_id, response_playbook_id=response_playbook_id,
                    status="active", created_by=identity.user_id,
                )
        except ResponsePlaybookValidationError as exc:
            raise HTTPException(400, str(exc))
        except ResponsePlaybookConflictError as exc:
            raise HTTPException(409, str(exc))
        await log_audit(
            db, action="ir.response_playbook.authored_updated",
            actor_principal="analyst", actor_id=str(identity.user_id),
            tenant_id=tenant_id, resource_type="response_playbook",
            resource_id=response_playbook_id, notes=f"revision {result['revision']}",
        )
    return _authored_response_dto(result)


@authored_response_playbooks_router.delete(
    "/{tenant_id}/response-playbooks/{response_playbook_id}",
    dependencies=[Depends(require_role(Role.PLATFORM_ADMIN, Role.MSSP_ADMIN))],
)
async def retire_authored_response_playbook_route(
    tenant_id: UUID, response_playbook_id: str, request: Request
) -> dict[str, str]:
    db = _db(request)
    identity = current_identity(request)
    async with tenant_context(db, tenant_id):
        ok = await retire_authored_response(
            db, tenant_id=tenant_id, response_playbook_id=response_playbook_id,
            retired_by=identity.user_id,
        )
        if not ok:
            raise HTTPException(404, "response playbook not found or already retired")
        await log_audit(
            db, action="ir.response_playbook.authored_retired",
            actor_principal="analyst", actor_id=str(identity.user_id),
            tenant_id=tenant_id, resource_type="response_playbook",
            resource_id=response_playbook_id,
        )
    return {"ok": "retired"}


async def _set_response_status(
    tenant_id: UUID, response_playbook_id: str, status: str, request: Request, action: str
) -> AuthoredResponsePlaybookDTO:
    db = _db(request)
    identity = current_identity(request)
    async with tenant_context(db, tenant_id):
        try:
            result = await set_authored_status_response(
                db, tenant_id=tenant_id, response_playbook_id=response_playbook_id,
                status=status, created_by=identity.user_id,
            )
        except ResponsePlaybookValidationError as exc:
            raise HTTPException(400, str(exc))
        except ResponsePlaybookConflictError as exc:
            raise HTTPException(409, str(exc))
        if result is None:
            raise HTTPException(404, "response playbook not found or retired")
        await log_audit(
            db, action=action, actor_principal="analyst", actor_id=str(identity.user_id),
            tenant_id=tenant_id, resource_type="response_playbook",
            resource_id=response_playbook_id,
        )
    return _authored_response_dto(result)


@authored_response_playbooks_router.post(
    "/{tenant_id}/response-playbooks/{response_playbook_id}/activate",
    response_model=AuthoredResponsePlaybookDTO,
    dependencies=[Depends(require_role(Role.PLATFORM_ADMIN, Role.MSSP_ADMIN))],
)
async def activate_authored_response_playbook_route(
    tenant_id: UUID, response_playbook_id: str, request: Request
) -> AuthoredResponsePlaybookDTO:
    """Activate so it governs response dispatch LIVE (no rollout — L1 reads the DB)."""
    return await _set_response_status(
        tenant_id, response_playbook_id, "active", request,
        "ir.response_playbook.authored_activated",
    )


@authored_response_playbooks_router.post(
    "/{tenant_id}/response-playbooks/{response_playbook_id}/deactivate",
    response_model=AuthoredResponsePlaybookDTO,
    dependencies=[Depends(require_role(Role.PLATFORM_ADMIN, Role.MSSP_ADMIN))],
)
async def deactivate_authored_response_playbook_route(
    tenant_id: UUID, response_playbook_id: str, request: Request
) -> AuthoredResponsePlaybookDTO:
    """Deactivate back to shadow — stops dispatching immediately (audited only)."""
    return await _set_response_status(
        tenant_id, response_playbook_id, "shadow", request,
        "ir.response_playbook.authored_deactivated",
    )


@authored_response_playbooks_router.get(
    "/{tenant_id}/response-playbooks/{response_playbook_id}/export",
    dependencies=[Depends(require_role(Role.PLATFORM_ADMIN, Role.MSSP_ADMIN, Role.MSSP_MANAGER, Role.ANALYST))],
)
async def export_authored_response_playbook_route(
    tenant_id: UUID, response_playbook_id: str, request: Request
) -> dict[str, str]:
    db = _db(request)
    async with tenant_context(db, tenant_id):
        row = await get_authored_response(
            db, tenant_id=tenant_id, response_playbook_id=response_playbook_id
        )
    if row is None:
        raise HTTPException(404, "response playbook not found")
    return {
        "response_playbook_id": response_playbook_id,
        "yaml": to_yaml_response(dict(row["definition"])),
    }


__all__ = [
    "alerts_router",
    "authored_playbooks_router",
    "authored_response_playbooks_router",
    "engagements_router",
    "integrations_router",
    "mssp_investigations_router",
    "playbooks_router",
    "triage_policies_router",
    "proposals_router",
    "tenant_engagements_router",
    "tenant_investigations_router",
]
