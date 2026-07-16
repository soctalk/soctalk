"""Authorization-fact ingest API (external submitters).

External systems (FIM/IAM connectors, provisioning scripts) submit typed AuthorizationFacts
here; the durable store persists them and the reasoning engine consumes them store-primary.
This is a privileged control surface: a fact can lower suspicion, so submission is authed with
a per-tenant token, tenant-scoped, and the ``source_type``/``trust`` are stamped from the
CREDENTIAL, never trusted from the payload. The safety floor still refuses to let any asserted
fact close over an IOC or an active incident (that stays downstream in the engine/floor).

Auth reuses the per-tenant adapter token; a future dedicated connector-token flavor would map
to CONNECTOR_VERIFIED (trust 100) instead of SYSTEM_ASSERTED (trust 80).
"""

from __future__ import annotations

from uuid import UUID, uuid4

import structlog
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field, ValidationError
from sqlalchemy.ext.asyncio import AsyncSession

from soctalk.core.ir.authorization_store import (
    list_current_facts,
    list_facts_with_status,
    revoke_fact,
    set_review_status,
    store_fact,
)
from soctalk.core.tenancy.auth import current_identity
from soctalk.core.tenancy.context import tenant_context
from soctalk.core.tenancy.decorators import require_permission
from soctalk.core.tenancy.permissions import Permission
from soctalk.models.authorization import (
    AUTHORIZATION_FACT_ADAPTER,
    TRUST_TIER,
    AuthorizationSourceType,
)

logger = structlog.get_logger()

router = APIRouter(prefix="/api/internal/authorization", tags=["internal-authorization"])


def _db(request: Request) -> AsyncSession:
    session = getattr(request.state, "db", None)
    if session is None:
        raise HTTPException(500, "db session not attached to request")
    return session


def _verify_submitter(request: Request) -> UUID:
    """Verify the per-tenant submitter (adapter) token; return its tenant_id."""
    from soctalk.core.tenancy.auth import verify_adapter_token

    auth = request.headers.get("Authorization", "")
    if not auth.lower().startswith("bearer "):
        raise HTTPException(401, "submitter JWT required")
    identity = verify_adapter_token(auth.split(" ", 1)[1].strip())
    if identity is None:
        raise HTTPException(401, "invalid submitter token")
    if identity.tenant_id is None:
        raise HTTPException(400, "submitter token missing tenant_id")
    return identity.tenant_id


class FactSubmission(BaseModel):
    tenant_id: UUID
    facts: list[dict] = Field(min_length=1)


class RevokeRequest(BaseModel):
    reason: str | None = None


@router.post("/facts")
async def submit_facts(payload: FactSubmission, request: Request) -> dict:
    """Ingest a batch of typed AuthorizationFacts. Per-fact validation: a bad fact is
    reported in ``errors`` and skipped; valid facts are stored. Trust is credential-stamped."""
    authed_tid = _verify_submitter(request)
    if authed_tid != payload.tenant_id:
        raise HTTPException(403, "submitter token tenant_id mismatch")

    # The credential fixes the source tier; the payload never gets to claim a higher trust.
    source_type = AuthorizationSourceType.SYSTEM_ASSERTED
    trust = TRUST_TIER[source_type]
    caller = f"adapter:{payload.tenant_id}"

    db = _db(request)
    stored: list[str] = []
    errors: list[dict] = []
    async with tenant_context(db, payload.tenant_id):
        for raw in payload.facts:
            try:
                fact = AUTHORIZATION_FACT_ADAPTER.validate_python(raw)
            except ValidationError as exc:
                errors.append({"id": raw.get("id"), "error": exc.errors()[0].get("msg", "invalid")})
                continue
            fact.source_type = source_type
            fact.trust = trust
            fact.tenant = str(payload.tenant_id)
            fact.provenance.api_caller = caller
            await store_fact(db, tenant_id=payload.tenant_id, fact=fact)
            stored.append(fact.id)

    logger.info(
        "authorization_facts_submitted",
        tenant_id=str(payload.tenant_id),
        stored=len(stored),
        errors=len(errors),
        source_type=source_type.value,
    )
    return {"stored": stored, "errors": errors}


@router.get("/facts")
async def list_facts(request: Request, tenant_id: UUID) -> dict:
    """List the tenant's current (non-revoked, non-superseded) facts."""
    authed_tid = _verify_submitter(request)
    if authed_tid != tenant_id:
        raise HTTPException(403, "submitter token tenant_id mismatch")
    db = _db(request)
    async with tenant_context(db, tenant_id):
        facts = await list_current_facts(db, tenant_id=tenant_id)
    return {"facts": [AUTHORIZATION_FACT_ADAPTER.dump_python(f, mode="json") for f in facts]}


@router.post("/facts/{fact_id}/revoke")
async def revoke(fact_id: str, payload: RevokeRequest, request: Request) -> dict:
    """Soft-delete one fact (the row survives for audit)."""
    authed_tid = _verify_submitter(request)
    db = _db(request)
    async with tenant_context(db, authed_tid):
        ok = await revoke_fact(
            db, tenant_id=authed_tid, fact_id=fact_id, revoked_by=None, reason=payload.reason
        )
    if not ok:
        raise HTTPException(404, "no live fact with that id")
    logger.info("authorization_fact_revoked", tenant_id=str(authed_tid), fact_id=fact_id)
    return {"revoked": fact_id}


# ---------------------------------------------------------------------------
# MSSP governance API (human-authed, per-tenant) — powers the frontend view.
# ---------------------------------------------------------------------------

mssp_router = APIRouter(prefix="/api/mssp/tenants", tags=["authz-facts-mssp"])



class FactCreateRequest(BaseModel):
    fact: dict


@mssp_router.get(
    "/{tenant_id}/authorization/facts",
    dependencies=[Depends(require_permission(Permission.VIEW_AUTHORIZATION_FACTS, audience="mssp"))],
)
async def mssp_list_facts(tenant_id: UUID, request: Request) -> dict:
    """All live facts for the tenant with their review lifecycle, so an analyst can see (and
    approve/reject) tenant-asserted facts that are still ``pending`` and not yet influencing
    triage."""
    db = _db(request)
    async with tenant_context(db, tenant_id):
        rows = await list_facts_with_status(db, tenant_id=tenant_id)
    return {"facts": [{**r["body"], "review_status": r["review_status"]} for r in rows]}


@mssp_router.post(
    "/{tenant_id}/authorization/facts",
    dependencies=[Depends(require_permission(Permission.MANAGE_AUTHORIZATION_FACTS, audience="mssp"))],
)
async def mssp_create_fact(tenant_id: UUID, payload: FactCreateRequest, request: Request) -> dict:
    """Create an analyst-asserted fact (HIL / manual). Trust is stamped analyst_asserted."""
    identity = current_identity(request)
    try:
        fact = AUTHORIZATION_FACT_ADAPTER.validate_python(payload.fact)
    except ValidationError as exc:
        raise HTTPException(422, exc.errors()[0].get("msg", "invalid fact")) from exc
    fact.source_type = AuthorizationSourceType.ANALYST_ASSERTED
    fact.trust = TRUST_TIER[fact.source_type]
    fact.tenant = str(tenant_id)
    fact.created_by = str(identity.user_id)
    db = _db(request)
    async with tenant_context(db, tenant_id):
        await store_fact(db, tenant_id=tenant_id, fact=fact)
    logger.info("authorization_fact_created", tenant_id=str(tenant_id), fact_id=fact.id)
    return {"stored": fact.id}


@mssp_router.post(
    "/{tenant_id}/authorization/facts/{fact_id}/revoke",
    dependencies=[Depends(require_permission(Permission.MANAGE_AUTHORIZATION_FACTS, audience="mssp"))],
)
async def mssp_revoke_fact(
    tenant_id: UUID, fact_id: str, payload: RevokeRequest, request: Request
) -> dict:
    identity = current_identity(request)
    db = _db(request)
    async with tenant_context(db, tenant_id):
        ok = await revoke_fact(
            db, tenant_id=tenant_id, fact_id=fact_id,
            revoked_by=identity.user_id, reason=payload.reason,
        )
    if not ok:
        raise HTTPException(404, "no live fact with that id")
    logger.info("authorization_fact_revoked", tenant_id=str(tenant_id), fact_id=fact_id)
    return {"revoked": fact_id}


class ReviewRequest(BaseModel):
    decision: str  # approve | reject
    reason: str | None = None


@mssp_router.post(
    "/{tenant_id}/authorization/facts/{fact_id}/review",
    dependencies=[Depends(require_permission(Permission.MANAGE_AUTHORIZATION_FACTS, audience="mssp"))],
)
async def mssp_review_fact(
    tenant_id: UUID, fact_id: str, payload: ReviewRequest, request: Request
) -> dict:
    """Analyst promotes (approve) or refuses (reject) a pending tenant-asserted fact. Approving
    makes it live to the reasoning engine; rejecting keeps it invisible."""
    if payload.decision not in ("approve", "reject"):
        raise HTTPException(400, "decision must be 'approve' or 'reject'")
    status = "approved" if payload.decision == "approve" else "rejected"
    identity = current_identity(request)
    db = _db(request)
    async with tenant_context(db, tenant_id):
        ok = await set_review_status(
            db, tenant_id=tenant_id, fact_id=fact_id, status=status,
            reviewed_by=identity.user_id,
        )
    if not ok:
        raise HTTPException(404, "no pending fact with that id")
    logger.info(
        "authorization_fact_reviewed", tenant_id=str(tenant_id), fact_id=fact_id, status=status
    )
    return {"reviewed": fact_id, "status": status}


# ---------------------------------------------------------------------------
# Tenant self-service authorization facts — a tenant asserts facts about ITS OWN org. They
# land 'pending' at the lowest trust and are invisible to triage until an MSSP analyst approves
# them (the review gate above). tenant_id + source_type + trust + review_status + id are all
# stamped server-side; nothing sensitive is trusted from the payload. The id is server-generated
# and namespaced so a tenant can never collide with (and overwrite) an existing fact.
# ---------------------------------------------------------------------------

tenant_authz_router = APIRouter(prefix="/api/tenant/authorization", tags=["tenant-authz-facts"])


def _caller_tenant(request: Request) -> UUID:
    identity = current_identity(request)
    tid = identity.tenant_id
    if not tid:
        raise HTTPException(400, "tenant_id missing from token")
    return tid if isinstance(tid, UUID) else UUID(str(tid))


@tenant_authz_router.get(
    "/facts",
    dependencies=[
        Depends(require_permission(Permission.TENANT_VIEW_AUTHORIZATION_FACTS, audience="tenant"))
    ],
)
async def tenant_list_own_facts(request: Request) -> dict:
    """The tenant's own facts, each with its review status (so they see what's pending)."""
    tid = _caller_tenant(request)
    db = _db(request)
    async with tenant_context(db, tid):
        rows = await list_facts_with_status(db, tenant_id=tid)
    return {"facts": [{**r["body"], "review_status": r["review_status"]} for r in rows]}


@tenant_authz_router.post(
    "/facts",
    dependencies=[
        Depends(require_permission(Permission.TENANT_ASSERT_AUTHORIZATION_FACTS, audience="tenant"))
    ],
)
async def tenant_assert_fact(payload: FactCreateRequest, request: Request) -> dict:
    """A tenant asserts a fact about its own environment. It lands 'pending' (invisible to
    triage) until an MSSP analyst approves it. All trust-bearing fields are stamped here."""
    tid = _caller_tenant(request)
    identity = current_identity(request)
    try:
        fact = AUTHORIZATION_FACT_ADAPTER.validate_python(payload.fact)
    except ValidationError as exc:
        raise HTTPException(422, exc.errors()[0].get("msg", "invalid fact")) from exc
    # Server-stamp everything — never trust the payload for these. The id is server-generated
    # and namespaced so a tenant assertion can never collide with / overwrite an existing fact.
    fact.id = f"tenant:{tid}:{uuid4()}"
    fact.source_type = AuthorizationSourceType.TENANT_ASSERTED
    fact.trust = TRUST_TIER[fact.source_type]
    fact.tenant = str(tid)
    fact.created_by = str(identity.user_id)
    db = _db(request)
    async with tenant_context(db, tid):
        await store_fact(db, tenant_id=tid, fact=fact, review_status="pending")
    logger.info("authorization_fact_tenant_asserted", tenant_id=str(tid), fact_id=fact.id)
    return {"stored": fact.id, "review_status": "pending"}
