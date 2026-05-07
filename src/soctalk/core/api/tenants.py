"""MSSP-side tenant lifecycle endpoints.

Mounted under ``/api/mssp/tenants/*`` by the top-level FastAPI app.
Every handler is guarded by :func:`require_role` on the 3 MSSP roles
(``platform_admin``, ``mssp_admin``, ``analyst``).
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from soctalk.core.provisioning import TenantController
from soctalk.core.tenancy.context import tenant_context
from soctalk.core.tenancy.decorators import require_role
from soctalk.core.tenancy.models import (
    BrandingConfig,
    IntegrationConfig,
    Organization,
    ProvisioningJob,
    Role,
    Tenant,
    TenantLifecycleEvent,
    TenantState,
)

router = APIRouter(prefix="/api/mssp/tenants", tags=["mssp-tenants"])


# ----- Schemas ---------------------------------------------------------------


class TenantCreate(BaseModel):
    slug: str = Field(..., pattern=r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?$", max_length=63)
    display_name: str = Field(..., min_length=1, max_length=255)
    # LLM
    llm_base_url: str = Field(default="https://api.openai.com/v1")
    llm_model: str = Field(default="gpt-4o")
    # Integration URLs (optional: chart renders defaults for ns-internal svcs)
    wazuh_url: str | None = None
    thehive_url: str | None = None
    cortex_url: str | None = None
    # Branding
    branding_app_name: str | None = None
    branding_logo_url: str | None = None
    branding_primary_color: str | None = None
    branding_secondary_color: str | None = None


class TenantRead(BaseModel):
    id: UUID
    slug: str
    display_name: str
    state: str
    profile: str | None = None
    created_at: str
    state_changed_at: str
    runtime: dict | None = None


class TenantOnboard(BaseModel):
    """Wizard payload — one POST, three logical steps' worth of data."""

    # Step 1 — identity
    slug: str = Field(..., pattern=r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?$", max_length=63)
    display_name: str = Field(..., min_length=1, max_length=255)
    # Step 2 — deployment profile
    profile: str = Field(..., pattern=r"^(poc|persistent)$")
    # Step 3 — branding + contact (all optional, defaults handled server-side)
    branding_app_name: str | None = Field(default=None, max_length=255)
    branding_logo_url: str | None = Field(default=None, max_length=500)
    branding_primary_color: str | None = Field(default=None, max_length=16)
    branding_secondary_color: str | None = Field(default=None, max_length=16)
    contact_email: str | None = Field(default=None, max_length=320)
    # LLM endpoint (optional; tenant can set API key later via detail page)
    llm_base_url: str = Field(default="https://api.openai.com/v1")
    llm_model: str = Field(default="gpt-4o")


class ProvisioningJobRead(BaseModel):
    id: UUID
    tenant_id: UUID
    kind: str
    status: str
    attempts: int
    max_attempts: int
    last_error: str | None
    next_attempt_at: str


class LifecycleEventRead(BaseModel):
    id: UUID
    timestamp: str
    event_type: str
    from_state: str | None
    to_state: str | None
    actor_id: str | None
    details: dict


# ----- Helpers ---------------------------------------------------------------


async def _get_organization(session: AsyncSession) -> Organization:
    result = await session.execute(select(Organization).limit(1))
    org = result.scalar_one_or_none()
    if org is None:
        raise HTTPException(500, "install not bootstrapped (no Organization row)")
    return org


def _db(request: Request) -> AsyncSession:
    session = getattr(request.state, "db", None)
    if session is None:
        raise HTTPException(500, "db session not attached to request")
    return session


# ----- Endpoints --------------------------------------------------------------


@router.post(
    "/onboard",
    response_model=TenantRead,
    status_code=202,
    dependencies=[
        Depends(require_role(Role.PLATFORM_ADMIN, Role.MSSP_ADMIN))
    ],
)
async def onboard_tenant(
    payload: TenantOnboard,
    request: Request,
) -> TenantRead:
    """Async tenant onboarding: writes initial rows, enqueues a provisioning
    job, and returns immediately with state=``provisioning``.

    The worker picks up the job, runs the stepwise reconcile on
    :class:`TenantController`, and flips the tenant to ``active`` when
    the namespace + secrets + Helm releases + workloads are all ready.
    """
    session = _db(request)
    org = await _get_organization(session)

    existing = await session.execute(
        select(Tenant).where(Tenant.slug == payload.slug)
    )
    if existing.scalar_one_or_none():
        raise HTTPException(409, f"tenant slug '{payload.slug}' already exists")

    tenant = Tenant(
        slug=payload.slug,
        display_name=payload.display_name,
        state=TenantState.PENDING.value,
        profile=payload.profile,
        organization_id=org.id,
        config={"contact_email": payload.contact_email} if payload.contact_email else {},
    )
    session.add(tenant)
    await session.flush()

    async with tenant_context(session, tenant.id):
        session.add_all([
            IntegrationConfig(
                tenant_id=tenant.id,
                llm_base_url=payload.llm_base_url,
                llm_model=payload.llm_model,
            ),
            BrandingConfig(
                tenant_id=tenant.id,
                app_name=payload.branding_app_name or payload.display_name,
                logo_url=payload.branding_logo_url,
                primary_color=payload.branding_primary_color,
                secondary_color=payload.branding_secondary_color,
            ),
        ])
        # Enqueue the provisioning job. The partial unique index on
        # provisioning_jobs makes re-enqueue idempotent if this POST
        # is retried client-side.
        session.add(
            ProvisioningJob(
                tenant_id=tenant.id,
                kind="tenant.provision",
                status="pending",
            )
        )
        # Lifecycle event so the wizard landing immediately sees something.
        session.add(
            TenantLifecycleEvent(
                tenant_id=tenant.id,
                event_type="onboard_submitted",
                from_state=None,
                to_state=TenantState.PENDING.value,
                actor_id=str(request.state.user_identity.get("user_id")),
                details={"profile": payload.profile},
            )
        )
        await session.commit()

    return _to_read(tenant)


@router.post(
    "/{tenant_id}:retry",
    response_model=ProvisioningJobRead,
    dependencies=[
        Depends(require_role(Role.PLATFORM_ADMIN, Role.MSSP_ADMIN))
    ],
)
async def retry_provisioning(tenant_id: UUID, request: Request) -> ProvisioningJobRead:
    """Re-enqueue a failed provisioning job for a degraded tenant."""
    session = _db(request)
    tenant = (
        await session.execute(select(Tenant).where(Tenant.id == tenant_id))
    ).scalar_one_or_none()
    if tenant is None:
        raise HTTPException(404, "tenant not found")
    if tenant.state != TenantState.DEGRADED.value:
        raise HTTPException(
            409, f"retry is only valid from state=degraded (current: {tenant.state})"
        )

    # Look for a previous failed job we can reopen, else insert a fresh one.
    existing_job = (
        await session.execute(
            select(ProvisioningJob)
            .where(ProvisioningJob.tenant_id == tenant_id)
            .where(ProvisioningJob.kind == "tenant.provision")
            .where(ProvisioningJob.status == "failed")
            .order_by(ProvisioningJob.created_at.desc())
            .limit(1)
        )
    ).scalar_one_or_none()

    async with tenant_context(session, tenant_id):
        if existing_job is not None:
            existing_job.status = "pending"
            existing_job.attempts = 0
            existing_job.last_error = None
            existing_job.claimed_at = None
            existing_job.claimed_by = None
            existing_job.next_attempt_at = datetime.utcnow()
            existing_job.updated_at = datetime.utcnow()
            job = existing_job
        else:
            job = ProvisioningJob(
                tenant_id=tenant_id,
                kind="tenant.provision",
                status="pending",
            )
            session.add(job)
        session.add(
            TenantLifecycleEvent(
                tenant_id=tenant_id,
                event_type="retry_requested",
                from_state=tenant.state,
                to_state=tenant.state,
                actor_id=str(request.state.user_identity.get("user_id")),
                details={},
            )
        )
        await session.commit()

    return ProvisioningJobRead(
        id=job.id,
        tenant_id=job.tenant_id,
        kind=job.kind,
        status=job.status,
        attempts=job.attempts,
        max_attempts=job.max_attempts,
        last_error=job.last_error,
        next_attempt_at=job.next_attempt_at.isoformat(),
    )


@router.post(
    "",
    response_model=TenantRead,
    status_code=201,
    dependencies=[
        Depends(require_role(Role.PLATFORM_ADMIN, Role.MSSP_ADMIN))
    ],
)
async def create_tenant(
    payload: TenantCreate,
    request: Request,
) -> TenantRead:
    session = _db(request)
    org = await _get_organization(session)

    # Enforce slug uniqueness (RLS not relevant: tenants table is install-scoped).
    existing = await session.execute(
        select(Tenant).where(Tenant.slug == payload.slug)
    )
    if existing.scalar_one_or_none():
        raise HTTPException(409, f"tenant slug '{payload.slug}' already exists")

    tenant = Tenant(
        slug=payload.slug,
        display_name=payload.display_name,
        state=TenantState.PENDING.value,
        organization_id=org.id,
        config={},
    )
    session.add(tenant)
    await session.flush()

    async with tenant_context(session, tenant.id):
        session.add_all([
            IntegrationConfig(
                tenant_id=tenant.id,
                llm_base_url=payload.llm_base_url,
                llm_model=payload.llm_model,
                wazuh_url=payload.wazuh_url,
                thehive_url=payload.thehive_url,
                cortex_url=payload.cortex_url,
            ),
            BrandingConfig(
                tenant_id=tenant.id,
                app_name=payload.branding_app_name or payload.display_name,
                logo_url=payload.branding_logo_url,
                primary_color=payload.branding_primary_color,
                secondary_color=payload.branding_secondary_color,
            ),
        ])
        await session.flush()

    # Identity-only: no inline helm, no worker enqueue. Programmatic
    # callers that want the data plane to come up should use the
    # ``/onboard`` wizard path (which enqueues a ProvisioningJob) or
    # issue a ``:retry`` once they're ready. Keeping this endpoint
    # inline would fork lifecycle behavior with /onboard.
    await session.commit()
    return _to_read(tenant)


@router.get(
    "",
    response_model=list[TenantRead],
    dependencies=[
        Depends(require_role(Role.PLATFORM_ADMIN, Role.MSSP_ADMIN, Role.ANALYST))
    ],
)
async def list_tenants(request: Request) -> list[TenantRead]:
    session = _db(request)
    result = await session.execute(select(Tenant).where(Tenant.deleted_at.is_(None)))
    tenants = result.scalars().all()
    return [
        TenantRead(
            id=t.id,
            slug=t.slug,
            display_name=t.display_name,
            state=t.state,
            profile=t.profile,
            created_at=t.created_at.isoformat(),
            state_changed_at=t.state_changed_at.isoformat(),
            runtime=t.runtime,
        )
        for t in tenants
    ]


@router.get(
    "/{tenant_id}",
    response_model=TenantRead,
    dependencies=[
        Depends(require_role(Role.PLATFORM_ADMIN, Role.MSSP_ADMIN, Role.ANALYST))
    ],
)
async def get_tenant(tenant_id: UUID, request: Request) -> TenantRead:
    session = _db(request)
    tenant = (await session.execute(select(Tenant).where(Tenant.id == tenant_id))).scalar_one_or_none()
    if tenant is None:
        raise HTTPException(404, "tenant not found")
    return TenantRead(
        id=tenant.id,
        slug=tenant.slug,
        display_name=tenant.display_name,
        state=tenant.state,
        created_at=tenant.created_at.isoformat(),
        state_changed_at=tenant.state_changed_at.isoformat(),
        runtime=tenant.runtime,
    )


@router.post(
    "/{tenant_id}:suspend",
    response_model=TenantRead,
    dependencies=[
        Depends(require_role(Role.PLATFORM_ADMIN, Role.MSSP_ADMIN))
    ],
)
async def suspend_tenant(tenant_id: UUID, request: Request) -> TenantRead:
    session = _db(request)
    controller = TenantController(session)
    async with tenant_context(session, tenant_id):
        tenant = await controller.suspend(
            tenant_id,
            actor_id=str(request.state.user_identity.get("user_id")),
        )
    return _to_read(tenant)


@router.post(
    "/{tenant_id}:resume",
    response_model=TenantRead,
    dependencies=[
        Depends(require_role(Role.PLATFORM_ADMIN, Role.MSSP_ADMIN))
    ],
)
async def resume_tenant(tenant_id: UUID, request: Request) -> TenantRead:
    session = _db(request)
    controller = TenantController(session)
    async with tenant_context(session, tenant_id):
        tenant = await controller.resume(
            tenant_id,
            actor_id=str(request.state.user_identity.get("user_id")),
        )
    return _to_read(tenant)


@router.post(
    "/{tenant_id}:decommission",
    response_model=TenantRead,
    status_code=202,
    dependencies=[
        Depends(require_role(Role.PLATFORM_ADMIN))
    ],
)
async def decommission_tenant(
    tenant_id: UUID, request: Request, force: bool = False
) -> TenantRead:
    """Enqueue tear-down of a tenant's data plane.

    Flips the tenant to ``decommissioning`` + records a
    ``decommission_started`` lifecycle event synchronously, then
    enqueues a ``tenant.decommission`` job for the provisioning worker
    to drive. Returns 202 immediately so the wizard/UI can poll.
    """
    session = _db(request)
    tenant = (
        await session.execute(select(Tenant).where(Tenant.id == tenant_id))
    ).scalar_one_or_none()
    if tenant is None:
        raise HTTPException(404, "tenant not found")

    # Idempotency: don't double-enqueue if one is already active.
    already_queued = (
        await session.execute(
            select(ProvisioningJob)
            .where(ProvisioningJob.tenant_id == tenant_id)
            .where(ProvisioningJob.kind == "tenant.decommission")
            .where(ProvisioningJob.status.in_(("pending", "in_flight")))
            .limit(1)
        )
    ).scalar_one_or_none()

    async with tenant_context(session, tenant_id):
        if tenant.state not in (
            TenantState.DECOMMISSIONING.value,
            TenantState.ARCHIVED.value,
            TenantState.PURGED.value,
        ):
            from_state = tenant.state
            tenant.state = TenantState.DECOMMISSIONING.value
            session.add(
                TenantLifecycleEvent(
                    tenant_id=tenant.id,
                    event_type="decommission_started",
                    from_state=from_state,
                    to_state=TenantState.DECOMMISSIONING.value,
                    actor_id=str(request.state.user_identity.get("user_id")),
                    details={"force": force},
                )
            )

        if already_queued is None:
            session.add(
                ProvisioningJob(
                    tenant_id=tenant_id,
                    kind="tenant.decommission",
                    status="pending",
                )
            )

        await session.commit()

    return _to_read(tenant)


@router.get(
    "/{tenant_id}/events",
    response_model=list[LifecycleEventRead],
    dependencies=[
        Depends(require_role(Role.PLATFORM_ADMIN, Role.MSSP_ADMIN, Role.ANALYST))
    ],
)
async def list_events(
    tenant_id: UUID, request: Request, limit: int = 100
) -> list[LifecycleEventRead]:
    session = _db(request)
    async with tenant_context(session, tenant_id):
        result = await session.execute(
            select(TenantLifecycleEvent)
            .where(TenantLifecycleEvent.tenant_id == tenant_id)
            .order_by(TenantLifecycleEvent.timestamp.desc())
            .limit(limit)
        )
    evts = result.scalars().all()
    return [
        LifecycleEventRead(
            id=e.id,
            timestamp=e.timestamp.isoformat(),
            event_type=e.event_type,
            from_state=e.from_state,
            to_state=e.to_state,
            actor_id=e.actor_id,
            details=e.details,
        )
        for e in evts
    ]


def _to_read(t: Tenant) -> TenantRead:
    return TenantRead(
        id=t.id,
        slug=t.slug,
        display_name=t.display_name,
        state=t.state,
        profile=t.profile,
        created_at=t.created_at.isoformat(),
        state_changed_at=t.state_changed_at.isoformat(),
        runtime=t.runtime,
    )


# ---------------------------------------------------------------------------
# Agent issuance (L1→L2): mint a bootstrap token + return install hint.
# ---------------------------------------------------------------------------


class AgentIssuance(BaseModel):
    """Credentials + install hint the MSSP gives the tenant admin out-of-band.

    The tenant admin runs one Helm install with this payload; the agent
    self-registers against L1 (``control_plane_url``), picks up an
    ``install_helm_release`` job, and deploys ``soctalk-tenant`` into
    L2's cluster.

    Note on scope: ``agent_chart_ref`` / ``agent_chart_version`` are the
    coordinates for the ``soctalk-cloud-agent`` chart — what the tenant
    admin installs in L2. The tenant SOC stack (``soctalk-tenant``) is
    dispatched by the agent itself once registered and is not exposed
    here; it lives on the ``TenantInstallation`` row for operator
    observability via ``GET /api/mssp/tenants/{id}``.
    """

    installation_id: str
    tenant_id: str
    # Plaintext bootstrap token — shown ONCE. No recovery path.
    bootstrap_token: str
    bootstrap_expires_at: str
    # Where the L2 agent will POST /api/agent/register.
    control_plane_url: str
    # The agent chart (soctalk-cloud-agent), NOT the tenant SOC stack.
    agent_chart_ref: str
    agent_chart_version: str
    # Copy-paste ready command the MSSP admin can hand to the tenant
    # admin. One-liner; everything secret is already in the values.
    helm_install_hint: str


class RetryInstallResponse(BaseModel):
    installation_id: str
    state: str
    reclaimed: int
    reset_to_pending: int


@router.post(
    "/{tenant_id}:retry-install",
    response_model=RetryInstallResponse,
    dependencies=[
        Depends(require_role(Role.PLATFORM_ADMIN, Role.MSSP_ADMIN))
    ],
)
async def retry_install(
    tenant_id: UUID, request: Request,
) -> RetryInstallResponse:
    """Operator-facing recovery for a wedged L2 install.

    Use when the tenant agent crashed mid-job and the installation is
    stuck in ``provisioning`` with an in_flight AgentJob. This:
      1. Reclaims any in_flight AgentJobs for the tenant's installation
         (regardless of age — operator-triggered bypasses the timeout).
      2. Resets any ``failed`` terminal jobs to ``pending`` so the agent
         can retry them on its next claim.
      3. Returns the installation's current state for the caller to poll.

    Does not re-enqueue preflight; if the failure was earlier in the
    pipeline a re-register from the agent side will reset the state.
    """
    from sqlalchemy import update as _update

    from soctalk.core.agents.models import (
        AgentJob,
        TenantInstallation,
        TenantInstallationEvent,
    )

    session = _db(request)
    installation = (
        await session.execute(
            select(TenantInstallation).where(
                TenantInstallation.tenant_id == tenant_id
            )
        )
    ).scalar_one_or_none()
    if installation is None:
        raise HTTPException(404, "tenant has no agent installation")

    reclaimed = (
        await session.execute(
            _update(AgentJob)
            .where(AgentJob.installation_id == installation.id)
            .where(AgentJob.status == "in_flight")
            .values(status="pending", claimed_at=None)
            .returning(AgentJob.id)
        )
    ).scalars().all()

    retried = (
        await session.execute(
            _update(AgentJob)
            .where(AgentJob.installation_id == installation.id)
            .where(AgentJob.status == "failed")
            .values(
                status="pending",
                claimed_at=None,
                completed_at=None,
                outcome=None,
                error_code=None,
                summary=None,
            )
            .returning(AgentJob.id)
        )
    ).scalars().all()

    actor = request.state.user_identity.get("user_id") \
        if getattr(request.state, "user_identity", None) else "operator"

    # When un-wedging a degraded install, pick the state that matches
    # the kind of job being retried. An upgrade_helm_release that
    # previously failed must resume under ``upgrading`` — the inline
    # controller's kind→state table (install→provisioning,
    # upgrade→upgrading) rejects the success otherwise and the
    # installation would hang in degraded forever.
    resume_state = "provisioning"
    if installation.state == "degraded" and retried:
        has_upgrade_failure = (
            await session.execute(
                select(AgentJob)
                .where(AgentJob.installation_id == installation.id)
                .where(AgentJob.kind == "upgrade_helm_release")
                .where(AgentJob.id.in_(retried))
            )
        ).first()
        if has_upgrade_failure is not None or installation.desired_action == "upgrade":
            resume_state = "upgrading"

    session.add(
        TenantInstallationEvent(
            installation_id=installation.id,
            event_type="retry_requested",
            from_state=installation.state,
            to_state=(
                resume_state if installation.state == "degraded" and retried
                else installation.state
            ),
            actor_id=f"user:{actor}",
            details={
                "reclaimed_in_flight": len(reclaimed),
                "retried_failed": len(retried),
                "resume_state": resume_state if retried else None,
            },
        )
    )
    if installation.state == "degraded" and retried:
        installation.state = resume_state
        installation.state_changed_at = datetime.utcnow()
    await session.commit()

    return RetryInstallResponse(
        installation_id=str(installation.id),
        state=installation.state,
        reclaimed=len(reclaimed),
        reset_to_pending=len(retried),
    )


@router.post(
    "/{tenant_id}:issue-agent",
    response_model=AgentIssuance,
    status_code=201,
    dependencies=[
        Depends(require_role(Role.PLATFORM_ADMIN, Role.MSSP_ADMIN))
    ],
)
async def issue_agent(
    tenant_id: UUID, request: Request,
) -> AgentIssuance:
    """Create-or-reuse the TenantInstallation for this tenant and mint a
    fresh bootstrap token.

    Re-calling revokes any un-consumed prior bootstrap token for the
    installation (a lost token never remains valid). Runtime tokens are
    untouched — this endpoint only addresses the bootstrap leg.
    """
    from datetime import timedelta

    from soctalk.core.agents.models import (
        TenantInstallation,
        TenantInstallationBootstrapToken,
    )
    from soctalk.core.agents.tokens import hash_token, mint_token
    from sqlalchemy import update as _update

    session = _db(request)
    tenant = (
        await session.execute(select(Tenant).where(Tenant.id == tenant_id))
    ).scalar_one_or_none()
    if tenant is None:
        raise HTTPException(404, "tenant not found")

    # Two chart coordinates in play:
    #
    # * ``chart_ref`` / ``chart_version`` — the tenant SOC stack
    #   (soctalk-tenant) the *agent* applies on L2 once registered.
    #   Stored on TenantInstallation.desired_* so re-issue + upgrade
    #   flows can move it atomically.
    # * ``agent_chart_ref`` / ``agent_chart_version`` — the
    #   soctalk-cloud-agent chart the *tenant admin* Helm-installs.
    #   Returned in AgentIssuance; never persisted.
    import os
    chart_ref = os.getenv(
        "SOCTALK_TENANT_CHART_REF",
        "oci://ghcr.io/gbrigandi/charts/soctalk-tenant",
    )
    chart_version = os.getenv("SOCTALK_TENANT_CHART_VERSION", "0.1.0")
    agent_chart_ref = os.getenv(
        "SOCTALK_AGENT_CHART_REF",
        "oci://ghcr.io/gbrigandi/charts/soctalk-cloud-agent",
    )
    agent_chart_version = os.getenv(
        "SOCTALK_AGENT_CHART_VERSION", "0.1.0"
    )
    control_plane_url = os.getenv(
        "SOCTALK_L1_PUBLIC_URL", "http://host.docker.internal:8000"
    )

    # Create-or-fetch the Installation row. Unique index on tenant_id
    # ensures at-most-one row per tenant.
    installation = (
        await session.execute(
            select(TenantInstallation)
            .where(TenantInstallation.tenant_id == tenant_id)
        )
    ).scalar_one_or_none()
    if installation is None:
        installation = TenantInstallation(
            tenant_id=tenant_id,
            desired_chart_ref=chart_ref,
            desired_chart_version=chart_version,
            desired_action="install",
            state="pending",
        )
        session.add(installation)
        await session.flush()
    else:
        # Re-issue: handle a chart bump depending on current state.
        #
        # The install_helm_release / upgrade_helm_release AgentJob spec
        # is frozen when enqueued (``agent_jobs.spec`` is a stored JSON
        # snapshot). So when the job is already in flight, updating
        # ``installation.desired_chart_version`` would desync: the
        # agent still applies the snapshotted version, but L1's later
        # ``wait_for_ready`` success copies the *current* desired into
        # ``reported_chart_version`` and we settle as if the new chart
        # was installed. Gate the update by state:
        #
        #   pending / agent_connected  → metadata update only; the
        #       install spec will be built later from the latest
        #       desired_*, so there is nothing to desync.
        #   active                     → dispatch the upgrade path.
        #   degraded                   → dispatch the upgrade path;
        #       the failed job stays as audit, a new job re-enqueues.
        #   provisioning / upgrading   → REJECT 409. Operator must
        #       wait for the current job to settle (or :retry-install
        #       then re-issue) before the chart can move.
        chart_moved = (
            installation.desired_chart_ref != chart_ref
            or installation.desired_chart_version != chart_version
        )
        if chart_moved:
            if installation.state in {"provisioning", "upgrading"}:
                raise HTTPException(
                    status_code=409,
                    detail={
                        "error_code": "AGENT_JOB_IN_FLIGHT",
                        "message": (
                            "chart update rejected while install/upgrade "
                            "is in flight; wait for current job to settle "
                            "or call :retry-install first"
                        ),
                        "state": installation.state,
                        "current_desired_chart_version": (
                            installation.desired_chart_version
                        ),
                        "requested_chart_version": chart_version,
                    },
                )
            prior_state = installation.state
            installation.desired_chart_ref = chart_ref
            installation.desired_chart_version = chart_version
            installation.desired_action = "upgrade"

            # Active or degraded install + new desired chart → dispatch
            # the upgrade_helm_release path. Without this,
            # desired_action="upgrade" is metadata-only: register()
            # won't re-enqueue preflight on a connected install, and
            # the inline controller only walks the first-install
            # pipeline.
            if installation.state in {"active", "degraded"}:
                from soctalk.core.agents.api import (
                    _build_install_helm_release_spec,
                    _enqueue_agent_job,
                )
                from soctalk.core.agents.models import TenantInstallationEvent

                installation.state = "upgrading"
                installation.state_changed_at = datetime.utcnow()
                session.add(
                    TenantInstallationEvent(
                        installation_id=installation.id,
                        event_type="upgrade_started",
                        from_state=prior_state,
                        to_state="upgrading",
                        actor_id="controller",
                        details={
                            "chart_ref": chart_ref,
                            "chart_version": chart_version,
                        },
                    )
                )
                await session.flush()

                # Re-use the install spec builder — same chart contract,
                # same values — and emit as an upgrade_helm_release job.
                spec = await _build_install_helm_release_spec(
                    session, installation
                )
                await _enqueue_agent_job(
                    session,
                    installation_id=installation.id,
                    kind="upgrade_helm_release",
                    idempotency_key=(
                        f"upgrade:{installation.id}:"
                        f"{chart_ref}:{chart_version}"
                    ),
                    spec=spec,
                )
            else:
                # pending / agent_connected: the install spec hasn't
                # been built yet. Metadata-only update; the builder
                # reads the latest desired_* when preflight completes.
                await session.flush()

    # Revoke any outstanding un-consumed bootstrap tokens.
    now = datetime.utcnow()
    await session.execute(
        _update(TenantInstallationBootstrapToken)
        .where(
            TenantInstallationBootstrapToken.installation_id == installation.id
        )
        .where(TenantInstallationBootstrapToken.consumed_at.is_(None))
        .where(TenantInstallationBootstrapToken.revoked_at.is_(None))
        .values(revoked_at=now)
    )

    # Mint the new one. 24h TTL, single-use (enforced on consume).
    plaintext = mint_token()
    expires_at = now + timedelta(hours=24)
    session.add(
        TenantInstallationBootstrapToken(
            installation_id=installation.id,
            token_hash=hash_token(plaintext),
            expires_at=expires_at,
        )
    )
    await session.commit()

    # One-line install hint the MSSP admin copy-pastes to the tenant
    # admin. Values flow through --set-string so shell escaping stays
    # sane for the bootstrap token.
    install_release = f"soctalk-agent-{tenant.slug}"
    helm_install_hint = (
        f"helm install {install_release} {agent_chart_ref} "
        f"--version {agent_chart_version} "
        f"--namespace soctalk-agent --create-namespace "
        f"--set-string controlPlaneUrl={control_plane_url} "
        f"--set-string bootstrapToken={plaintext}"
    )

    return AgentIssuance(
        installation_id=str(installation.id),
        tenant_id=str(tenant_id),
        bootstrap_token=plaintext,
        bootstrap_expires_at=expires_at.isoformat(),
        control_plane_url=control_plane_url,
        agent_chart_ref=agent_chart_ref,
        agent_chart_version=agent_chart_version,
        helm_install_hint=helm_install_hint,
    )
