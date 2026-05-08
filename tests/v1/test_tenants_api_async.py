"""Assertions that the legacy POST /api/mssp/tenants no longer
provisions inline, and that ``:decommission`` is async.

Both contracts are the review-closing invariants: a caller that hits
either endpoint must not trigger helm from inside the request handler.
The worker owns every data-plane mutation now.
"""

from __future__ import annotations

import os
from collections.abc import AsyncIterator
from uuid import uuid4

import pytest
import pytest_asyncio
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from soctalk.core.tenancy.models import (
    Organization,
    ProvisioningJob,
    Tenant,
    TenantState,
)

SKIP_INTEGRATION = os.getenv("SKIP_INTEGRATION", "0") == "1"

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        SKIP_INTEGRATION,
        reason="SKIP_INTEGRATION set; tenants-API async tests need Postgres",
    ),
]


def _mssp_url() -> str:
    return os.getenv(
        "DATABASE_URL_MSSP",
        "postgresql+asyncpg://soctalk_mssp:soctalk_mssp@localhost:5444/soctalk",
    )


def _admin_url() -> str:
    return os.getenv(
        "DATABASE_URL_ADMIN",
        "postgresql+asyncpg://soctalk_admin:soctalk_admin@localhost:5444/soctalk",
    )


@pytest_asyncio.fixture
async def admin_session() -> AsyncIterator[AsyncSession]:
    engine = create_async_engine(_admin_url(), echo=False, pool_pre_ping=True)
    sm = async_sessionmaker(engine, expire_on_commit=False)
    async with sm() as s:
        yield s
    await engine.dispose()


@pytest_asyncio.fixture
async def mssp_session() -> AsyncIterator[AsyncSession]:
    engine = create_async_engine(_mssp_url(), echo=False, pool_pre_ping=True)
    sm = async_sessionmaker(engine, expire_on_commit=False)
    async with sm() as s:
        yield s
    await engine.dispose()


@pytest_asyncio.fixture
async def seeded_org(
    mssp_session: AsyncSession, admin_session: AsyncSession
) -> Organization:
    await admin_session.execute(
        text(
            "TRUNCATE tenant_lifecycle_events, integration_configs, "
            "branding_configs, tenant_secrets, provisioning_jobs, "
            "tenants, organizations CASCADE"
        )
    )
    await admin_session.commit()
    org = Organization(
        mssp_id=uuid4(), mssp_name="Legacy-API Test", slug="legacy-api-test",
        install_id=uuid4(), install_label="test",
    )
    mssp_session.add(org)
    await mssp_session.commit()
    return org


# ---------------------------------------------------------------------------
# Call the handler function directly so we don't need the full FastAPI
# app stack (auth middleware, DB middleware, etc.). The guarantees we
# want to prove are about what the handler writes to the DB and what it
# does NOT call — not HTTP plumbing.
# ---------------------------------------------------------------------------


async def test_legacy_create_is_identity_only_no_provisioning(
    mssp_session: AsyncSession, seeded_org: Organization, monkeypatch
):
    """Review gap #4: POST /api/mssp/tenants must not provision inline."""

    from soctalk.core.api.tenants import TenantCreate, create_tenant
    from soctalk.core.provisioning import controller as ctrl_mod

    # Poison the controller so any inline provisioning attempt is obvious.
    sentinel = {"called": False}

    async def forbidden(*_a, **_kw):
        sentinel["called"] = True
        raise AssertionError(
            "create_tenant must not call TenantController.provision"
        )

    monkeypatch.setattr(ctrl_mod.TenantController, "provision", forbidden)

    class FakeRequest:
        class State:
            user_identity = {"user_id": "test-user"}
            db = mssp_session
        state = State()

    payload = TenantCreate(
        slug=f"id{uuid4().hex[:8]}",
        display_name="Identity Only",
    )

    result = await create_tenant(payload, FakeRequest())
    assert sentinel["called"] is False
    assert result.state == TenantState.PENDING.value
    assert result.profile in (None, "legacy", "poc")

    # No provisioning job should have been enqueued on this path.
    jobs = (
        await mssp_session.execute(
            select(ProvisioningJob).where(ProvisioningJob.tenant_id == result.id)
        )
    ).scalars().all()
    assert jobs == []


async def test_decommission_enqueues_job_and_returns_immediately(
    mssp_session: AsyncSession, seeded_org: Organization, monkeypatch
):
    """Review gap #4: :decommission must not call helm from the handler."""

    from soctalk.core.api.tenants import decommission_tenant
    from soctalk.core.provisioning import controller as ctrl_mod

    sentinel = {"called": False}

    async def forbidden(*_a, **_kw):
        sentinel["called"] = True
        raise AssertionError(
            "decommission_tenant must not call TenantController.decommission"
        )

    monkeypatch.setattr(ctrl_mod.TenantController, "decommission", forbidden)

    tenant = Tenant(
        slug=f"dc{uuid4().hex[:8]}",
        display_name="Decomm target",
        state=TenantState.ACTIVE.value,
        profile="poc",
        organization_id=seeded_org.id,
    )
    mssp_session.add(tenant)
    await mssp_session.commit()
    await mssp_session.refresh(tenant)

    class FakeRequest:
        class State:
            user_identity = {"user_id": "test-user"}
            db = mssp_session
        state = State()

    result = await decommission_tenant(tenant.id, FakeRequest(), force=False)
    assert sentinel["called"] is False
    assert result.state == TenantState.DECOMMISSIONING.value

    jobs = (
        await mssp_session.execute(
            select(ProvisioningJob)
            .where(ProvisioningJob.tenant_id == tenant.id)
            .where(ProvisioningJob.kind == "tenant.decommission")
        )
    ).scalars().all()
    assert len(jobs) == 1
    assert jobs[0].status == "pending"


async def test_decommission_is_idempotent_under_double_call(
    mssp_session: AsyncSession, seeded_org: Organization, monkeypatch
):
    """Two :decommission calls on the same tenant enqueue at most one
    active job (partial unique index would otherwise throw)."""

    from soctalk.core.api.tenants import decommission_tenant
    from soctalk.core.provisioning import controller as ctrl_mod

    async def noop(*_a, **_kw):  # let the call through, but do nothing
        raise AssertionError("unreachable")

    monkeypatch.setattr(ctrl_mod.TenantController, "decommission", noop)

    tenant = Tenant(
        slug=f"dd{uuid4().hex[:8]}",
        display_name="Double Decomm",
        state=TenantState.ACTIVE.value,
        profile="poc",
        organization_id=seeded_org.id,
    )
    mssp_session.add(tenant)
    await mssp_session.commit()
    await mssp_session.refresh(tenant)

    class FakeRequest:
        class State:
            user_identity = {"user_id": "test-user"}
            db = mssp_session
        state = State()

    await decommission_tenant(tenant.id, FakeRequest(), force=False)
    await decommission_tenant(tenant.id, FakeRequest(), force=False)

    jobs = (
        await mssp_session.execute(
            select(ProvisioningJob)
            .where(ProvisioningJob.tenant_id == tenant.id)
            .where(ProvisioningJob.kind == "tenant.decommission")
        )
    ).scalars().all()
    assert len(jobs) == 1
