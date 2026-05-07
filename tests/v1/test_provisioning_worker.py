"""ProvisioningWorker semantics — queue claim/reclaim/lifecycle.

Uses the real Postgres harness (same as test_provisioning_controller.py)
so the claim path exercises ``SELECT ... FOR UPDATE SKIP LOCKED`` against
the real engine and the partial unique index on ``provisioning_jobs``.
"""

from __future__ import annotations

import asyncio
import os
from collections.abc import AsyncIterator
from datetime import datetime, timedelta
from uuid import uuid4

import pytest
import pytest_asyncio
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from soctalk.core.provisioning.worker import ProvisioningWorker
from soctalk.core.tenancy.models import (
    BrandingConfig,
    IntegrationConfig,
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
        reason="SKIP_INTEGRATION set; worker tests need Postgres",
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
async def mssp_sessionmaker() -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    engine = create_async_engine(_mssp_url(), echo=False, pool_pre_ping=True)
    sm = async_sessionmaker(engine, expire_on_commit=False)
    yield sm
    await engine.dispose()


@pytest_asyncio.fixture
async def seeded_tenant(
    mssp_sessionmaker, admin_session: AsyncSession
) -> Tenant:
    await admin_session.execute(
        text(
            "TRUNCATE tenant_lifecycle_events, integration_configs, "
            "branding_configs, tenant_secrets, provisioning_jobs, "
            "tenants, organizations CASCADE"
        )
    )
    await admin_session.commit()

    async with mssp_sessionmaker() as session:
        org = Organization(
            mssp_id=uuid4(), mssp_name="Worker Test",
            install_id=uuid4(), install_label="test",
        )
        session.add(org)
        await session.flush()
        tenant = Tenant(
            slug=f"wrk{uuid4().hex[:6]}",
            display_name="Worker Test",
            state=TenantState.PENDING.value,
            profile="poc",
            organization_id=org.id,
        )
        session.add(tenant)
        await session.flush()
        session.add_all([
            IntegrationConfig(tenant_id=tenant.id),
            BrandingConfig(tenant_id=tenant.id, app_name="W"),
        ])
        await session.commit()
        return tenant


# ---------------------------------------------------------------------------
# Stale-claim reclaim
# ---------------------------------------------------------------------------


async def test_reclaim_flips_stale_in_flight_back_to_pending(
    mssp_sessionmaker, seeded_tenant: Tenant
):
    """A worker crash leaves an ``in_flight`` row with a claimed_at older
    than ``stale_claim_seconds``. The next reclaim pass must flip it
    back to ``pending`` so a new worker can claim it.
    """
    async with mssp_sessionmaker() as s:
        # Fresh in_flight job claimed 2 hours ago by a ghost worker.
        job = ProvisioningJob(
            tenant_id=seeded_tenant.id,
            kind="tenant.provision",
            status="in_flight",
            claimed_at=datetime.utcnow() - timedelta(hours=2),
            claimed_by="dead-worker",
            attempts=1,
        )
        s.add(job)
        await s.commit()
        job_id = job.id

    worker = ProvisioningWorker(
        mssp_sessionmaker,
        stale_claim_seconds=60,
        reclaim_interval_seconds=0,
    )
    # Drive one reclaim pass.
    await worker._maybe_reclaim_stale()

    async with mssp_sessionmaker() as s:
        row = (
            await s.execute(
                select(ProvisioningJob).where(ProvisioningJob.id == job_id)
            )
        ).scalar_one()
    assert row.status == "pending"
    assert row.claimed_at is None
    assert row.claimed_by is None
    assert row.last_error == "reclaimed after stale claim"
    # Attempts is preserved — stale reclaim counts toward retry budget.
    assert row.attempts == 1


async def test_reclaim_leaves_recent_in_flight_alone(
    mssp_sessionmaker, seeded_tenant: Tenant
):
    """A job claimed seconds ago is still the active worker's — hands off."""
    async with mssp_sessionmaker() as s:
        job = ProvisioningJob(
            tenant_id=seeded_tenant.id,
            kind="tenant.provision",
            status="in_flight",
            claimed_at=datetime.utcnow() - timedelta(seconds=5),
            claimed_by="me",
            attempts=1,
        )
        s.add(job)
        await s.commit()
        job_id = job.id

    worker = ProvisioningWorker(
        mssp_sessionmaker,
        stale_claim_seconds=60,  # 60s threshold, row is 5s old
        reclaim_interval_seconds=0,
    )
    await worker._maybe_reclaim_stale()

    async with mssp_sessionmaker() as s:
        row = (
            await s.execute(
                select(ProvisioningJob).where(ProvisioningJob.id == job_id)
            )
        ).scalar_one()
    assert row.status == "in_flight"
    assert row.claimed_by == "me"


async def test_reclaim_interval_rate_limits_passes(
    mssp_sessionmaker, seeded_tenant: Tenant
):
    """Two back-to-back ``_maybe_reclaim_stale`` calls: second is a no-op."""
    worker = ProvisioningWorker(
        mssp_sessionmaker,
        stale_claim_seconds=60,
        reclaim_interval_seconds=300,  # 5 min — tight enough we can observe
    )
    await worker._maybe_reclaim_stale()
    first_tick = worker._last_reclaim_at
    await worker._maybe_reclaim_stale()
    # Second call short-circuits — timestamp unchanged.
    assert worker._last_reclaim_at == first_tick


# ---------------------------------------------------------------------------
# Claim + run dispatch
# ---------------------------------------------------------------------------


async def test_claim_skips_rows_whose_next_attempt_is_in_the_future(
    mssp_sessionmaker, seeded_tenant: Tenant
):
    """Failed jobs sit in ``pending`` with a future next_attempt_at after
    backoff; the claim query must respect it.
    """
    async with mssp_sessionmaker() as s:
        future = datetime.utcnow() + timedelta(minutes=10)
        past_job = ProvisioningJob(
            tenant_id=seeded_tenant.id,
            kind="tenant.provision",
            status="pending",
            next_attempt_at=future,
        )
        s.add(past_job)
        await s.commit()

    worker = ProvisioningWorker(mssp_sessionmaker)
    async with mssp_sessionmaker() as s:
        claimed = await worker._claim(s)
    assert claimed is None
