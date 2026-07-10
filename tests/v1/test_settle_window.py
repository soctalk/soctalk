"""Settle window (#28): a run is not claimable until not_before passes."""

from __future__ import annotations

import os
from datetime import datetime, timezone

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from soctalk.core.ir.runtime import start_run

SKIP_INTEGRATION = os.getenv("SKIP_INTEGRATION", "0") == "1"

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(SKIP_INTEGRATION, reason="needs Postgres"),
]


async def _mk_investigation(s: AsyncSession, tenant_id) -> str:
    from uuid import uuid4
    cid = str(uuid4())
    await s.execute(
        text(
            "INSERT INTO investigations (id, tenant_id, short_id, title, status, "
            "severity, opened_at, visibility) "
            "VALUES (:id, :t, :sid, 'x', 'active', 5, now(), 'mssp_only')"
        ),
        {"id": cid, "t": str(tenant_id), "sid": f"S-{cid[:6]}"},
    )
    return cid


async def _not_before(s: AsyncSession, run_id) -> datetime:
    return (await s.execute(
        text("SELECT not_before FROM investigation_runs WHERE id = :r"),
        {"r": str(run_id)},
    )).scalar_one()


async def test_settle_window_delays_not_before(
    mssp_session: AsyncSession, seed_two_tenants
):
    tenant_a, _ = seed_two_tenants
    cid = await _mk_investigation(mssp_session, tenant_a.tenant_id)
    run_id = await start_run(mssp_session, tenant_a.tenant_id, cid, settle_seconds=90)
    await mssp_session.commit()

    nb = await _not_before(mssp_session, run_id)
    delta = nb - datetime.now(timezone.utc)
    assert delta.total_seconds() > 60, "settle window must push not_before into the future"


async def test_zero_settle_is_immediately_claimable(
    mssp_session: AsyncSession, seed_two_tenants
):
    tenant_a, _ = seed_two_tenants
    cid = await _mk_investigation(mssp_session, tenant_a.tenant_id)
    run_id = await start_run(mssp_session, tenant_a.tenant_id, cid, settle_seconds=0)
    await mssp_session.commit()

    nb = await _not_before(mssp_session, run_id)
    assert nb <= datetime.now(timezone.utc), "no settle → claimable now"

    # And the claim predicate sees it: not_before <= now().
    claimable = (await mssp_session.execute(
        text("SELECT count(*) FROM investigation_runs "
             "WHERE id = :r AND status = 'active' AND not_before <= now()"),
        {"r": str(run_id)},
    )).scalar_one()
    assert claimable == 1


async def test_settled_run_not_yet_claimable(
    mssp_session: AsyncSession, seed_two_tenants
):
    tenant_a, _ = seed_two_tenants
    cid = await _mk_investigation(mssp_session, tenant_a.tenant_id)
    run_id = await start_run(mssp_session, tenant_a.tenant_id, cid, settle_seconds=300)
    await mssp_session.commit()

    claimable = (await mssp_session.execute(
        text("SELECT count(*) FROM investigation_runs "
             "WHERE id = :r AND not_before <= now()"),
        {"r": str(run_id)},
    )).scalar_one()
    assert claimable == 0, "a settling run must not be claimable yet"
