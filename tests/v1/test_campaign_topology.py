"""Campaign discrimination + topology (#31)."""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from soctalk.core.ir.campaign import (
    attack_path_exists,
    classify_activity,
    declare_engagement,
    deconflict,
    upsert_topology_edge,
)

SKIP_INTEGRATION = os.getenv("SKIP_INTEGRATION", "0") == "1"


# ------------------------------------------------------------------ pure unit


def test_classify_activity_categories():
    # Exfil or depth => real campaign.
    assert classify_activity({"exfil": True})[0] == "campaign"
    assert classify_activity({"depth": 3})[0] == "campaign"
    # Known scanner, narrow => benign probe.
    assert classify_activity({"known_scanner": True, "breadth": 2})[0] == "benign_probe"
    # Known scanner, broad => inferred test (flag, not suppress).
    assert classify_activity({"known_scanner": True, "breadth": 20})[0] == "inferred_test"
    # Broad + shallow + homogeneous tooling => benign probe.
    assert classify_activity({"breadth": 12, "depth": 1, "tool_homogeneity": 0.9})[0] == "benign_probe"
    # Broad + shallow, ambiguous => inferred test.
    assert classify_activity({"breadth": 9, "depth": 1})[0] == "inferred_test"


# ----------------------------------------------------------------- integration


@pytest.mark.integration
@pytest.mark.skipif(SKIP_INTEGRATION, reason="needs Postgres")
async def test_deconflict_in_scope_and_out_of_scope(
    mssp_session: AsyncSession, seed_two_tenants
):
    tenant_a, _ = seed_two_tenants
    now = datetime.now(timezone.utc)
    await declare_engagement(
        mssp_session, tenant_id=tenant_a.tenant_id, name="Q3 pentest", kind="pentest",
        starts_at=now - timedelta(hours=1), ends_at=now + timedelta(hours=1),
        scope_source_ips=["203.0.113.0/24"], scope_hosts=["web-01", "web-02"],
        scope_techniques=["T1110"],
    )
    await mssp_session.commit()

    # In-window, fully in-scope → declared_test.
    r = await deconflict(
        mssp_session, tenant_id=tenant_a.tenant_id, occurred_at=now,
        source_ips=["203.0.113.5"], hosts=["web-01"], techniques=["T1110"],
    )
    assert r["status"] == "declared_test"

    # In-window but the tester strayed to an out-of-scope host + technique.
    r2 = await deconflict(
        mssp_session, tenant_id=tenant_a.tenant_id, occurred_at=now,
        source_ips=["203.0.113.5"], hosts=["db-01"], techniques=["T1486"],
    )
    assert r2["status"] == "out_of_scope"
    assert "db-01" in r2["out_of_scope"]["hosts"]
    assert "T1486" in r2["out_of_scope"]["techniques"]

    # Outside any engagement window → None (normal triage).
    r3 = await deconflict(
        mssp_session, tenant_id=tenant_a.tenant_id, occurred_at=now + timedelta(days=2),
        source_ips=["203.0.113.5"], hosts=["web-01"], techniques=["T1110"],
    )
    assert r3 is None


@pytest.mark.integration
@pytest.mark.skipif(SKIP_INTEGRATION, reason="needs Postgres")
async def test_attack_path_query(mssp_session: AsyncSession, seed_two_tenants):
    tenant_a, _ = seed_two_tenants
    now = datetime.now(timezone.utc)
    # dmz -> app (observed) -> db (potential, routable but unseen)
    await upsert_topology_edge(mssp_session, tenant_id=tenant_a.tenant_id,
                               src_host="dmz-1", dst_host="app-1", port=443,
                               adjacency="observed", occurred_at=now)
    await upsert_topology_edge(mssp_session, tenant_id=tenant_a.tenant_id,
                               src_host="app-1", dst_host="db-1", port=5432,
                               adjacency="potential", occurred_at=now)
    await mssp_session.commit()

    # Path to the crown-jewel db host exists (2 hops), mixing observed+potential.
    r = await attack_path_exists(
        mssp_session, tenant_id=tenant_a.tenant_id, from_host="dmz-1", to_host="db-1"
    )
    assert r["path_exists"] is True
    assert r["hops"] == 2
    assert r["any_observed"] is True

    # No route from an isolated host.
    r2 = await attack_path_exists(
        mssp_session, tenant_id=tenant_a.tenant_id, from_host="isolated", to_host="db-1"
    )
    assert r2["path_exists"] is False
