"""Correlation label capture (#30 substrate): merge/detach/confirm."""

from __future__ import annotations

import os
from datetime import datetime, timezone

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from soctalk.core.ir.labels import (
    confirm_grouping,
    detach_alert,
    merge_investigations,
)
from soctalk.core.ir.policies import set_tenant_policy
from soctalk.core.ir.triage import triage_event

SKIP_INTEGRATION = os.getenv("SKIP_INTEGRATION", "0") == "1"

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(SKIP_INTEGRATION, reason="needs Postgres"),
]


def _ev(seid, host, rule):
    return dict(
        source="wazuh", rule_id=rule, severity=9, asset_ids=[host],
        initial_iocs=[], source_event_id=seid, ts=datetime.now(timezone.utc),
        description="x",
        evidence={"entities": [{"type": "host", "value": host, "role": "target"}],
                  "mitre": {}, "schema_version": 2},
    )


async def test_merge_records_false_split_label_and_moves_alerts(
    mssp_session: AsyncSession, seed_two_tenants
):
    tenant_a, _ = seed_two_tenants
    # Two separate investigations (correlation off → separate).
    r1 = await triage_event(mssp_session, tenant_id=tenant_a.tenant_id, **_ev("m1", "h1", "5710"))
    r2 = await triage_event(mssp_session, tenant_id=tenant_a.tenant_id, **_ev("m2", "h2", "5710"))
    await mssp_session.commit()
    keep, other = r1["investigation_id"], r2["investigation_id"]

    out = await merge_investigations(
        mssp_session, tenant_id=tenant_a.tenant_id,
        keep_id=keep, other_id=other, reviewer="ana@x", note="same incident",
    )
    await mssp_session.commit()
    assert out["kept"] == keep

    # other's alert moved to keep; other closed.
    n_keep = (await mssp_session.execute(
        text("SELECT count(*) FROM alerts WHERE investigation_id = :c"), {"c": keep},
    )).scalar_one()
    assert n_keep == 2
    status = (await mssp_session.execute(
        text("SELECT status FROM investigations WHERE id = :c"), {"c": other},
    )).scalar_one()
    assert status == "closed"

    label = (await mssp_session.execute(
        text("SELECT label, other_investigation_id FROM correlation_labels "
             "WHERE tenant_id = :t AND label = 'merge'"),
        {"t": str(tenant_a.tenant_id)},
    )).mappings().one()
    assert str(label["other_investigation_id"]) == other


async def test_detach_records_false_attach_and_moves_alert(
    mssp_session: AsyncSession, seed_two_tenants
):
    tenant_a, _ = seed_two_tenants
    await set_tenant_policy(mssp_session, tenant_a.tenant_id, "entity_correlation_enabled", True)
    await mssp_session.commit()
    # Two alerts correlated onto one investigation via shared host.
    r1 = await triage_event(mssp_session, tenant_id=tenant_a.tenant_id, **_ev("d1", "hZ", "5710"))
    await triage_event(mssp_session, tenant_id=tenant_a.tenant_id, **_ev("d2", "hZ", "92657"))
    await mssp_session.commit()
    inv = r1["investigation_id"]

    # Detach the second alert.
    alert_id = (await mssp_session.execute(
        text("SELECT id FROM alerts WHERE investigation_id = :c "
             "ORDER BY first_event_at DESC LIMIT 1"), {"c": inv},
    )).scalar_one()
    out = await detach_alert(
        mssp_session, tenant_id=tenant_a.tenant_id, alert_id=alert_id, reviewer="ana@x",
    )
    await mssp_session.commit()

    # alert moved to a fresh investigation.
    new_inv = out["new_investigation_id"]
    assert new_inv != inv
    moved = (await mssp_session.execute(
        text("SELECT investigation_id FROM alerts WHERE id = :a"), {"a": str(alert_id)},
    )).scalar_one()
    assert str(moved) == new_inv

    label = (await mssp_session.execute(
        text("SELECT label FROM correlation_labels WHERE tenant_id = :t AND label = 'detach'"),
        {"t": str(tenant_a.tenant_id)},
    )).scalar_one()
    assert label == "detach"


async def test_confirm_records_positive_label(
    mssp_session: AsyncSession, seed_two_tenants
):
    tenant_a, _ = seed_two_tenants
    r1 = await triage_event(mssp_session, tenant_id=tenant_a.tenant_id, **_ev("c1", "hC", "5710"))
    await mssp_session.commit()
    await confirm_grouping(
        mssp_session, tenant_id=tenant_a.tenant_id,
        investigation_id=r1["investigation_id"], reviewer="ana@x",
    )
    await mssp_session.commit()
    n = (await mssp_session.execute(
        text("SELECT count(*) FROM correlation_labels WHERE tenant_id = :t AND label = 'confirm'"),
        {"t": str(tenant_a.tenant_id)},
    )).scalar_one()
    assert n == 1
