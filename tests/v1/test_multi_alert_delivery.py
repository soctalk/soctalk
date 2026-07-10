"""Multi-alert delivery (#26): a claim returns all correlated alerts and
_build_state projects them into one graph state."""

from __future__ import annotations

import os
from datetime import datetime, timezone

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from soctalk.core.ir.policies import set_tenant_policy
from soctalk.core.ir.triage import triage_event

SKIP_INTEGRATION = os.getenv("SKIP_INTEGRATION", "0") == "1"

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(SKIP_INTEGRATION, reason="needs Postgres"),
]


def test_build_state_projects_multiple_alerts():
    """Unit: _build_state maps claim['alerts'] into N supervisor alerts,
    dedupes observables, and keeps the primary for compat."""
    from soctalk.runs_worker.main import _build_state

    claim = {
        "run_id": "r1",
        "alert": {"id": "a1", "rule": {"id": "5710", "level": 10},
                  "asset_ids": ["web-01"], "initial_iocs": [{"type": "ip", "value": "1.2.3.4"}],
                  "description": "brute force", "mitre": {"ids": ["T1110"]}},
        "alerts": [
            {"id": "a1", "rule": {"id": "5710", "level": 10}, "asset_ids": ["web-01"],
             "initial_iocs": [{"type": "ip", "value": "1.2.3.4"}], "description": "brute force",
             "mitre": {"ids": ["T1110"]}},
            {"id": "a2", "rule": {"id": "92657", "level": 9}, "asset_ids": ["web-01"],
             "initial_iocs": [{"type": "ip", "value": "1.2.3.4"}], "description": "priv esc"},
        ],
        "tokens_used": 0, "tokens_budget": 200000,
        "dollars_used": 0.0, "dollars_budget": 5.0,
    }
    state = _build_state(claim)
    alerts = state["investigation"]["alerts"]
    assert len(alerts) == 2
    assert {a["id"] for a in alerts} == {"a1", "a2"}
    # observables deduped across alerts (both cite 1.2.3.4)
    assert len(state["investigation"]["observables"]) == 1


async def test_claim_returns_all_correlated_alerts(
    mssp_session: AsyncSession, seed_two_tenants
):
    """End-to-end at the DB layer: correlate two alerts, then the claim
    query returns both (severity-ordered)."""
    tenant_a, _ = seed_two_tenants
    await set_tenant_policy(mssp_session, tenant_a.tenant_id, "entity_correlation_enabled", True)
    await mssp_session.commit()

    def ev(seid, rule, sev):
        return dict(
            source="wazuh", rule_id=rule, severity=sev, asset_ids=["srv-1"],
            initial_iocs=[], source_event_id=seid, ts=datetime.now(timezone.utc),
            description=f"alert {seid}",
            evidence={"entities": [{"type": "host", "value": "srv-1", "role": "target"}],
                      "mitre": {}, "schema_version": 2},
        )

    r1 = await triage_event(mssp_session, tenant_id=tenant_a.tenant_id, **ev("m1", "5710", 9))
    r2 = await triage_event(mssp_session, tenant_id=tenant_a.tenant_id, **ev("m2", "92657", 11))
    await mssp_session.commit()
    assert r1["action"] == "promoted"
    assert r2["action"] == "correlated"

    # The claim SQL (severity DESC): both alerts, highest first.
    rows = (await mssp_session.execute(
        text("SELECT severity FROM alerts WHERE investigation_id = :c "
             "ORDER BY severity DESC, first_event_at DESC"),
        {"c": r1["investigation_id"]},
    )).scalars().all()
    assert rows == [11, 9], "claim returns all alerts, highest severity first"


async def test_hil_alert_count_reflects_grouping(
    mssp_session: AsyncSession, seed_two_tenants
):
    """The HIL review row's alert_count is the real grouped count, not 1."""
    from soctalk.core.ir.review_events import record_human_review_requested

    tenant_a, _ = seed_two_tenants
    await set_tenant_policy(mssp_session, tenant_a.tenant_id, "entity_correlation_enabled", True)
    await mssp_session.commit()

    def ev(seid, rule, sev):
        return dict(
            source="wazuh", rule_id=rule, severity=sev, asset_ids=["host-x"],
            initial_iocs=[], source_event_id=seid, ts=datetime.now(timezone.utc),
            description="x",
            evidence={"entities": [{"type": "host", "value": "host-x", "role": "target"}],
                      "mitre": {}, "schema_version": 2},
        )
    r1 = await triage_event(mssp_session, tenant_id=tenant_a.tenant_id, **ev("h1", "5710", 9))
    await triage_event(mssp_session, tenant_id=tenant_a.tenant_id, **ev("h2", "92657", 9))
    await mssp_session.commit()
    inv = r1["investigation_id"]

    await record_human_review_requested(
        mssp_session, investigation_id=inv, tenant_id=tenant_a.tenant_id,
        reason="review", verdict_decision="escalate", verdict_confidence=0.9,
        findings=[], enrichments={},
    )
    await mssp_session.commit()

    cnt = (await mssp_session.execute(
        text("SELECT alert_count FROM pending_reviews WHERE investigation_id = :c"),
        {"c": inv},
    )).scalar_one()
    assert cnt == 2, "HIL alert_count must reflect the correlated group, not 1"


async def test_followup_flag_set_when_correlating_to_live_run(
    mssp_session: AsyncSession, seed_two_tenants
):
    """Review finding #2: correlating an alert onto an investigation that has
    a live run sets has_new_evidence, so complete_run can start a follow-up."""
    tenant_a, _ = seed_two_tenants
    await set_tenant_policy(mssp_session, tenant_a.tenant_id, "entity_correlation_enabled", True)
    await mssp_session.commit()

    def ev(seid, rule):
        return dict(source="wazuh", rule_id=rule, severity=9, asset_ids=["fl-1"],
                    initial_iocs=[], source_event_id=seid, ts=datetime.now(timezone.utc),
                    description="x",
                    evidence={"entities": [{"type": "host", "value": "fl-1", "role": "target"}],
                              "mitre": {}, "schema_version": 2})

    r1 = await triage_event(mssp_session, tenant_id=tenant_a.tenant_id, **ev("f1", "5710"))
    await mssp_session.commit()
    inv = r1["investigation_id"]
    # The promote created an active run. A correlated alert now arrives.
    r2 = await triage_event(mssp_session, tenant_id=tenant_a.tenant_id, **ev("f2", "92657"))
    await mssp_session.commit()
    assert r2["action"] == "correlated"

    flag = (await mssp_session.execute(
        text("SELECT has_new_evidence FROM investigations WHERE id = :c"), {"c": inv},
    )).scalar_one()
    assert flag is True, "correlating onto a live-run investigation must flag follow-up"
