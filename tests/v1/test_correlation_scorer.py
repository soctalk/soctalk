"""Learned correlation scorer (#30): scoring math, spike gate, review-only path."""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from soctalk.core.ir.policies import set_tenant_policy
from soctalk.core.ir.scorer import entity_jaccard, suggest_for_alert, time_decay
from soctalk.core.ir.triage import triage_event
from soctalk.evals.correlation import (
    best_threshold,
    load_pairs,
    score_pairs,
    sweep,
)

SKIP_INTEGRATION = os.getenv("SKIP_INTEGRATION", "0") == "1"


# ------------------------------------------------------------------ pure unit


def test_entity_jaccard_rarity_weights_strong_keys():
    # Shared strong key (hash) scores higher than shared weak key (rule).
    strong = entity_jaccard([("hash", "h", "strong")], [("hash", "h", "strong")])
    weak = entity_jaccard([("rule", "r", "weak")], [("rule", "r", "weak")])
    assert strong == pytest.approx(1.0)
    assert weak == pytest.approx(1.0)
    # Mixed: a shared strong key among noise beats a shared weak key among noise.
    s_mixed = entity_jaccard(
        [("hash", "h", "strong"), ("rule", "x", "weak")],
        [("hash", "h", "strong"), ("rule", "y", "weak")],
    )
    w_mixed = entity_jaccard(
        [("rule", "h", "weak"), ("host", "x", "strong")],
        [("rule", "h", "weak"), ("host", "y", "strong")],
    )
    assert s_mixed > w_mixed


def test_entity_jaccard_no_overlap_is_zero():
    assert entity_jaccard([("host", "a", "strong")], [("host", "b", "strong")]) == 0.0
    assert entity_jaccard([], [("host", "a", "strong")]) == 0.0


def test_time_decay_monotonic():
    now = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)
    near = time_decay(now, now + timedelta(minutes=10), 120)
    far = time_decay(now, now + timedelta(hours=6), 120)
    assert 0 < far < near <= 1.0


def test_spike_gate_separates_labeled_pairs():
    pairs = load_pairs()
    scored = score_pairs(pairs)
    # Same-incident pairs should generally outscore different-incident ones.
    same = [s["score"] for s in scored if s["same"]]
    diff = [s["score"] for s in scored if not s["same"]]
    assert max(same) > max(diff), "top same-incident pair must outscore top diff"
    # A precision-1.0 threshold at non-zero recall must exist (the gate).
    best = best_threshold(sweep(scored), min_precision=1.0)
    assert best is not None and best["recall"] > 0


# ----------------------------------------------------------------- integration


@pytest.mark.integration
@pytest.mark.skipif(SKIP_INTEGRATION, reason="needs Postgres")
async def test_scorer_records_suggestion_never_attaches(
    mssp_session: AsyncSession, seed_two_tenants
):
    """With the scorer enabled (but entity-correlation OFF), a second alert
    sharing a host records a REVIEW-ONLY suggestion and still promotes to its
    own investigation — never auto-attaches."""
    tenant_a, _ = seed_two_tenants
    await set_tenant_policy(mssp_session, tenant_a.tenant_id, "correlation_scorer_enabled", True)
    # entity_correlation_enabled stays False — deterministic attach must NOT fire.
    await mssp_session.commit()

    def ev(seid, rule):
        return dict(source="wazuh", rule_id=rule, severity=9, asset_ids=["sc-1"],
                    initial_iocs=[], source_event_id=seid, ts=datetime.now(timezone.utc),
                    description="x",
                    evidence={"entities": [{"type": "host", "value": "sc-1", "role": "target"}],
                              "mitre": {}, "schema_version": 2})

    r1 = await triage_event(mssp_session, tenant_id=tenant_a.tenant_id, **ev("s1", "5710"))
    r2 = await triage_event(mssp_session, tenant_id=tenant_a.tenant_id, **ev("s2", "92657"))
    await mssp_session.commit()

    # Both promoted to SEPARATE investigations (scorer never attaches).
    assert r1["action"] == "promoted"
    assert r2["action"] == "promoted"
    assert r1["investigation_id"] != r2["investigation_id"]

    # A review-only suggestion was recorded pointing the 2nd alert at the 1st.
    sug = (await mssp_session.execute(
        text("SELECT suggested_investigation_id, band, status, score "
             "FROM correlation_suggestions WHERE tenant_id = :t"),
        {"t": str(tenant_a.tenant_id)},
    )).mappings().all()
    assert len(sug) >= 1
    assert sug[0]["status"] == "pending"
    assert str(sug[0]["suggested_investigation_id"]) == r1["investigation_id"]


@pytest.mark.integration
@pytest.mark.skipif(SKIP_INTEGRATION, reason="needs Postgres")
async def test_scorer_off_by_default_records_nothing(
    mssp_session: AsyncSession, seed_two_tenants
):
    tenant_a, _ = seed_two_tenants

    def ev(seid, rule):
        return dict(source="wazuh", rule_id=rule, severity=9, asset_ids=["off-1"],
                    initial_iocs=[], source_event_id=seid, ts=datetime.now(timezone.utc),
                    description="x",
                    evidence={"entities": [{"type": "host", "value": "off-1", "role": "target"}],
                              "mitre": {}, "schema_version": 2})
    await triage_event(mssp_session, tenant_id=tenant_a.tenant_id, **ev("o1", "5710"))
    await triage_event(mssp_session, tenant_id=tenant_a.tenant_id, **ev("o2", "92657"))
    await mssp_session.commit()
    n = (await mssp_session.execute(
        text("SELECT count(*) FROM correlation_suggestions WHERE tenant_id = :t"),
        {"t": str(tenant_a.tenant_id)},
    )).scalar_one()
    assert n == 0, "scorer default-off records no suggestions"
