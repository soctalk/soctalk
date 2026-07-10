"""Verdict memoization (#29): a recurring FP shape closes without a run."""

from __future__ import annotations

import os
from datetime import datetime, timezone

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from soctalk.core.ir.memoization import (
    lookup_memoized_close,
    record_verdict,
    shape_key,
)
from soctalk.core.ir.policies import set_tenant_policy
from soctalk.core.ir.triage import triage_event

SKIP_INTEGRATION = os.getenv("SKIP_INTEGRATION", "0") == "1"

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(SKIP_INTEGRATION, reason="needs Postgres"),
]


def test_shape_key_stable_and_none_without_template():
    k1 = shape_key(source="wazuh", decoder="sshd", template_hash="abc", template_version="1")
    k2 = shape_key(source="WAZUH", decoder="SSHD", template_hash="abc", template_version="1")
    assert k1 == k2, "shape key is case-normalized"
    assert shape_key(source="wazuh", decoder="sshd", template_hash=None, template_version="1") is None


async def test_only_high_conf_close_is_reusable(
    mssp_session: AsyncSession, seed_two_tenants
):
    tenant_a, _ = seed_two_tenants
    k = shape_key(source="wazuh", decoder="sshd", template_hash="t1", template_version="1")

    # An escalate verdict is never reusable.
    await record_verdict(mssp_session, tenant_id=tenant_a.tenant_id, key=k,
                         decision="escalate", confidence=0.95, template_hash="t1")
    await mssp_session.commit()
    assert await lookup_memoized_close(mssp_session, tenant_id=tenant_a.tenant_id, key=k) is None

    # A low-confidence close is below the reuse floor.
    await record_verdict(mssp_session, tenant_id=tenant_a.tenant_id, key=k,
                         decision="close", confidence=0.5, template_hash="t1")
    await mssp_session.commit()
    assert await lookup_memoized_close(mssp_session, tenant_id=tenant_a.tenant_id, key=k) is None

    # A high-confidence close IS reusable.
    await record_verdict(mssp_session, tenant_id=tenant_a.tenant_id, key=k,
                         decision="close", confidence=0.95, template_hash="t1")
    await mssp_session.commit()
    memo = await lookup_memoized_close(mssp_session, tenant_id=tenant_a.tenant_id, key=k)
    assert memo is not None and memo["decision"] == "close"


async def test_memoized_ingest_closes_without_run(
    mssp_session: AsyncSession, seed_two_tenants
):
    """With a cached FP verdict for a shape, a matching new alert is
    memoized-closed (auto_closed_fp) instead of promoted."""
    tenant_a, _ = seed_two_tenants
    await set_tenant_policy(mssp_session, tenant_a.tenant_id, "verdict_memoization_enabled", True)
    k = shape_key(source="wazuh", decoder="pam", template_hash="benign-tmpl", template_version="1")
    await record_verdict(mssp_session, tenant_id=tenant_a.tenant_id, key=k,
                         decision="close", confidence=0.95, template_hash="benign-tmpl")
    await mssp_session.commit()

    result = await triage_event(
        mssp_session, tenant_id=tenant_a.tenant_id,
        source="wazuh", rule_id="5501", severity=9, asset_ids=["h1"],
        initial_iocs=[], source_event_id="memo-1", ts=datetime.now(timezone.utc),
        description="cron session opened",
        evidence={"decoder": "pam", "template_hash": "benign-tmpl",
                  "template_version": "1", "schema_version": 2},
    )
    await mssp_session.commit()
    assert result["action"] == "memoized_close"

    # No investigation_runs created (no LLM run spun up).
    n_runs = (await mssp_session.execute(
        text("SELECT count(*) FROM investigation_runs WHERE tenant_id = :t"),
        {"t": str(tenant_a.tenant_id)},
    )).scalar_one()
    assert n_runs == 0, "memoized close must not spin a run"
    # hit_count bumped.
    hits = (await mssp_session.execute(
        text("SELECT hit_count FROM verdict_cache WHERE tenant_id = :t AND shape_key = :k"),
        {"t": str(tenant_a.tenant_id), "k": k},
    )).scalar_one()
    assert hits == 1


async def test_no_template_no_memoization(
    mssp_session: AsyncSession, seed_two_tenants
):
    """An event without a template_hash can't be memoized — promotes normally."""
    tenant_a, _ = seed_two_tenants
    await set_tenant_policy(mssp_session, tenant_a.tenant_id, "verdict_memoization_enabled", True)
    await mssp_session.commit()
    result = await triage_event(
        mssp_session, tenant_id=tenant_a.tenant_id,
        source="wazuh", rule_id="5501", severity=9, asset_ids=["h2"],
        initial_iocs=[], source_event_id="notmpl-1", ts=datetime.now(timezone.utc),
        description="x", evidence={"decoder": "pam", "schema_version": 2},
    )
    await mssp_session.commit()
    assert result["action"] == "promoted"


async def test_correlation_beats_memoization_for_live_incident(
    mssp_session: AsyncSession, seed_two_tenants
):
    """Review finding #1: an alert whose shape is a memoized FP but which
    shares an entity with a LIVE active investigation must CORRELATE, not be
    memoized-closed (suppressing live-incident evidence)."""
    tenant_a, _ = seed_two_tenants
    await set_tenant_policy(mssp_session, tenant_a.tenant_id, "entity_correlation_enabled", True)
    await set_tenant_policy(mssp_session, tenant_a.tenant_id, "verdict_memoization_enabled", True)
    # Cache an FP verdict for a shape.
    k = shape_key(source="wazuh", decoder="pam", template_hash="tmpl-x", template_version="1")
    await record_verdict(mssp_session, tenant_id=tenant_a.tenant_id, key=k,
                         decision="close", confidence=0.95, template_hash="tmpl-x")
    await mssp_session.commit()

    # A live active investigation exists on host 'hot-1'.
    r1 = await triage_event(
        mssp_session, tenant_id=tenant_a.tenant_id,
        source="wazuh", rule_id="5710", severity=9, asset_ids=["hot-1"],
        initial_iocs=[], source_event_id="live-1", ts=datetime.now(timezone.utc),
        description="first", evidence={"entities": [{"type": "host", "value": "hot-1", "role": "target"}],
                                       "mitre": {}, "schema_version": 2},
    )
    await mssp_session.commit()
    assert r1["action"] == "promoted"

    # A new alert with the memoized-FP shape BUT on the same live host.
    r2 = await triage_event(
        mssp_session, tenant_id=tenant_a.tenant_id,
        source="wazuh", rule_id="9999", severity=9, asset_ids=["hot-1"],
        initial_iocs=[], source_event_id="live-2", ts=datetime.now(timezone.utc),
        description="benign-shape but live host",
        evidence={"entities": [{"type": "host", "value": "hot-1", "role": "target"}],
                  "decoder": "pam", "template_hash": "tmpl-x", "template_version": "1",
                  "mitre": {}, "schema_version": 2},
    )
    await mssp_session.commit()
    assert r2["action"] == "correlated", "must correlate to the live incident, not memoized-close"
    assert r2["investigation_id"] == r1["investigation_id"]
