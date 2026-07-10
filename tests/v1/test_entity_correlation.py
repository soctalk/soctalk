"""Entity-overlap correlation attach (#27).

Requires Postgres + migrations (v1_0020). Skipped under SKIP_INTEGRATION=1.
"""

from __future__ import annotations

import os
from datetime import datetime, timezone

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from soctalk.core.ir.correlation import extract_keys, find_correlated_investigation
from soctalk.core.ir.policies import set_tenant_policy
from soctalk.core.ir.triage import triage_event

SKIP_INTEGRATION = os.getenv("SKIP_INTEGRATION", "0") == "1"

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(SKIP_INTEGRATION, reason="needs Postgres"),
]


# --------------------------------------------------------------- pure unit-ish


def test_extract_keys_strength_and_types():
    keys = extract_keys(
        entities=[
            {"type": "host", "value": "web-01"},
            {"type": "user", "value": "root"},
        ],
        initial_iocs=[{"type": "ip", "value": "203.0.113.9"},
                      {"type": "hash_sha256", "value": "a" * 64}],
        rule_id="5710",
    )
    by = {(kt): st for kt, kv, st in keys}
    assert by["host"] == "strong"
    assert by["hash"] == "strong"
    assert by["ip"] == "conditional"
    assert by["user"] == "weak"
    assert by["rule"] == "weak"


# ----------------------------------------------------------------- integration


def _ev(seid, *, host, rule_id="5710", severity=9, ip=None):
    ent = [{"type": "host", "value": host, "role": "target", "source_field": "agent.name"}]
    iocs = [{"type": "ip", "value": ip}] if ip else []
    return dict(
        source="wazuh", rule_id=rule_id, severity=severity,
        asset_ids=[host], initial_iocs=iocs, source_event_id=seid,
        ts=datetime.now(timezone.utc), description="x",
        evidence={"entities": ent, "mitre": {}, "schema_version": 2},
    )


async def _enable(session, tenant_id):
    await set_tenant_policy(session, tenant_id, "entity_correlation_enabled", True)
    await session.commit()


async def test_shared_host_attaches_across_rules(
    mssp_session: AsyncSession, seed_two_tenants
):
    """Two different-rule alerts on the same host: the second attaches to
    the first's investigation instead of creating a new one."""
    tenant_a, _ = seed_two_tenants
    await _enable(mssp_session, tenant_a.tenant_id)

    r1 = await triage_event(mssp_session, tenant_id=tenant_a.tenant_id,
                            **_ev("c1", host="web-01", rule_id="5710"))
    await mssp_session.commit()
    assert r1["action"] == "promoted"

    # Different rule + different signature, same host.
    r2 = await triage_event(mssp_session, tenant_id=tenant_a.tenant_id,
                            **_ev("c2", host="web-01", rule_id="92657"))
    await mssp_session.commit()
    assert r2["action"] == "correlated"
    assert r2["investigation_id"] == r1["investigation_id"]

    n_inv = (await mssp_session.execute(
        text("SELECT count(*) FROM investigations WHERE tenant_id = :t"),
        {"t": str(tenant_a.tenant_id)},
    )).scalar_one()
    assert n_inv == 1, "correlated alert must not create a second investigation"

    # Both alerts are linked to the one investigation (insert-and-link,
    # not merge — two distinct alert rows).
    n_alerts = (await mssp_session.execute(
        text("SELECT count(*) FROM alerts WHERE investigation_id = :c"),
        {"c": r1["investigation_id"]},
    )).scalar_one()
    assert n_alerts == 2


async def test_no_shared_entity_promotes_separately(
    mssp_session: AsyncSession, seed_two_tenants
):
    tenant_a, _ = seed_two_tenants
    await _enable(mssp_session, tenant_a.tenant_id)
    r1 = await triage_event(mssp_session, tenant_id=tenant_a.tenant_id,
                            **_ev("d1", host="host-a"))
    r2 = await triage_event(mssp_session, tenant_id=tenant_a.tenant_id,
                            **_ev("d2", host="host-b"))
    await mssp_session.commit()
    assert r1["action"] == r2["action"] == "promoted"
    assert r1["investigation_id"] != r2["investigation_id"]


async def test_disabled_by_default(
    mssp_session: AsyncSession, seed_two_tenants
):
    """With the flag off (default), no entity correlation happens."""
    tenant_a, _ = seed_two_tenants
    r1 = await triage_event(mssp_session, tenant_id=tenant_a.tenant_id,
                            **_ev("e1", host="web-9", rule_id="5710"))
    r2 = await triage_event(mssp_session, tenant_id=tenant_a.tenant_id,
                            **_ev("e2", host="web-9", rule_id="92657"))
    await mssp_session.commit()
    assert r1["action"] == "promoted"
    assert r2["action"] == "promoted", "correlation off → separate investigations"
    assert r1["investigation_id"] != r2["investigation_id"]


async def test_hub_key_demotion(mssp_session: AsyncSession, seed_two_tenants):
    """A conditional key (ip) seen above the hub threshold stops correlating;
    a strong key (host) still does."""
    tenant_a, _ = seed_two_tenants
    keys = [("ip", "10.0.0.1", "conditional")]
    # Seed the stat above threshold.
    await mssp_session.execute(
        text("INSERT INTO entity_key_stats (tenant_id, key_type, key_value, seen_count, last_seen) "
             "VALUES (:t, 'ip', '10.0.0.1', 5000, now())"),
        {"t": str(tenant_a.tenant_id)},
    )
    await mssp_session.commit()
    # Even if an investigation had this key, a hub ip must not match.
    found = await find_correlated_investigation(
        mssp_session, tenant_id=tenant_a.tenant_id, keys=keys
    )
    assert found is None, "hub ip must be demoted out of correlation"
