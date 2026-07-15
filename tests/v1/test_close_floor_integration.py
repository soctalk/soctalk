"""Safety floor on the IR ingest auto-close plane (issue #43) — DB-backed.

The floor must veto BOTH ingest close paths (memoized close and the rules band) when
the alert carries IOCs or overlaps an active incident, regardless of policy flags,
and each veto leaves an ``ir.playbook.close_floor_veto`` audit row. The worker-plane
half of the floor is covered DB-free in test_playbook_unit.py.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from soctalk.core.ir.correlation import (
    find_other_active_investigation_sharing_keys,
)
from soctalk.core.ir.memoization import record_verdict, shape_key
from soctalk.core.ir.policies import set_tenant_policy
from soctalk.core.ir.triage import triage_event
from soctalk.playbook.floor import FLOOR_AUDIT_ACTION

SKIP_INTEGRATION = os.getenv("SKIP_INTEGRATION", "0") == "1"

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(SKIP_INTEGRATION, reason="needs Postgres"),
]


async def _floor_audit_rows(db: AsyncSession, tenant_id) -> list[dict]:
    rows = (
        await db.execute(
            text(
                "SELECT resource_id, notes FROM audit_log "
                "WHERE tenant_id = :t AND action = :a ORDER BY timestamp"
            ),
            {"t": str(tenant_id), "a": FLOOR_AUDIT_ACTION},
        )
    ).mappings().all()
    return [dict(r) for r in rows]


async def test_ioc_vetoes_memoized_close(mssp_session: AsyncSession, seed_two_tenants):
    """A shape with a cached FP verdict does NOT memoize-close when the new alert
    carries an IOC — it promotes to a real investigation, with an audit row."""
    tenant_a, _ = seed_two_tenants
    await set_tenant_policy(
        mssp_session, tenant_a.tenant_id, "verdict_memoization_enabled", True
    )
    k = shape_key(
        source="wazuh", decoder="pam", template_hash="floor-tmpl", template_version="1"
    )
    await record_verdict(
        mssp_session, tenant_id=tenant_a.tenant_id, key=k,
        decision="close", confidence=0.95, template_hash="floor-tmpl",
    )
    await mssp_session.commit()

    result = await triage_event(
        mssp_session, tenant_id=tenant_a.tenant_id,
        source="wazuh", rule_id="5501", severity=9, asset_ids=["fh-1"],
        initial_iocs=[{"type": "ip", "value": "203.0.113.9"}],
        source_event_id="floor-memo-1", ts=datetime.now(UTC),
        description="pam session with IOC",
        evidence={"decoder": "pam", "template_hash": "floor-tmpl",
                  "template_version": "1", "schema_version": 2},
    )
    await mssp_session.commit()

    assert result["action"] == "promoted", "IOC-bearing alert must never memoize-close"
    audits = await _floor_audit_rows(mssp_session, tenant_a.tenant_id)
    assert audits, "floor veto must leave an audit row"
    assert '"blocked":"memoized_close"' in audits[-1]["notes"]
    assert '"veto":"ioc_present"' in audits[-1]["notes"]


async def test_ioc_vetoes_rules_auto_close(mssp_session: AsyncSession, seed_two_tenants):
    """severity<3, no MITRE → high_conf_fp band — but an IOC on the alert vetoes the
    rules auto-close and the alert promotes instead."""
    tenant_a, _ = seed_two_tenants
    result = await triage_event(
        mssp_session, tenant_id=tenant_a.tenant_id,
        source="wazuh", rule_id="1002", severity=1, asset_ids=["fh-2"],
        initial_iocs=[{"type": "domain", "value": "evil.example"}],
        source_event_id="floor-rules-1", ts=datetime.now(UTC),
        description="low-sev noise carrying an IOC",
        evidence={"schema_version": 2},
    )
    await mssp_session.commit()

    assert result["action"] == "promoted"
    audits = await _floor_audit_rows(mssp_session, tenant_a.tenant_id)
    assert any('"blocked":"rules_auto_close"' in a["notes"] for a in audits)


async def test_clean_low_sev_alert_still_auto_closes(
    mssp_session: AsyncSession, seed_two_tenants
):
    """The floor is a veto, not a new gate: a clean high_conf_fp alert (no IOC, no
    active incident) auto-closes exactly as before."""
    tenant_a, _ = seed_two_tenants
    result = await triage_event(
        mssp_session, tenant_id=tenant_a.tenant_id,
        source="wazuh", rule_id="1002", severity=1, asset_ids=["fh-3"],
        initial_iocs=[], source_event_id="floor-clean-1",
        ts=datetime.now(UTC),
        description="clean low-sev noise",
        evidence={"schema_version": 2},
    )
    await mssp_session.commit()
    assert result["action"] == "auto_closed"
    audits = await _floor_audit_rows(mssp_session, tenant_a.tenant_id)
    assert not any("floor-clean" in (a["resource_id"] or "") for a in audits)


async def test_active_incident_vetoes_auto_close_when_correlation_disabled(
    mssp_session: AsyncSession, seed_two_tenants
):
    """Correlation attach is OFF (default policy), so nothing attaches the alert to
    the live incident — but the floor still refuses to auto-close over it."""
    tenant_a, _ = seed_two_tenants
    # A live active investigation on host floor-hot-1.
    r1 = await triage_event(
        mssp_session, tenant_id=tenant_a.tenant_id,
        source="wazuh", rule_id="5710", severity=9, asset_ids=["floor-hot-1"],
        initial_iocs=[], source_event_id="floor-live-1",
        ts=datetime.now(UTC),
        description="live incident",
        evidence={"entities": [{"type": "host", "value": "floor-hot-1", "role": "target"}],
                  "mitre": {}, "schema_version": 2},
    )
    await mssp_session.commit()
    assert r1["action"] == "promoted"

    # A low-sev alert sharing the host would rules-auto-close without the floor.
    r2 = await triage_event(
        mssp_session, tenant_id=tenant_a.tenant_id,
        source="wazuh", rule_id="1002", severity=1, asset_ids=["floor-hot-1"],
        initial_iocs=[], source_event_id="floor-live-2",
        ts=datetime.now(UTC),
        description="low-sev noise on a host with a live incident",
        evidence={"entities": [{"type": "host", "value": "floor-hot-1", "role": "target"}],
                  "schema_version": 2},
    )
    await mssp_session.commit()

    assert r2["action"] == "promoted", "must not auto-close over an active incident"
    audits = await _floor_audit_rows(mssp_session, tenant_a.tenant_id)
    assert any('"veto":"active_incident"' in a["notes"] for a in audits)


async def test_worker_close_floor_sees_sibling_active_investigation(
    mssp_session: AsyncSession, seed_two_tenants
):
    """complete_run's server-side veto (issue #43): two separately-promoted ACTIVE
    investigations share a host entity — the helper finds the sibling from either
    side, so a worker close_fp on one is escalated instead of committed."""
    from uuid import UUID

    tenant_a, _ = seed_two_tenants
    ids = []
    for n in (1, 2):
        r = await triage_event(
            mssp_session, tenant_id=tenant_a.tenant_id,
            source="wazuh", rule_id=f"57{n}0", severity=9,
            asset_ids=["floor-sib-1"], initial_iocs=[],
            source_event_id=f"floor-sib-{n}", ts=datetime.now(UTC),
            description=f"incident {n}",
            evidence={"entities": [{"type": "host", "value": "floor-sib-1",
                                    "role": "target"}],
                      "mitre": {}, "schema_version": 2},
        )
        await mssp_session.commit()
        assert r["action"] == "promoted"
        ids.append(UUID(r["investigation_id"]))

    other = await find_other_active_investigation_sharing_keys(
        mssp_session, tenant_id=tenant_a.tenant_id, investigation_id=ids[0]
    )
    assert other == ids[1]

    # An investigation with no entity overlap sees no sibling.
    lone = await triage_event(
        mssp_session, tenant_id=tenant_a.tenant_id,
        source="wazuh", rule_id="5990", severity=9,
        asset_ids=["floor-lone-1"], initial_iocs=[],
        source_event_id="floor-lone-1", ts=datetime.now(UTC),
        description="unrelated",
        evidence={"entities": [{"type": "host", "value": "floor-lone-1",
                                "role": "target"}],
                  "mitre": {}, "schema_version": 2},
    )
    await mssp_session.commit()
    assert await find_other_active_investigation_sharing_keys(
        mssp_session, tenant_id=tenant_a.tenant_id,
        investigation_id=UUID(lone["investigation_id"]),
    ) is None
