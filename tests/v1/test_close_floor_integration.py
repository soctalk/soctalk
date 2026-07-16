"""Safety floor on the IR ingest auto-close plane (issue #43) — DB-backed.

The floor must veto BOTH ingest close paths (memoized close and the rules band) when
the alert carries IOCs or overlaps an active incident, regardless of policy flags,
and each veto leaves an ``ir.triage_policy.close_floor_veto`` audit row. The worker-plane
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
from soctalk.triage_policy.floor import FLOOR_AUDIT_ACTION

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


async def test_close_fp_floor_veto_helper_end_to_end(
    mssp_session: AsyncSession, seed_two_tenants
):
    """The extracted complete_run veto (issue #43, Codex full-module finding 5):
    an active investigation with an active key-sharing sibling is vetoed (audit
    row written); a non-active investigation is never vetoed even with a sibling
    (the close path's WHERE status='active' no-op owns that case)."""
    from uuid import UUID

    from soctalk.core.api.worker_runs import close_fp_floor_veto

    tenant_a, _ = seed_two_tenants
    ids = []
    for n in (1, 2):
        r = await triage_event(
            mssp_session, tenant_id=tenant_a.tenant_id,
            source="wazuh", rule_id=f"58{n}0", severity=9,
            asset_ids=["floor-veto-1"], initial_iocs=[],
            source_event_id=f"floor-veto-{n}", ts=datetime.now(UTC),
            description=f"incident {n}",
            evidence={"entities": [{"type": "host", "value": "floor-veto-1",
                                    "role": "target"}],
                      "mitre": {}, "schema_version": 2},
        )
        await mssp_session.commit()
        assert r["action"] == "promoted"
        ids.append(UUID(r["investigation_id"]))

    veto = await close_fp_floor_veto(
        mssp_session, tenant_id=tenant_a.tenant_id, investigation_id=ids[0]
    )
    await mssp_session.commit()
    assert veto == "active_incident"
    audits = await _floor_audit_rows(mssp_session, tenant_a.tenant_id)
    # canonical_json (compact, sorted keys) on every plane — string-based audit
    # filters must match worker vetoes and ingest vetoes identically.
    assert any(
        '"blocked":"worker_close_fp"' in a["notes"]
        and str(ids[1]) in a["notes"]
        and a["resource_id"] == str(ids[0])
        for a in audits
    )

    # Close the investigation out from under the worker: the veto must stand down.
    await mssp_session.execute(
        text("UPDATE investigations SET status = 'auto_closed_fp', closed_at = now() "
             "WHERE id = :c"),
        {"c": str(ids[0])},
    )
    assert await close_fp_floor_veto(
        mssp_session, tenant_id=tenant_a.tenant_id, investigation_id=ids[0]
    ) is None


# ---------------------------------------------------------------------------
# issue #46: kill switch + close-volume cap
# ---------------------------------------------------------------------------


async def test_kill_switch_policy_vetoes_rules_auto_close(
    mssp_session: AsyncSession, seed_two_tenants
):
    """Per-tenant ``auto_close_kill`` flips a clean rules-band auto-close to
    promotion, audited — no env change, no rollout."""
    tenant_a, _ = seed_two_tenants
    await set_tenant_policy(mssp_session, tenant_a.tenant_id, "auto_close_kill", True)
    await mssp_session.commit()

    result = await triage_event(
        mssp_session, tenant_id=tenant_a.tenant_id,
        source="wazuh", rule_id="1002", severity=1, asset_ids=["kill-1"],
        initial_iocs=[], source_event_id="kill-sw-1", ts=datetime.now(UTC),
        description="clean low-sev noise under kill switch",
        evidence={"schema_version": 2},
    )
    await mssp_session.commit()
    assert result["action"] == "promoted"
    audits = await _floor_audit_rows(mssp_session, tenant_a.tenant_id)
    assert any('"veto":"auto_close_killed"' in a["notes"] for a in audits)


async def test_kill_switch_env_vetoes_worker_close(
    mssp_session: AsyncSession, seed_two_tenants, monkeypatch
):
    """Install-wide SOCTALK_AUTO_CLOSE_KILL vetoes a worker close_fp at
    complete_run's floor helper, regardless of tenant policy."""
    from uuid import UUID

    from soctalk.core.api.worker_runs import close_fp_floor_veto

    tenant_a, _ = seed_two_tenants
    r = await triage_event(
        mssp_session, tenant_id=tenant_a.tenant_id,
        source="wazuh", rule_id="5910", severity=9, asset_ids=["kill-2"],
        initial_iocs=[], source_event_id="kill-env-1", ts=datetime.now(UTC),
        description="promoted case",
        evidence={"entities": [{"type": "host", "value": "kill-2", "role": "target"}],
                  "mitre": {}, "schema_version": 2},
    )
    await mssp_session.commit()
    inv = UUID(r["investigation_id"])

    monkeypatch.setenv("SOCTALK_AUTO_CLOSE_KILL", "true")
    assert await close_fp_floor_veto(
        mssp_session, tenant_id=tenant_a.tenant_id, investigation_id=inv
    ) == "auto_close_killed"
    monkeypatch.delenv("SOCTALK_AUTO_CLOSE_KILL")
    assert await close_fp_floor_veto(
        mssp_session, tenant_id=tenant_a.tenant_id, investigation_id=inv
    ) is None


async def test_volume_cap_vetoes_after_cap_spent(
    mssp_session: AsyncSession, seed_two_tenants
):
    """auto_close_volume_cap=1: the first clean auto-close commits, the second is
    vetoed to promotion with a close_volume_cap audit row — runaway close loops
    degrade to humans looking, never mass suppression."""
    tenant_a, _ = seed_two_tenants
    await set_tenant_policy(
        mssp_session, tenant_a.tenant_id, "auto_close_volume_cap", 1
    )
    await mssp_session.commit()

    r1 = await triage_event(
        mssp_session, tenant_id=tenant_a.tenant_id,
        source="wazuh", rule_id="1002", severity=1, asset_ids=["cap-1"],
        initial_iocs=[], source_event_id="cap-1", ts=datetime.now(UTC),
        description="first clean noise", evidence={"schema_version": 2},
    )
    await mssp_session.commit()
    assert r1["action"] == "auto_closed", "cap not yet spent — close commits"

    r2 = await triage_event(
        mssp_session, tenant_id=tenant_a.tenant_id,
        source="wazuh", rule_id="1003", severity=1, asset_ids=["cap-2"],
        initial_iocs=[], source_event_id="cap-2", ts=datetime.now(UTC),
        description="second clean noise", evidence={"schema_version": 2},
    )
    await mssp_session.commit()
    assert r2["action"] == "promoted", "cap spent — close vetoed to promotion"
    audits = await _floor_audit_rows(mssp_session, tenant_a.tenant_id)
    assert any('"veto":"close_volume_cap"' in a["notes"] for a in audits)
