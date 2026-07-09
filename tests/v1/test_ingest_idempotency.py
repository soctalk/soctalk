"""Integration tests for #17: idempotency, evidence store, MITRE veto.

Requires Postgres + migrations (v1_0018). Skipped under SKIP_INTEGRATION=1.
"""

from __future__ import annotations

import os
from datetime import datetime, timezone

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from soctalk.core.ir.triage import assess, triage_event

SKIP_INTEGRATION = os.getenv("SKIP_INTEGRATION", "0") == "1"

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(SKIP_INTEGRATION, reason="needs Postgres"),
]


def _kwargs(seid: str, **over):
    base = dict(
        source="wazuh", rule_id="5710", severity=9,
        asset_ids=["agent-9", "bastion-9"],
        initial_iocs=[{"type": "ip", "value": "203.0.113.9"}],
        source_event_id=seid,
        ts=datetime.now(timezone.utc),
        description="sshd auth failure from 203.0.113.9",
    )
    base.update(over)
    return base


async def test_replayed_event_noops(mssp_session: AsyncSession, seed_two_tenants):
    """A replayed (tenant, source, source_event_id) returns duplicate and
    does not inflate coalescing counters or create a second investigation."""
    tenant_a, _ = seed_two_tenants

    r1 = await triage_event(mssp_session, tenant_id=tenant_a.tenant_id, **_kwargs("dup-1"))
    await mssp_session.commit()
    assert r1["action"] == "promoted"

    r2 = await triage_event(mssp_session, tenant_id=tenant_a.tenant_id, **_kwargs("dup-1"))
    await mssp_session.commit()
    assert r2["action"] == "duplicate"

    n_inv = (await mssp_session.execute(
        text("SELECT count(*) FROM investigations WHERE tenant_id = :t"),
        {"t": str(tenant_a.tenant_id)},
    )).scalar_one()
    n_se = (await mssp_session.execute(
        text("SELECT count(*) FROM alert_source_events WHERE tenant_id = :t"),
        {"t": str(tenant_a.tenant_id)},
    )).scalar_one()
    assert n_inv == 1, "replay must not create a second investigation"
    assert n_se == 1, "replay must not insert a second source-event row"


async def test_evidence_persisted(mssp_session: AsyncSession, seed_two_tenants):
    tenant_a, _ = seed_two_tenants
    evidence = {
        "entities": [{"type": "user", "value": "root", "role": "actor", "source_field": "data.srcuser"}],
        "mitre": {"ids": ["T1110"], "tactics": ["Credential Access"], "techniques": ["Brute Force"]},
        "rule_groups": ["authentication_failed", "sshd"],
        "decoder": "sshd",
        "full_log": "Failed password for root from 203.0.113.9 <REDACTED:credential>",
        "template_hash": "abc123",
        "template_version": "1",
        "redaction_version": "1",
        "schema_version": 2,
        "observed_at": datetime.now(timezone.utc),
    }
    await triage_event(
        mssp_session, tenant_id=tenant_a.tenant_id,
        evidence=evidence, **_kwargs("ev-1"),
    )
    await mssp_session.commit()

    row = (await mssp_session.execute(
        text(
            "SELECT mitre, rule_groups, decoder, full_log_redacted, "
            "       template_hash, schema_version, entities, alert_id "
            "FROM alert_source_events WHERE tenant_id = :t AND source_event_id = 'ev-1'"
        ),
        {"t": str(tenant_a.tenant_id)},
    )).mappings().one()
    assert row["mitre"]["ids"] == ["T1110"]
    assert "authentication_failed" in row["rule_groups"]
    assert row["decoder"] == "sshd"
    assert "<REDACTED:credential>" in row["full_log_redacted"]
    assert row["schema_version"] == 2
    assert row["entities"][0]["type"] == "user"
    assert row["alert_id"] is not None, "source event must link to its alert"


async def test_description_no_longer_clobbers_ai_assessment(
    mssp_session: AsyncSession, seed_two_tenants
):
    tenant_a, _ = seed_two_tenants
    await triage_event(
        mssp_session, tenant_id=tenant_a.tenant_id,
        **_kwargs("desc-1", description="the human readable log line"),
    )
    await mssp_session.commit()
    row = (await mssp_session.execute(
        text("SELECT description, ai_assessment FROM alerts WHERE tenant_id = :t"),
        {"t": str(tenant_a.tenant_id)},
    )).mappings().one()
    assert row["description"] == "the human readable log line"
    # ai_assessment retains the rules-based label, not the log line.
    assert row["ai_assessment"] in ("real", "unclear", "likely_fp", "high_conf_fp")


def test_assess_mitre_veto():
    # Low severity that would auto-close, but a MITRE mapping vetoes it.
    assert assess(2, "1234")[0] == "high_conf_fp"
    assert assess(2, "1234", mitre={"techniques": ["Brute Force"]})[0] == "unclear"
    assert assess(2, "1234", mitre={})[0] == "high_conf_fp"
