"""SIEM-routine shadow scoring — end-to-end through the real triage path (epic M2 exit gate).

Proves against a live Postgres that `triage_event` runs the shadow scorer, writes the
`ir.authorization.routine_shadow` audit row, and — the load-bearing part per handoff §7 M2 —
that the malicious/correlation/immaturity overrides hold on the RED-TEAM set (nothing that
should escalate ever scores would_close=True). This is the code proof required before Phase b
(actual auto-close) may be built.
"""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime, timedelta

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

_DECODER = "sshd"
_THASH = "tmpl-abc123"
_NOW = datetime(2026, 7, 20, 3, 0, 12, tzinfo=UTC)


@pytest.fixture(autouse=True)
def _routine_family(monkeypatch):
    # enable the sshd family + a low kill-switch-off config for every test here
    monkeypatch.setenv("SOCTALK_AUTHZ_ROUTINE_FAMILIES", _DECODER)
    monkeypatch.setenv("SOCTALK_AUTHZ_ROUTINE_MIN_DAYS", "5")
    monkeypatch.delenv("SOCTALK_AUTHZ_ROUTINE_KILL", raising=False)


def _ev(
    seid,
    *,
    host="app-01",
    user="svc-a",
    severity=5,
    ts=None,
    iocs=None,
    mitre=None,
    decoder=_DECODER,
    thash=_THASH,
    rule_id="5715",
):
    ent = [
        {"type": "host", "value": host, "role": "target", "source_field": "agent.name"},
        {"type": "user", "value": user, "role": "actor", "source_field": "data.dstuser"},
    ]
    return dict(
        source="wazuh",
        rule_id=rule_id,
        severity=severity,
        asset_ids=[host],
        initial_iocs=iocs or [],
        source_event_id=seid,
        ts=ts or _NOW,
        description="sshd session",
        evidence={
            "entities": ent,
            "mitre": mitre or {},
            "decoder": decoder,
            "template_hash": thash,
            "template_version": "1",
            "schema_version": 2,
        },
    )


async def _enable(session, tenant_id):
    # §8.2: shadow scoring requires entity correlation on (active-incident veto runs first)
    await set_tenant_policy(session, tenant_id, "entity_correlation_enabled", True)
    await set_tenant_policy(session, tenant_id, "authz_routine_shadow_enabled", True)
    await session.commit()


async def _seed_history(session, tenant_id, days=6, host="app-01", user="svc-a"):
    """Insert `days` prior sshd source-event rows on distinct calendar days — telemetry
    history for the same tuple, WITHOUT creating investigations. (Routine daily activity is
    SIEM history; going through triage_event would spin up a live investigation that the
    candidate would then entity-correlate into — the §8.2 path, tested separately.)"""
    ents = json.dumps(
        [
            {"type": "host", "value": host, "role": "target", "source_field": "agent.name"},
            {"type": "user", "value": user, "role": "actor", "source_field": "data.dstuser"},
        ]
    )
    for i in range(1, days + 1):
        await session.execute(
            text(
                "INSERT INTO alert_source_events "
                "(id, tenant_id, source, source_event_id, occurred_at, entities, decoder, "
                " template_hash, template_version, schema_version, retention_until) "
                "VALUES (gen_random_uuid(), :t, 'wazuh', :seid, :occ, CAST(:ent AS JSONB), "
                " :dec, :th, '1', 2, now() + interval '90 days')"
            ),
            {
                "t": str(tenant_id),
                "seid": f"hist-{i}",
                "occ": _NOW - timedelta(days=i),
                "ent": ents,
                "dec": _DECODER,
                "th": _THASH,
            },
        )
    await session.commit()


async def _shadow_rows(session, tenant_id):
    rows = (
        await session.execute(
            text(
                "SELECT resource_id, notes FROM audit_log "
                "WHERE tenant_id = :t AND action = 'ir.authorization.routine_shadow' "
                "ORDER BY timestamp"
            ),
            {"t": str(tenant_id)},
        )
    ).all()
    return [(r[0], json.loads(r[1])) for r in rows]


async def test_mature_routine_scores_would_close_and_logs(
    mssp_session: AsyncSession, seed_two_tenants
):
    """Six prior benign sshd days + a clean candidate -> one shadow row, would_close True,
    disposition unchanged (the alert still promotes; scoring closes NOTHING)."""
    tenant_a, _ = seed_two_tenants
    await _enable(mssp_session, tenant_a.tenant_id)
    await _seed_history(mssp_session, tenant_a.tenant_id)

    result = await triage_event(
        mssp_session, tenant_id=tenant_a.tenant_id, **_ev("cand")
    )
    await mssp_session.commit()

    rows = await _shadow_rows(mssp_session, tenant_a.tenant_id)
    # only the candidate's own scoring row carries would_close True on mature history;
    # the history-seeding events had thin history of their own.
    cand = [n for _, n in rows if n["would_close"] is True]
    assert cand, f"expected a would_close row; got {[n for _, n in rows]}"
    top = cand[-1]
    assert top["seen_days"] >= 5 and top["mature_history"] is True
    assert top["excluded"] == []
    # DISPOSITION SAFETY: scoring changed nothing — the candidate is a normal promotion.
    assert result["action"] in ("promoted", "attached")


async def test_ioc_present_never_would_close(mssp_session: AsyncSession, seed_two_tenants):
    tenant_a, _ = seed_two_tenants
    await _enable(mssp_session, tenant_a.tenant_id)
    await _seed_history(mssp_session, tenant_a.tenant_id)

    await triage_event(
        mssp_session, tenant_id=tenant_a.tenant_id,
        **_ev("cand-ioc", iocs=[{"type": "ip", "value": "185.220.101.34"}]),
    )
    await mssp_session.commit()

    rows = await _shadow_rows(mssp_session, tenant_a.tenant_id)
    # the IOC-carrying candidate has mature history but must be excluded, never would_close
    ioc_rows = [n for _, n in rows if "ioc_present" in n["excluded"]]
    assert ioc_rows and all(n["would_close"] is False for n in ioc_rows)


async def test_mitre_mapped_never_would_close(mssp_session: AsyncSession, seed_two_tenants):
    tenant_a, _ = seed_two_tenants
    await _enable(mssp_session, tenant_a.tenant_id)
    await _seed_history(mssp_session, tenant_a.tenant_id)

    await triage_event(
        mssp_session, tenant_id=tenant_a.tenant_id,
        **_ev("cand-mitre", mitre={"ids": ["T1110"], "tactics": ["Credential Access"]}),
    )
    await mssp_session.commit()

    rows = await _shadow_rows(mssp_session, tenant_a.tenant_id)
    mitre_rows = [n for _, n in rows if "mitre_mapped" in n["excluded"]]
    assert mitre_rows and all(n["would_close"] is False for n in mitre_rows)


async def test_immature_history_never_would_close(
    mssp_session: AsyncSession, seed_two_tenants
):
    """Only 2 prior days -> below min_days=5 -> the candidate scores would_close False."""
    tenant_a, _ = seed_two_tenants
    await _enable(mssp_session, tenant_a.tenant_id)
    await _seed_history(mssp_session, tenant_a.tenant_id, days=2)

    await triage_event(mssp_session, tenant_id=tenant_a.tenant_id, **_ev("cand-thin"))
    await mssp_session.commit()

    rows = await _shadow_rows(mssp_session, tenant_a.tenant_id)
    assert rows, "expected shadow rows"
    assert all(n["would_close"] is False for _, n in rows)
    assert all(n["mature_history"] is False for _, n in rows)


async def test_active_incident_correlation_preempts_scoring(
    mssp_session: AsyncSession, seed_two_tenants
):
    """§8.2: an alert that entity-correlates to a live investigation must attach, NOT be
    scored routine. The shadow hook is after correlation, so a correlated alert writes no
    shadow row."""
    tenant_a, _ = seed_two_tenants
    await _enable(mssp_session, tenant_a.tenant_id)
    await _seed_history(mssp_session, tenant_a.tenant_id)

    # First alert promotes to a live investigation on host app-01.
    r1 = await triage_event(
        mssp_session, tenant_id=tenant_a.tenant_id,
        **_ev("live-1", host="app-01", user="svc-a", severity=9),
    )
    await mssp_session.commit()

    # A different-rule alert sharing the host entity-correlates into it (a different rule_id
    # avoids the coalescing signature so we exercise the entity-correlation branch, not the
    # earlier attach) — and must NOT be scored routine.
    before = len(await _shadow_rows(mssp_session, tenant_a.tenant_id))
    r2 = await triage_event(
        mssp_session, tenant_id=tenant_a.tenant_id,
        **_ev("live-2", host="app-01", user="svc-a", severity=9, rule_id="92657"),
    )
    await mssp_session.commit()
    after = len(await _shadow_rows(mssp_session, tenant_a.tenant_id))

    assert r2["action"] == "correlated"
    assert r2["investigation_id"] == r1["investigation_id"]
    assert after == before, "a correlated alert must not be scored routine (§8.2)"


async def test_kill_switch_and_policy_flag_disable_scoring(
    mssp_session: AsyncSession, seed_two_tenants, monkeypatch
):
    tenant_a, _ = seed_two_tenants
    await _enable(mssp_session, tenant_a.tenant_id)
    await _seed_history(mssp_session, tenant_a.tenant_id)
    before = len(await _shadow_rows(mssp_session, tenant_a.tenant_id))

    monkeypatch.setenv("SOCTALK_AUTHZ_ROUTINE_KILL", "true")
    await triage_event(mssp_session, tenant_id=tenant_a.tenant_id, **_ev("killed"))
    await mssp_session.commit()
    assert len(await _shadow_rows(mssp_session, tenant_a.tenant_id)) == before

    # policy flag off also disables (kill back off)
    monkeypatch.delenv("SOCTALK_AUTHZ_ROUTINE_KILL", raising=False)
    await set_tenant_policy(mssp_session, tenant_a.tenant_id, "authz_routine_shadow_enabled", False)
    await mssp_session.commit()
    await triage_event(mssp_session, tenant_id=tenant_a.tenant_id, **_ev("flagged-off"))
    await mssp_session.commit()
    assert len(await _shadow_rows(mssp_session, tenant_a.tenant_id)) == before
