"""Authorization-aware verdict memoization — the replay gate, end-to-end (live Postgres).

A cached high-confidence-FP close is keyed source-blind (source|decoder|template_hash|version),
so it must not replay onto a different source that merely shares the template. With
``authz_aware_memoization`` on, a memo replay is applied ONLY if the CURRENT alert independently
passes source-aware routine authorization (deterministic would_close on its own entity tuple).

Proves: a memo + mature routine on the scanner's tuple closes; the identical template from a new
attacker IP is denied (routine seen_days=0) and promotes to the LLM; malicious signal denies even
with mature history; the flag defaults off (no behaviour change); tenant isolation holds.
"""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from soctalk.core.ir.memoization import record_verdict, shape_key
from soctalk.core.ir.policies import set_tenant_policy
from soctalk.core.ir.triage import triage_event

SKIP_INTEGRATION = os.getenv("SKIP_INTEGRATION", "0") == "1"

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(SKIP_INTEGRATION, reason="needs Postgres"),
]

_DECODER = "web-accesslog"
_THASH = "tmpl-webget"
_NOW = datetime(2026, 7, 20, 22, 40, 0, tzinfo=UTC)
SCANNER_IP = "172.19.0.4"
ATTACKER_IP = "203.0.113.66"


def _ev(seid, *, host="web-01", ip=SCANNER_IP, severity=5, iocs=None, mitre=None, ts=None):
    return dict(
        source="wazuh", rule_id="31101", severity=severity, asset_ids=[host],
        initial_iocs=iocs or [], source_event_id=seid, ts=ts or _NOW, description="GET /",
        evidence={
            "entities": [
                {"type": "host", "value": host, "role": "target"},
                {"type": "ip", "value": ip, "role": "src"},
            ],
            "mitre": mitre or {},
            "decoder": _DECODER, "template_hash": _THASH, "template_version": "1",
            "schema_version": 2,
        },
    )


async def _enable(session, tenant_id, *, authz_aware):
    await set_tenant_policy(session, tenant_id, "verdict_memoization_enabled", True)
    await set_tenant_policy(session, tenant_id, "entity_correlation_enabled", True)
    await set_tenant_policy(session, tenant_id, "authz_routine_shadow_enabled", True)
    await set_tenant_policy(session, tenant_id, "authz_aware_memoization", authz_aware)
    await session.commit()


async def _record_memo(session, tenant_id):
    key = shape_key(source="wazuh", decoder=_DECODER, template_hash=_THASH, template_version="1")
    await record_verdict(session, tenant_id=tenant_id, key=key, decision="close",
                         confidence=0.97, template_hash=_THASH)
    await session.commit()
    return key


async def _seed_routine(session, tenant_id, *, ip=SCANNER_IP, host="web-01", days=6):
    ents = json.dumps([
        {"type": "host", "value": host, "role": "target"},
        {"type": "ip", "value": ip, "role": "src"},
    ])
    for i in range(1, days + 1):
        await session.execute(
            text(
                "INSERT INTO alert_source_events "
                "(id, tenant_id, source, source_event_id, occurred_at, entities, decoder, "
                " template_hash, template_version, schema_version, retention_until) "
                "VALUES (gen_random_uuid(), :t, 'wazuh', :seid, :occ, CAST(:ent AS JSONB), "
                " :dec, :th, '1', 2, now() + interval '90 days')"
            ),
            {"t": str(tenant_id), "seid": f"rt-{ip}-{i}", "occ": _NOW - timedelta(days=i),
             "ent": ents, "dec": _DECODER, "th": _THASH},
        )
    await session.commit()


async def _hit_count(session, tenant_id, key):
    return (
        await session.execute(
            text("SELECT hit_count FROM verdict_cache WHERE tenant_id = :t AND shape_key = :k"),
            {"t": str(tenant_id), "k": key},
        )
    ).scalar_one_or_none()


async def _denied(session, tenant_id):
    return (
        await session.execute(
            text("SELECT count(*) FROM audit_log WHERE tenant_id = :t "
                 "AND action = 'ir.verdict_memoization.replay_denied'"),
            {"t": str(tenant_id)},
        )
    ).scalar_one()


@pytest.fixture(autouse=True)
def _family(monkeypatch):
    monkeypatch.setenv("SOCTALK_AUTHZ_ROUTINE_FAMILIES", _DECODER)
    monkeypatch.setenv("SOCTALK_AUTHZ_ROUTINE_MIN_DAYS", "5")
    monkeypatch.delenv("SOCTALK_AUTHZ_ROUTINE_KILL", raising=False)


async def test_authorized_source_replays_memo(mssp_session: AsyncSession, seed_two_tenants):
    t, _ = seed_two_tenants
    await _enable(mssp_session, t.tenant_id, authz_aware=True)
    key = await _record_memo(mssp_session, t.tenant_id)
    await _seed_routine(mssp_session, t.tenant_id, ip=SCANNER_IP)

    r = await triage_event(mssp_session, tenant_id=t.tenant_id, **_ev("scan"))
    await mssp_session.commit()

    assert r["action"] == "memoized_close"  # authorized routine source -> cached close applies
    assert await _hit_count(mssp_session, t.tenant_id, key) == 1
    assert await _denied(mssp_session, t.tenant_id) == 0


async def test_new_attacker_ip_same_template_is_denied(
    mssp_session: AsyncSession, seed_two_tenants
):
    t, _ = seed_two_tenants
    await _enable(mssp_session, t.tenant_id, authz_aware=True)
    key = await _record_memo(mssp_session, t.tenant_id)
    await _seed_routine(mssp_session, t.tenant_id, ip=SCANNER_IP)  # routine only for the scanner

    # identical template + host, but a NEW external IP -> different tuple, no routine
    r = await triage_event(
        mssp_session, tenant_id=t.tenant_id, **_ev("atk", ip=ATTACKER_IP)
    )
    await mssp_session.commit()

    assert r["action"] != "memoized_close", "attacker sharing the template must not replay"
    assert await _hit_count(mssp_session, t.tenant_id, key) == 0
    assert await _denied(mssp_session, t.tenant_id) == 1


async def test_malicious_signal_blocks_replay_even_with_routine(
    mssp_session: AsyncSession, seed_two_tenants
):
    """An IOC on the current alert blocks the memo replay. This is owned by the
    non-overridable close-floor veto (issue #43), which runs BEFORE the opt-in authz gate —
    malicious signal is blocked regardless of routine history or policy flags."""
    t, _ = seed_two_tenants
    await _enable(mssp_session, t.tenant_id, authz_aware=True)
    await _record_memo(mssp_session, t.tenant_id)
    await _seed_routine(mssp_session, t.tenant_id, ip=SCANNER_IP)

    # the scanner's own tuple has routine, but this instance carries an IOC
    r = await triage_event(
        mssp_session, tenant_id=t.tenant_id,
        **_ev("ioc", iocs=[{"type": "ip", "value": "185.220.101.34"}]),
    )
    await mssp_session.commit()
    assert r["action"] != "memoized_close"
    floor_vetoes = (
        await mssp_session.execute(
            text("SELECT count(*) FROM audit_log WHERE tenant_id = :t "
                 "AND action = 'ir.playbook.close_floor_veto'"),
            {"t": str(t.tenant_id)},
        )
    ).scalar_one()
    assert floor_vetoes >= 1, "an IOC must trip the non-overridable close floor"


async def test_low_severity_denied_replay_does_not_fall_through_to_high_conf_fp(
    mssp_session: AsyncSession, seed_two_tenants
):
    """A denied replay must route to the LLM, NOT get swept up by the cruder high-conf-FP
    auto-close (which fires on low-severity non-MITRE alerts) — else authz gives no
    protection for exactly the low-severity attacker-shares-template case."""
    t, _ = seed_two_tenants
    await _enable(mssp_session, t.tenant_id, authz_aware=True)
    await set_tenant_policy(mssp_session, t.tenant_id, "auto_close_enabled", True)
    await mssp_session.commit()
    await _record_memo(mssp_session, t.tenant_id)
    await _seed_routine(mssp_session, t.tenant_id, ip=SCANNER_IP)

    # severity 2 → assess() returns high_conf_fp/0.95 → would auto-close via the fallback;
    # but it's a NEW attacker IP (no routine) so the memo gate denies → must promote.
    r = await triage_event(
        mssp_session, tenant_id=t.tenant_id, **_ev("lowsev-atk", ip=ATTACKER_IP, severity=2)
    )
    await mssp_session.commit()
    assert r["action"] not in ("memoized_close", "auto_closed"), r
    assert await _denied(mssp_session, t.tenant_id) == 1


async def test_routine_disabled_denies_replay(mssp_session: AsyncSession, seed_two_tenants):
    """authz_aware on but routine shadow scoring NOT eligible (family not enabled) → the gate
    can't confirm authorization → deny (fail-closed), even with mature history."""
    t, _ = seed_two_tenants
    await _enable(mssp_session, t.tenant_id, authz_aware=True)
    await set_tenant_policy(mssp_session, t.tenant_id, "authz_routine_shadow_enabled", False)
    await mssp_session.commit()
    await _record_memo(mssp_session, t.tenant_id)
    await _seed_routine(mssp_session, t.tenant_id, ip=SCANNER_IP)

    r = await triage_event(mssp_session, tenant_id=t.tenant_id, **_ev("routine-off"))
    await mssp_session.commit()
    assert r["action"] != "memoized_close"
    assert await _denied(mssp_session, t.tenant_id) == 1


async def test_flag_off_replays_as_before(mssp_session: AsyncSession, seed_two_tenants):
    """Default (flag off): memoization behaves exactly as today — source-blind replay, no gate."""
    t, _ = seed_two_tenants
    await _enable(mssp_session, t.tenant_id, authz_aware=False)
    key = await _record_memo(mssp_session, t.tenant_id)
    # no routine history at all; with the flag off the memo still replays

    r = await triage_event(mssp_session, tenant_id=t.tenant_id, **_ev("plain", ip=ATTACKER_IP))
    await mssp_session.commit()
    assert r["action"] == "memoized_close"
    assert await _hit_count(mssp_session, t.tenant_id, key) == 1
    assert await _denied(mssp_session, t.tenant_id) == 0


async def test_tenant_isolation(mssp_session: AsyncSession, seed_two_tenants):
    """Tenant A's memo + routine cannot authorize tenant B's identical alert."""
    ta, tb = seed_two_tenants
    await _enable(mssp_session, ta.tenant_id, authz_aware=True)
    await _enable(mssp_session, tb.tenant_id, authz_aware=True)
    await _record_memo(mssp_session, ta.tenant_id)
    await _seed_routine(mssp_session, ta.tenant_id, ip=SCANNER_IP)
    # tenant B has neither a memo nor routine

    r = await triage_event(mssp_session, tenant_id=tb.tenant_id, **_ev("b-scan"))
    await mssp_session.commit()
    assert r["action"] != "memoized_close"  # no memo for B -> no replay at all
