"""Authorization PoC on REAL Nessus scan traffic — the canonical dual-use case, end-to-end.

A Nessus vulnerability scan looks like an attack (web probing, port sweeps, cred attempts) but
is AUTHORIZED benign activity from a sanctioned scanner. The authorization question is source:
the SAME alert bytes are benign from the scanner and hostile from an attacker. The SIEM-routine
shadow scorer keys its tuple on the source `ip` entity, so a sanctioned scanner accrues routine
history while a new attacker IP is a fresh, unseen tuple.

Corpus: evals/nessus_scan_alerts.ndjson.gz — 2,293 real Wazuh alerts from a real multi-host
Nessus campaign (scanner 172.19.0.4). Rule 31101 (plain web GET, sev 5, no MITRE, no IOC) is the
benign-scan candidate. Replayed through the production `triage_event` + shadow scorer against a
live Postgres. Demonstrates authorization deterministically separating the sanctioned scanner
from an attacker hiding in the same scan noise:

  - a scanner 31101 GET on a host with mature routine history        -> would_close (authorized)
  - the IDENTICAL 31101 GET from a new external IP (different tuple)  -> escalate (unseen source)
  - a forged web-shell upload from the attacker (higher-sev / IOC)   -> excluded (malicious wins)
"""

from __future__ import annotations

import copy
import gzip
import json
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from soctalk.core.ir.policies import set_tenant_policy
from soctalk.core.ir.triage import triage_event
from soctalk_adapter.main import _hit_to_event

SKIP_INTEGRATION = os.getenv("SKIP_INTEGRATION", "0") == "1"

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(SKIP_INTEGRATION, reason="needs Postgres"),
]

CORPUS = Path(__file__).resolve().parents[2] / "evals" / "nessus_scan_alerts.ndjson.gz"
SCANNER_IP = "172.19.0.4"
ATTACKER_IP = "203.0.113.66"  # TEST-NET-3 (RFC 5737) — a public, non-scanner source
_NOW = datetime(2026, 7, 20, 22, 40, 0, tzinfo=UTC)


def _corpus_events() -> list[dict]:
    raw = [json.loads(x) for x in gzip.open(CORPUS, "rt").read().splitlines() if x.strip()]
    return [e for e in (_hit_to_event({"_source": a, "_id": a.get("id")}) for a in raw) if e]


def _benign_scan(events: list[dict]) -> dict:
    """A real benign scanner web-GET: rule 31101, decoder web-accesslog, sev 5, no MITRE/IOC."""
    return next(e for e in events if e["rule_id"] == "31101")


def _host_of(event: dict) -> str:
    return next(en["value"] for en in event["entities"] if en["type"] == "host")


def _triage_kwargs(event: dict, *, seid: str, ts: datetime, entities=None) -> dict:
    """Map an adapter event into triage_event kwargs (the runs-worker does this in prod)."""
    ents = entities if entities is not None else event["entities"]
    return dict(
        source=event["source"],
        rule_id=event["rule_id"],
        severity=event["severity"],
        asset_ids=list(event.get("asset_ids") or [_host_of(event)]),
        initial_iocs=list(event.get("initial_iocs") or []),
        source_event_id=seid,
        ts=ts,
        description=event.get("description"),
        evidence={
            "entities": ents,
            "mitre": event.get("mitre") or {},
            "decoder": event.get("decoder"),
            "template_hash": event.get("template_hash"),
            "template_version": event.get("template_version"),
            "schema_version": 2,
        },
    )


async def _enable(session, tenant_id, decoder):
    await set_tenant_policy(session, tenant_id, "entity_correlation_enabled", True)
    await set_tenant_policy(session, tenant_id, "authz_routine_shadow_enabled", True)
    await session.commit()


async def _seed_scanner_history(session, tenant_id, event, days=6):
    """Insert `days` of prior scanner activity for this exact tuple (host + scanner IP +
    decoder + template) as source-event telemetry — routine daily scanning."""
    ents = json.dumps(event["entities"])
    for i in range(1, days + 1):
        await session.execute(
            text(
                "INSERT INTO alert_source_events "
                "(id, tenant_id, source, source_event_id, occurred_at, entities, decoder, "
                " template_hash, template_version, schema_version, retention_until) "
                "VALUES (gen_random_uuid(), :t, :src, :seid, :occ, CAST(:ent AS JSONB), "
                " :dec, :th, :tv, 2, now() + interval '90 days')"
            ),
            {
                "t": str(tenant_id),
                "src": event["source"],
                "seid": f"nessus-hist-{i}",
                "occ": _NOW - timedelta(days=i),
                "ent": ents,
                "dec": event["decoder"],
                "th": event["template_hash"],
                "tv": event["template_version"],
            },
        )
    await session.commit()


async def _shadow(session, tenant_id):
    rows = (
        await session.execute(
            text(
                "SELECT notes FROM audit_log WHERE tenant_id = :t "
                "AND action = 'ir.authorization.routine_shadow' ORDER BY timestamp"
            ),
            {"t": str(tenant_id)},
        )
    ).all()
    return [json.loads(r[0]) for r in rows]


async def test_sanctioned_scanner_closes_attacker_escalates(
    mssp_session: AsyncSession, seed_two_tenants
):
    """Same benign Nessus GET shape, opposite disposition by source. Two tenants isolate the
    two source tuples (on one tenant the identical-shape alerts would coalesce into one alert —
    coalescing is source-blind, the documented Nessus 'sharp edge' — so the attacker would be
    masked rather than independently scored)."""
    tenant_a, tenant_b = seed_two_tenants
    scan = _benign_scan(_corpus_events())
    decoder = scan["decoder"]  # web-accesslog
    assert not (scan.get("mitre") or {}).get("ids"), "the benign GET must carry no MITRE"

    os.environ["SOCTALK_AUTHZ_ROUTINE_FAMILIES"] = decoder
    os.environ["SOCTALK_AUTHZ_ROUTINE_MIN_DAYS"] = "5"
    os.environ.pop("SOCTALK_AUTHZ_ROUTINE_KILL", None)
    try:
        # tenant A: the sanctioned scanner has mature routine on this tuple
        await _enable(mssp_session, tenant_a.tenant_id, decoder)
        await _seed_scanner_history(mssp_session, tenant_a.tenant_id, scan)
        await triage_event(
            mssp_session, tenant_id=tenant_a.tenant_id,
            **_triage_kwargs(scan, seid="scan-cand", ts=_NOW),
        )
        await mssp_session.commit()

        # tenant B: the IDENTICAL shape from a NEW external IP — no routine for its tuple
        await _enable(mssp_session, tenant_b.tenant_id, decoder)
        attacker_ents = [
            en if en["type"] != "ip" else {**en, "value": ATTACKER_IP}
            for en in scan["entities"]
        ]
        await triage_event(
            mssp_session, tenant_id=tenant_b.tenant_id,
            **_triage_kwargs(scan, seid="attacker-same-shape", ts=_NOW, entities=attacker_ents),
        )
        await mssp_session.commit()

        scanner_rows = await _shadow(mssp_session, tenant_a.tenant_id)
        scanner = next(
            n for n in scanner_rows
            if any(e["type"] == "ip" and e["value"] == SCANNER_IP for e in n["tuple"]["scope"])
        )
        assert scanner["would_close"] is True, scanner  # authorized benign scan
        assert scanner["seen_days"] >= 5 and scanner["excluded"] == []

        attacker_rows = await _shadow(mssp_session, tenant_b.tenant_id)
        attacker = next(
            n for n in attacker_rows
            if any(e["type"] == "ip" and e["value"] == ATTACKER_IP for e in n["tuple"]["scope"])
        )
        assert attacker["would_close"] is False, "unseen source has no routine -> escalate"
        assert attacker["seen_days"] == 0
    finally:
        for k in ("SOCTALK_AUTHZ_ROUTINE_FAMILIES", "SOCTALK_AUTHZ_ROUTINE_MIN_DAYS"):
            os.environ.pop(k, None)


async def test_forged_webshell_excluded_even_with_scanner_ip(
    mssp_session: AsyncSession, seed_two_tenants
):
    """Malicious signal always wins: a higher-severity web-shell upload is excluded even if it
    rode in on the scanner's IP with mature routine history (authorization never overrides)."""
    tenant_a, _ = seed_two_tenants
    events = _corpus_events()
    scan = _benign_scan(events)
    decoder = scan["decoder"]

    # a real higher-severity web alert (rule 31106, sev 10) — the attack shape
    attack = copy.deepcopy(next(e for e in events if e["severity"] >= 10))

    os.environ["SOCTALK_AUTHZ_ROUTINE_FAMILIES"] = decoder
    os.environ["SOCTALK_AUTHZ_ROUTINE_MIN_DAYS"] = "5"
    os.environ.pop("SOCTALK_AUTHZ_ROUTINE_KILL", None)
    try:
        await _enable(mssp_session, tenant_a.tenant_id, decoder)
        # seed history keyed on the ATTACK's own tuple so seen_days would otherwise be mature
        await _seed_scanner_history(mssp_session, tenant_a.tenant_id, attack)

        await triage_event(
            mssp_session, tenant_id=tenant_a.tenant_id,
            **_triage_kwargs(attack, seid="webshell", ts=_NOW),
        )
        await mssp_session.commit()

        rows = await _shadow(mssp_session, tenant_a.tenant_id)
        assert rows, "the attack alert should have been scored (its decoder is enabled)"
        webshell = rows[-1]
        assert webshell["would_close"] is False
        assert webshell["excluded"], "a higher-severity attack must be excluded from routine"
    finally:
        for k in ("SOCTALK_AUTHZ_ROUTINE_FAMILIES", "SOCTALK_AUTHZ_ROUTINE_MIN_DAYS"):
            os.environ.pop(k, None)
