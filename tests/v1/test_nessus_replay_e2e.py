"""End-to-end replay of a real Nessus scan campaign through SocTalk's
correlation logic — self-contained (no Nessus, no live scan, no DB, no LLM).

The corpus ``evals/nessus_scan_alerts.ndjson.gz`` is 2,293 REAL Wazuh alerts
captured from a real multi-host Nessus campaign (see ``evals/nessus-lab/``).
These tests replay it through the *production* functions — the adapter's
``_hit_to_event``, the IR layer's ``alert_signature`` (coalescing) and
``extract_keys`` / ``_STRENGTH`` / ``_HUB_THRESHOLD`` (entity correlation) — and
pin the campaign's correlation behaviour, including the sharp edge that
coalescing is source-blind and can mask a real attack hiding in scan noise.

DB persistence of the coalescing merge (``upsert_alert``) is covered separately
by ``test_triage_attach_reopen.py``; the live LLM verdict is the opt-in test at
the bottom (and the ``evals/nessus_triage_verdict.py`` script).
"""

from __future__ import annotations

import copy
import gzip
import json
import os
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import pytest

from soctalk.core.ir.correlation import _HUB_THRESHOLD, _STRENGTH, extract_keys
from soctalk.core.ir.events import alert_signature
from soctalk_adapter.main import _hit_to_event

CORPUS = Path(__file__).resolve().parents[2] / "evals" / "nessus_scan_alerts.ndjson.gz"
ATTACKER_IP = "203.0.113.66"   # TEST-NET-3 (RFC 5737) — a public, non-scanner source
SCANNER_IP = "172.19.0.4"


# --------------------------------------------------------------------------- helpers


def _raw() -> list[dict]:
    with gzip.open(CORPUS, "rt") as f:
        return [json.loads(x) for x in f.read().splitlines() if x.strip()]


def _events(raw: list[dict]) -> list[dict]:
    evs = [_hit_to_event({"_source": a, "_id": a.get("id")}) for a in raw]
    return [e for e in evs if e is not None]


def _sig(ev: dict) -> str:
    ts = datetime.fromisoformat(ev["ts"].replace("Z", "+00:00"))
    return alert_signature(ev.get("rule_id"), ev.get("asset_ids") or [], ts)


def _forge_attack(raw: list[dict]) -> dict:
    """A real successful web compromise (rule 31106, POST -> 200) from a real
    external attacker, placed in the SAME rule+host+5min bucket the scanner
    already tripped on nessus-target-2."""
    base = next(a for a in raw
                if a["rule"]["id"] == "31106" and a["agent"]["name"] == "nessus-target-2")
    bucket_start = (int(datetime.fromisoformat(
        base["timestamp"].replace("Z", "+00:00")).timestamp()) // 300) * 300
    ts = datetime.fromtimestamp(bucket_start + 90, tz=timezone.utc)
    a = copy.deepcopy(base)
    a["id"] = "9999999999.0000001"
    a["timestamp"] = ts.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "+0000"
    a["data"] = {**a.get("data", {}), "srcip": ATTACKER_IP,
                 "protocol": "POST", "url": "/uploads/shell.php"}
    a["full_log"] = (f'{ATTACKER_IP} - - [{ts.strftime("%d/%b/%Y:%H:%M:%S +0000")}] '
                     '"POST /uploads/shell.php HTTP/1.1" 200 31 "-" "python-requests/2.31"')
    return a


def _src_ip(ev: dict) -> str | None:
    for coll in (ev.get("initial_iocs") or [], ev.get("entities") or []):
        for x in coll:
            if x.get("type") == "ip":
                return x.get("value")
    return None


# --------------------------------------------------------------------- deterministic


def test_scan_corpus_coalesces_to_alert_rows():
    """2,293 real scan alerts collapse to a handful of coalesced rows
    (rule + host + 5-minute bucket)."""
    raw = _raw()
    assert len(raw) == 2293
    evs = _events(raw)
    assert len(evs) == 2293, "adapter should map every captured alert to an event"

    sigs = {_sig(e) for e in evs}
    assert len(sigs) == 31, f"expected 31 coalesced rows, got {len(sigs)}"
    # Massive dedup: the 2,293 raw alerts are ~31 distinct things.
    assert len(sigs) < len(evs) * 0.02


def test_coalescing_is_source_blind_and_masks_a_real_attack():
    """Coalescing keys on rule|host|5min but NOT the source, so a real
    successful-exploit alert from a different attacker IP, in the same bucket
    the scanner tripped, gets the SAME signature — it merges into the scanner's
    row instead of surfacing as its own alert. A source-aware key would split
    it out."""
    raw = _raw()
    attack = _forge_attack(raw)

    scan_ev = _hit_to_event({"_source": next(
        a for a in raw if a["rule"]["id"] == "31106"
        and a["agent"]["name"] == "nessus-target-2"), "_id": "x"})
    attack_ev = _hit_to_event({"_source": attack, "_id": attack["id"]})

    # Different sources...
    assert _src_ip(scan_ev) == SCANNER_IP
    assert _src_ip(attack_ev) == ATTACKER_IP
    # ...identical coalescing signature (source-blind).
    assert _sig(scan_ev) == _sig(attack_ev)

    base_sigs = {_sig(e) for e in _events(raw)}
    with_attack_sigs = {_sig(e) for e in _events(raw + [attack])}
    # The attack adds NO new alert row — it is masked inside the scanner's row.
    assert with_attack_sigs == base_sigs

    # A source-aware signature WOULD have given the attacker its own row.
    src_aware = {(_sig(e), _src_ip(e)) for e in _events(raw + [attack])}
    assert len(src_aware) == len(base_sigs) + 1


def test_scanner_ip_hub_demotes_while_host_key_stays_strong():
    """The busy scanner IP is a conditional key seen on every alert, so it
    hub-demotes (>_HUB_THRESHOLD) and stops collapsing the campaign; grouping
    falls to the strong per-host key (one case per scanned host)."""
    evs = _events(_raw())
    sightings: Counter = Counter()
    for e in evs:
        for kt, kv, _ in extract_keys(entities=e.get("entities"),
                                      initial_iocs=e.get("initial_iocs"),
                                      rule_id=e.get("rule_id")):
            sightings[(kt, kv)] += 1

    assert _STRENGTH.get("ip") == "conditional"
    assert _STRENGTH.get("host") == "strong"
    assert sightings[("ip", SCANNER_IP)] > _HUB_THRESHOLD  # 2293 > 200 -> demoted

    hosts = {e2["value"] for e in evs for e2 in (e.get("entities") or [])
             if e2.get("type") == "host"}
    assert hosts == {"nessus-target-1", "nessus-target-2", "nessus-target-3"}


# --------------------------------------------------------------- opt-in live LLM

_LIVE = os.getenv("SOCTALK_NESSUS_VERDICT_LIVE", "0") == "1"


@pytest.mark.skipif(
    not _LIVE,
    reason="live verdict: set SOCTALK_NESSUS_VERDICT_LIVE=1 + a reasoning endpoint "
           "(SOCTALK_REASONING_MODEL / OPENAI_BASE_URL) — costs LLM tokens",
)
async def test_verdict_recovers_needle_via_enrichment():
    """The needle coalescing buried is recoverable through the enrichment
    channel: with an alert view indistinguishable from benign scan noise, one
    malicious enrichment on the attacker IP makes the real verdict node
    escalate rather than close. (Qwen3-14B: 3/3 escalate @0.85 in dev.)"""
    from soctalk.config import get_config
    from soctalk.supervisor.verdict import _build_verdict_context, _get_verdict

    raw = _raw()
    # coalesced rows -> verdict-context alerts (severity-ordered)
    groups: dict[str, dict] = {}
    for a in raw:
        ev = _hit_to_event({"_source": a, "_id": a.get("id")})
        if ev is None:
            continue
        g = groups.setdefault(_sig(ev), {"level": 0, "desc": "", "host": "", "ts": ""})
        if a["rule"]["level"] >= g["level"]:
            g.update(level=a["rule"]["level"], desc=a["rule"]["description"],
                     host=a["agent"]["name"], ts=a["timestamp"])
    alerts = sorted(
        ({"severity": "medium" if g["level"] >= 7 else "low", "level": g["level"],
          "rule_description": g["desc"], "source": {"agent_name": g["host"]},
          "timestamp": g["ts"]} for g in groups.values()),
        key=lambda x: -x["level"],
    )
    enrich = [
        {"verdict": "benign", "observable": {"type": "ip", "value": SCANNER_IP},
         "analyzer": "AbuseIPDB", "confidence": 0.15},
        {"verdict": "malicious", "observable": {"type": "ip", "value": ATTACKER_IP},
         "analyzer": "AbuseIPDB", "confidence": 0.94},
    ]
    state = {
        "investigation": {"id": "nessus-attack", "alerts": alerts,
                          "enrichments": enrich, "findings": []},
        "supervisor_decision": {"next_action": "VERDICT", "tp_confidence": 0.3},
        "iteration_count": 3,
        "started_at": datetime.now(timezone.utc).isoformat(),
    }
    verdict = await _get_verdict(get_config(), _build_verdict_context(state))
    assert verdict.decision.value == "escalate"
