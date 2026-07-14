#!/usr/bin/env python
"""Drive the REAL verdict node over the coalesced Nessus campaign — and test
whether triage can find a real attack that coalescing buried in scan noise.

Builds the verdict-node context exactly as production does (soctalk.supervisor
.verdict._build_verdict_context / _get_verdict — same prompt, schema, LLM
factory) from the real captured corpus, then runs three scenarios:

  A. BENIGN (control)   — the coalesced scan rows, no malicious enrichment.
                          Intended disposition: close (benign).
  B. ATTACK, enriched   — identical alert rows (the injected 200-success
                          exploit coalesced into the scanner's 31106 row, so it
                          adds NO row), but its source IP 203.0.113.66 — seeded
                          as an investigation IOC on promotion (triage.py:340) —
                          reaches the verdict context as ONE malicious
                          enrichment. Does the LLM escalate on it?
  C. ATTACK, missed     — analytic, not a separate LLM call: if enrichment does
                          NOT flag the IP, B's context collapses to A's exactly
                          (the alert view is identical), so the verdict is A's by
                          construction — the needle is lost.

So B is the whole question: with the alert view indistinguishable from benign
scan noise, can a single malicious enrichment make triage decline to close?

    python evals/nessus_triage_verdict.py --dry-run     # print contexts, no LLM
    python evals/nessus_triage_verdict.py --trials 3    # live (needs an LLM)

LLM comes from get_config() / env (SOCTALK_REASONING_MODEL + provider, or
OPENAI_BASE_URL for a self-hosted endpoint) — same as the golden triage evals.
"""
from __future__ import annotations

import argparse
import asyncio
import gzip
import json
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

from soctalk.core.ir.events import alert_signature
from soctalk_adapter.main import _hit_to_event

CORPUS = Path(__file__).resolve().parent / "nessus_scan_alerts.ndjson.gz"
ATTACKER_IP = "203.0.113.66"
SCANNER_IP = "172.19.0.4"


def _sev(level: int) -> str:
    # Standard Wazuh-ish banding. The scan tops out at level 10 -> nothing here
    # is worse than "medium", which is exactly why it reads as benign.
    if level >= 15:
        return "critical"
    if level >= 12:
        return "high"
    if level >= 7:
        return "medium"
    return "low"


def _coalesced_alerts() -> list[dict]:
    """Collapse the real corpus into alert ROWS the way production coalescing
    does (one row per rule+host+5min signature) and render each as a
    verdict-context alert dict, severity-ordered (most severe first)."""
    raw = [json.loads(x) for x in gzip.open(CORPUS, "rt").read().splitlines() if x.strip()]
    groups: dict[str, dict] = {}
    for a in raw:
        ev = _hit_to_event({"_source": a, "_id": a.get("id")})
        if ev is None:
            continue
        ts = datetime.fromisoformat(ev["ts"].replace("Z", "+00:00"))
        sig = alert_signature(ev.get("rule_id"), ev.get("asset_ids") or [], ts)
        g = groups.setdefault(sig, {"level": 0, "count": 0, "desc": "", "host": "", "ts": ""})
        g["count"] += 1
        lvl = a["rule"]["level"]
        if lvl >= g["level"]:
            g["level"] = lvl
            g["desc"] = a["rule"]["description"]
            g["host"] = a["agent"]["name"]
            g["ts"] = a["timestamp"]
    alerts = [
        {
            "severity": _sev(g["level"]),
            "level": g["level"],
            "rule_description": g["desc"],
            "source": {"agent_name": g["host"]},
            "timestamp": g["ts"],
            "_event_count": g["count"],   # not rendered by the verdict context
        }
        for g in groups.values()
    ]
    alerts.sort(key=lambda x: -x["level"])
    return alerts


def _scenarios():
    alerts = _coalesced_alerts()

    # The scanner IP is a real observable on every row; in the lab it's an
    # internal-net address, enriched benign/unknown — nothing alarming.
    benign_enrich = [
        {"verdict": "benign", "observable": {"type": "ip", "value": SCANNER_IP},
         "analyzer": "AbuseIPDB", "confidence": 0.15},
    ]
    # Same corpus + the injected exploit: it coalesced into the 31106 row (no new
    # alert), but its src IP was seeded as an IOC and enrichment flagged it.
    attack_enrich = benign_enrich + [
        {"verdict": "malicious", "observable": {"type": "ip", "value": ATTACKER_IP},
         "analyzer": "AbuseIPDB", "confidence": 0.94},
    ]
    # Identical supervisor routing for both: the alert view is the same, so a
    # router would route the same. Isolating the verdict node's use of the lone
    # malicious enrichment is the point.
    supervisor = {
        "next_action": "VERDICT", "tp_confidence": 0.3,
        "confidence_reasoning": "High-volume web probes from a single source across "
        "three hosts — consistent with a vulnerability scan.",
    }
    return {
        "A_benign": {"alerts": alerts, "enrichments": benign_enrich, "supervisor": supervisor},
        "B_attack_enriched": {"alerts": alerts, "enrichments": attack_enrich, "supervisor": supervisor},
    }


def _state(scn: dict, name: str) -> dict:
    started = datetime.now(timezone.utc) - timedelta(minutes=5)
    return {
        "investigation": {
            "id": f"nessus-{name}",
            "alerts": scn["alerts"],
            "enrichments": scn["enrichments"],
            "findings": [],
        },
        "supervisor_decision": scn["supervisor"],
        "iteration_count": 3,
        "started_at": started.isoformat(),
    }


async def _run(name: str, scn: dict, trials: int) -> None:
    from soctalk.config import get_config
    from soctalk.supervisor.verdict import _build_verdict_context, _get_verdict

    config = get_config()
    ctx = _build_verdict_context(_state(scn, name))
    print(f"\n----- {name}: {trials} trial(s) -----")
    for i in range(trials):
        try:
            v = await _get_verdict(config, ctx)
            print(f"  trial {i+1}: decision={v.decision.value:14s} conf={v.confidence:.2f} "
                  f"impact={v.potential_impact.value} urgency={v.urgency.value}")
            print(f"           threat: {v.threat_assessment[:100]}")
            if v.decision.value == "escalate":
                print(f"           key_evidence: {v.key_evidence[:2]}")
        except Exception as e:  # noqa: BLE001
            print(f"  trial {i+1}: ERROR {type(e).__name__}: {str(e)[:160]}")


def _dry_run(scns: dict) -> None:
    from soctalk.supervisor.verdict import _build_verdict_context
    for name, scn in scns.items():
        ctx = _build_verdict_context(_state(scn, name))
        print(f"\n===== {name} — verdict context =====")
        print(f"alert_count={ctx['alert_count']}  enrichment_count={ctx['enrichment_count']}")
        print("--- alerts_detail (what the LLM sees for alerts) ---")
        print(ctx["alerts_detail"])
        print("--- enrichments_detail ---")
        print(ctx["enrichments_detail"])


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true", help="print contexts, no LLM")
    ap.add_argument("--trials", type=int, default=3)
    args = ap.parse_args()

    scns = _scenarios()
    a = scns["A_benign"]["alerts"]
    merged = next((x for x in a if x["rule_description"].startswith("A web attack returned")), None)
    print(f"coalesced corpus -> {len(a)} alert rows (severity-ordered); "
          f"top level={a[0]['level']} ({a[0]['severity']})")
    if merged:
        print(f"the 31106 'returned 200' row: level {merged['level']} ({merged['severity']}), "
              f"event_count={merged['_event_count']} — the injected exploit hides in this count")
    print(f"A and B alert views identical? "
          f"{scns['A_benign']['alerts'] == scns['B_attack_enriched']['alerts']}  "
          f"(only enrichments differ: B adds 1 malicious IP {ATTACKER_IP})")

    if args.dry_run:
        _dry_run(scns)
        return 0

    async def go():
        for name in ("A_benign", "B_attack_enriched"):
            await _run(name, scns[name], args.trials)
    asyncio.run(go())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
