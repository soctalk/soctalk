#!/usr/bin/env python
"""Adversarial test: does coalescing MASK a real attack hiding in scan noise?

The benign replay (nessus_replay.py) shows the campaign collapsing to ~30
coalesced alert rows. Coalescing keys each row on::

    alert_signature = sha256(rule_id | sorted(asset_ids) | floor(ts / 300s))

Note what is NOT in that key: the *source* of the activity. Two different
actors that trip the same rule on the same target host in the same 5-minute
bucket produce the SAME signature -> they merge into one alert row.

For a benign scan (one scanner) that is harmless dedup. This test probes the
sharp edge: inject ONE genuinely malicious alert -- a *successful* web
exploitation (Wazuh rule 31106, "web attack returned code 200") from a real
external attacker IP -- into the same rule+host+5min bucket the scanner already
tripped, and check whether coalescing gives it its own alert row or swallows it
into the scanner's row.

    python evals/nessus_masking_test.py

Uses the REAL adapter mapping (_hit_to_event) and the REAL coalescing signature
(alert_signature) -- nothing about the merge is re-implemented.
"""
from __future__ import annotations

import copy
import gzip
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from soctalk.core.ir.events import alert_signature
from soctalk_adapter.main import _hit_to_event

CORPUS = Path(__file__).resolve().parent / "nessus_scan_alerts.ndjson.gz"

# The collision target: a rule the scan tripped that a *real* successful attack
# would also trip. 31106 = "A web attack returned code 200 (success)" -- i.e. a
# probe that actually got through. The scan produced a couple of these per host;
# a real exploit that lands is indistinguishable at the rule level.
TARGET_RULE = "31106"
TARGET_HOST = "nessus-target-2"
ATTACKER_IP = "203.0.113.66"   # TEST-NET-3 (RFC 5737) -- a public, non-scanner source


def _read(path: Path):
    with gzip.open(path, "rt") as f:
        return [json.loads(x) for x in f.read().splitlines() if x.strip()]


def _ts_epoch(ts: str) -> float:
    return datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp()


def _sig(ev) -> str:
    ts = datetime.fromtimestamp(_ts_epoch(ev["ts"]), tz=timezone.utc)
    return alert_signature(ev.get("rule_id"), ev.get("asset_ids") or [], ts)


def _forge_attack(scan_alert: dict) -> dict:
    """A real successful compromise, placed in the SAME 5-min bucket as the
    scanner's 31106 hits on the same host, but from a real external attacker."""
    bucket_start = (int(_ts_epoch(scan_alert["timestamp"])) // 300) * 300
    attack_ts = datetime.fromtimestamp(bucket_start + 90, tz=timezone.utc)
    a = copy.deepcopy(scan_alert)
    a["id"] = "9999999999.0000001"          # distinct source event
    a["timestamp"] = attack_ts.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "+0000"
    a["data"]["srcip"] = ATTACKER_IP
    a["data"]["protocol"] = "POST"
    a["data"]["url"] = "/uploads/shell.php"
    # a real webshell drop that returned 200 -- not a scanner 404-fishing probe
    a["full_log"] = (
        f'{ATTACKER_IP} - - [{attack_ts.strftime("%d/%b/%Y:%H:%M:%S +0000")}] '
        '"POST /uploads/shell.php HTTP/1.1" 200 31 "-" "python-requests/2.31"'
    )
    return a


def main() -> int:
    raw = _read(CORPUS)
    scan_hit = next(a for a in raw
                    if a["rule"]["id"] == TARGET_RULE and a["agent"]["name"] == TARGET_HOST)
    attack = _forge_attack(scan_hit)

    scan_ev = _hit_to_event({"_source": scan_hit, "_id": scan_hit["id"]})
    attack_ev = _hit_to_event({"_source": attack, "_id": attack["id"]})

    print("=== adversarial coalescing test: real attack in scan noise ===\n")
    print(f"scanner   31106 on {TARGET_HOST}: srcip={scan_ev and dict((e['type'],e['value']) for e in (scan_ev.get('entities') or []))}")
    print(f"  full_log: {scan_hit['full_log'][:88]}")
    print(f"attacker  31106 on {TARGET_HOST}: srcip={ATTACKER_IP}  (POST /uploads/shell.php -> 200)")
    print(f"  full_log: {attack['full_log']}\n")

    s_scan, s_attack = _sig(scan_ev), _sig(attack_ev)
    print(f"scanner  signature: {s_scan[:16]}...")
    print(f"attacker signature: {s_attack[:16]}...")
    collide = s_scan == s_attack
    print(f"same coalescing signature? {collide}  "
          f"({'MERGE — attack has no row of its own' if collide else 'separate rows'})\n")

    # Coalesce the whole corpus + the injected attack; count rows per signature.
    events = []
    for a in raw + [attack]:
        ev = _hit_to_event({"_source": a, "_id": a.get("id")})
        if ev is not None:
            events.append(ev)
    rows: Counter = Counter()
    for ev in events:
        rows[_sig(ev)] += 1

    n_rows = len(rows)
    landed = rows[s_attack]
    print(f"corpus+attack: {len(events)} events -> {n_rows} coalesced alert rows")
    print(f"the attack landed in a row that now has event_count={landed} "
          f"(scanner 31106s + the 1 real exploit, indistinguishable at row level)")

    # What a source-aware signature would have done instead.
    def src_of(ev):
        for ioc in ev.get("initial_iocs") or []:
            if ioc.get("type") == "ip":
                return ioc.get("value")
        for e in ev.get("entities") or []:
            if e.get("type") == "ip":
                return e.get("value")
        return None

    src_rows = {(_sig(ev), src_of(ev)) for ev in events}
    print(f"\nif the signature also keyed on source IP: {len(src_rows)} rows "
          f"(+{len(src_rows) - n_rows}) — the attacker's {ATTACKER_IP} row would split out.\n")

    # Precise scope of the masking (see src/soctalk/core/ir/triage.py:upsert_alert):
    #  - merge fires only against a same-signature alert still in status='new'
    #    (triage.py:171), or attaches-as-evidence to a still-open, non-FP
    #    investigation (triage.py:199). So masking bites during the live scan
    #    window, not forever.
    #  - on merge the incoming IOC IS appended to the row's initial_iocs
    #    (triage.py:208) — the attacker IP is NOT lost, it is buried.
    #  - but assess() runs only on fresh insert (triage.py:236): the merged row
    #    keeps the scanner probe's benign assessment/severity. The real exploit
    #    gets no row, no re-assessment, no independent investigation/triage.
    print("VERDICT:", "MASKED — coalescing is source-blind: while the scanner's row is\n"
          "         still open, the real 200-success exploit merges into it (event_count++),\n"
          "         inherits its benign assessment, and never gets independently triaged.\n"
          "         Its IOC survives inside initial_iocs, but nothing elevates it."
          if collide else "not masked")
    return 0 if collide else 1


if __name__ == "__main__":
    raise SystemExit(main())
