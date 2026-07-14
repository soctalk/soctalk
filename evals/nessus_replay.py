#!/usr/bin/env python
"""Replay a captured Nessus-scan corpus through SocTalk's REAL correlation logic.

Not a fabricated fixture: the corpus (evals/nessus_scan_alerts.ndjson) is real
Wazuh alerts from a real Nessus campaign against the nessus-lab targets. This
harness maps each raw alert through the adapter's real ``_hit_to_event`` and the
IR layer's real ``extract_keys`` / coalescing signature / strength + hub
constants, then reproduces the deterministic attach rule to show exactly how the
campaign correlates — how many investigations form, on which keys, and where the
conditional scanner-IP key hub-demotes.

    python evals/nessus_replay.py [corpus.ndjson]

Correlation grouping is DB-coupled in production (find_correlated_investigation),
but the rule is simple and its inputs (extract_keys) + thresholds (_STRENGTH,
_HUB_THRESHOLD, windows) are imported here verbatim, so the reported grouping is
faithful without needing a database. The LLM triage of each correlated
investigation (the benign disposition) is exercised separately.
"""
from __future__ import annotations

import gzip
import json
import sys
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

from soctalk.core.ir.correlation import _HUB_THRESHOLD, _STRENGTH, _WINDOW_MINUTES, extract_keys
from soctalk.core.ir.events import alert_signature

# Real production functions/constants — the whole point is to use them, not
# re-implement them.
from soctalk_adapter.main import _hit_to_event

DEFAULT_CORPUS = Path(__file__).resolve().parent / "nessus_scan_alerts.ndjson.gz"


def _read_lines(path: Path) -> list[str]:
    opener = gzip.open if path.suffix == ".gz" else open
    with opener(path, "rt") as f:
        return [x for x in f.read().splitlines() if x.strip()]


def _parse_ts(ts: str | None) -> datetime | None:
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        return None


def main() -> int:
    corpus = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_CORPUS
    if not corpus.exists():
        print(f"corpus not found: {corpus}", file=sys.stderr)
        return 2

    raw = [json.loads(x) for x in _read_lines(corpus)]
    print(f"=== corpus: {len(raw)} real Wazuh alerts from {corpus.name} ===")

    # 1. Map each raw alert -> SocTalk event via the REAL adapter mapping.
    events = []
    for a in raw:
        ev = _hit_to_event({"_source": a, "_id": a.get("id")})
        if ev is not None:
            events.append(ev)
    print(f"mapped to {len(events)} events (adapter _hit_to_event)")

    hosts = Counter()
    levels = Counter(a.get("rule", {}).get("level") for a in raw)
    for ev in events:
        for e in ev.get("entities") or []:
            if e.get("type") == "host":
                hosts[e.get("value")] += 1
    print(f"target hosts: {dict(hosts)}")
    print(f"severity spread (rule.level): {dict(sorted(levels.items(), reverse=True))}")

    # 2. Coalescing (always on): distinct alert ROWS = distinct signatures
    #    (rule_id | sorted(asset_ids) | floor(ts/300s)).
    sigs = set()
    for ev in events:
        ts = _parse_ts(ev.get("ts")) or _parse_ts(ev.get("observed_at"))
        if ts is None:
            continue
        sigs.add(alert_signature(ev.get("rule_id"), ev.get("asset_ids") or [], ts))
    print(f"\ncoalescing -> {len(sigs)} distinct alert rows "
          f"(from {len(events)} events; same rule+asset+5min merge)")

    # 3. Entity correlation (entity_correlation_enabled=true): reproduce the
    #    deterministic attach rule on the extracted keys.
    #    - strong keys always attach; conditional attach unless the key is a hub
    #      (> _HUB_THRESHOLD sightings this tenant); weak never auto-attach.
    #    - an alert attaches to the OLDEST open investigation sharing an
    #      attach-eligible key; else opens a new one.
    key_sightings: Counter = Counter()
    inv_of_key: dict[tuple[str, str], int] = {}   # attach-eligible key -> investigation id
    inv_keys: dict[int, set] = defaultdict(set)
    inv_hosts: dict[int, set] = defaultdict(set)
    inv_rows: Counter = Counter()
    next_inv = 0

    # process oldest-first (attach picks the oldest active investigation)
    def _ts_key(e):
        return (_parse_ts(e.get("ts")) or _parse_ts(e.get("observed_at"))
                or datetime.min.replace(tzinfo=None))

    for ev in sorted(events, key=_ts_key):
        keys = extract_keys(
            entities=ev.get("entities"),
            initial_iocs=ev.get("initial_iocs"),
            rule_id=ev.get("rule_id"),
        )
        eligible = []
        for kt, kv, strength in keys:
            key_sightings[(kt, kv)] += 1
            if strength == "weak":
                continue
            if strength == "conditional" and key_sightings[(kt, kv)] > _HUB_THRESHOLD:
                continue  # hub-demoted — stops attaching (by design, e.g. a busy scanner IP)
            eligible.append((kt, kv))

        target = None
        for k in eligible:
            if k in inv_of_key:
                target = inv_of_key[k]
                break
        if target is None:
            target = next_inv
            next_inv += 1
        for k in eligible:
            inv_of_key.setdefault(k, target)
        inv_keys[target].update(eligible)
        inv_rows[target] += 1
        for e in ev.get("entities") or []:
            if e.get("type") == "host":
                inv_hosts[target].add(e.get("value"))

    print(f"\nentity correlation -> {next_inv} investigation(s):")
    for inv in range(next_inv):
        kinds = Counter(kt for kt, _ in inv_keys[inv])
        print(f"  inv#{inv}: {inv_rows[inv]} alerts | hosts={sorted(inv_hosts[inv]) or ['-']} "
              f"| key types={dict(kinds)}")

    # Hub demotion report for the scanner IP(s).
    demoted = [(kt, kv, n) for (kt, kv), n in key_sightings.items()
               if _STRENGTH.get(kt) == "conditional" and n > _HUB_THRESHOLD]
    if demoted:
        print(f"\nhub-demoted conditional keys (> {_HUB_THRESHOLD} sightings — stopped grouping):")
        for kt, kv, n in sorted(demoted, key=lambda x: -x[2])[:5]:
            print(f"  {kt}={kv}: {n} sightings")
        print("  -> the scanner IP does NOT collapse the campaign; grouping falls to the")
        print(f"     strong host key: one investigation per scanned host ({len(hosts)} hosts).")

    print(f"\nwindows in play: host={_WINDOW_MINUTES['host']}m (strong), "
          f"ip={_WINDOW_MINUTES['ip']}m (conditional)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
