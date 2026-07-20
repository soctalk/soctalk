#!/usr/bin/env python3
"""Cherry-pick soctalk-goldens cases into the triage eval's golden format.

soctalk never imports soctalk-goldens; the coupling is file-based only. This
reads the goldens-emitted cases.jsonl + gold.jsonl by PATH and converts a
balanced sample into triage verdict cases (evals/golden_alerts.yaml shape) so the
triage eval runs over real benchmark payloads. The org-state narrative in each
goldens case (the authorization evidence) is carried into a finding, and the gold
authorization decision becomes the expected verdict: close -> [close], escalate ->
[escalate, needs_more_info] (absence legitimately routes to needs_more_info).

Usage:
    python bench/goldens_to_triage.py \
        --goldens-dir ../soctalk-goldens/data_golden_seed200_account \
        --n 12 --out /tmp/goldens_triage.yaml
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import yaml


def _severity(level: int) -> str:
    if level >= 12:
        return "critical"
    if level >= 8:
        return "high"
    if level >= 5:
        return "medium"
    return "low"


def _org_state_text(context: str) -> str:
    # Keep the observed activity + org-state facts, drop the goldens rubric so the
    # triage verdict node applies its own decision framework to the evidence.
    marker = "Authorization rules."
    return context.split(marker, 1)[0].strip()


def _convert(case: dict, gold: dict) -> dict:
    alert = case["alert"]
    rule = alert.get("rule", {})
    level = int(rule.get("level", 5))
    agent = (alert.get("agent") or {}).get("name", "unknown")
    decision = gold["decision"]
    expect = ["close"] if decision == "close" else ["escalate", "needs_more_info"]
    return {
        "id": f"goldens-{case['id']}",
        "kind": "verdict",
        "description": rule.get("description", "activity")[:200],
        "iteration_count": 3,
        "investigation": {
            "title": rule.get("description", "activity")[:120],
            "alerts": [{
                "severity": _severity(level),
                "level": level,
                "rule_description": rule.get("description", ""),
                "source": {"agent_name": agent},
            }],
            "enrichments": [],
            "findings": [{
                "severity": _severity(level),
                "description": _org_state_text(case.get("context", "")),
            }],
        },
        "supervisor_assessment": {
            "next_action": "VERDICT",
            "tp_confidence": 0.7,
            "action_reasoning": "authorization evidence gathered; ready to decide",
        },
        "expect": {"verdict_decisions": expect, "confidence_min": 0.5},
    }


def cherry_pick(cases: dict, gold: dict, n: int) -> list[dict]:
    # Deterministic, balanced: skip paraphrases (byte-dupes), then round-robin one
    # case per (decision, flipped_dimension) so the sample spans the trap dimensions
    # instead of clustering on the base case.
    buckets: dict[tuple, list[str]] = {}
    for cid, g in sorted(gold.items()):
        if g["metadata"].get("paraphrase_of"):
            continue
        key = (g["decision"], g["metadata"].get("flipped_dimension"))
        buckets.setdefault(key, []).append(cid)
    picked: list[str] = []
    # alternate close/escalate keys for balance
    keys = sorted(buckets, key=lambda k: (k[1] or "", k[0]))
    while len(picked) < n and any(buckets[k] for k in keys):
        for k in keys:
            if buckets[k]:
                picked.append(buckets[k].pop(0))
                if len(picked) >= n:
                    break
    return [_convert(cases[cid], gold[cid]) for cid in picked]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--goldens-dir",
                    default="../soctalk-goldens/data_golden_seed200_account")
    ap.add_argument("--n", type=int, default=12)
    ap.add_argument("--out", default="/tmp/goldens_triage.yaml")
    args = ap.parse_args()

    d = Path(args.goldens_dir)
    cases = {json.loads(line)["id"]: json.loads(line)
             for line in (d / "cases.jsonl").read_text().splitlines() if line.strip()}
    gold = {json.loads(line)["id"]: json.loads(line)
            for line in (d / "gold.jsonl").read_text().splitlines() if line.strip()}

    converted = cherry_pick(cases, gold, args.n)
    Path(args.out).write_text(yaml.safe_dump({"cases": converted}, sort_keys=False))
    from collections import Counter
    dist = Counter(c["expect"]["verdict_decisions"][0] for c in converted)
    print(f"wrote {len(converted)} cases to {args.out}  (expect: {dict(dist)})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
