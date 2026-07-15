"""Red-team the SIEM-routine shadow scorer against the soctalk-goldens benchmark (M2 gate).

Instead of waiting for live shadow-mode traffic, this replays the benchmark's deterministically
labelled, adversarially-decorrelated cases through the SHADOW SCORER'S decision logic and reports
its false-negative rate — a would_close on a gold=escalate case. Zero FN on this set is a hard
prerequisite for M2 Phase b (auto-close), and the benchmark's trap classes (ioc_sighting,
actor_compromised, evidence_stale_owner, low-and-slow counterfactuals) are exactly the red-team
surface §7 names.

soctalk never imports soctalk_goldens — this reads its emitted dataset FILES (orgstate.jsonl +
gold.jsonl + cases.jsonl) from a directory given on the CLI. Account-track only (the shadow
scorer is host-auth; FIM has no routine analog).

    python -m soctalk.evals.authz_shadow_redteam --data ../soctalk-goldens/data_parity_account
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any

from soctalk.core.ir.authz_shadow import ShadowSettings, evaluate_shadow


def _rows(path: Path) -> dict[str, dict[str, Any]]:
    return {
        r["id"]: r
        for r in (json.loads(x) for x in path.read_text().splitlines() if x.strip())
    }


def _matching_observation(org: dict[str, Any], activity: dict[str, Any]) -> dict[str, Any] | None:
    for o in org.get("observations", []):
        if (
            o.get("account") == activity.get("account")
            and o.get("host") == activity.get("host")
            and o.get("action") == activity.get("action")
        ):
            return dict(o)
    return None


def run_redteam(
    data_dir: Path, *, ignore_history_ioc: bool = False, relax_mitre: bool = False
) -> dict[str, Any]:
    org_states = _rows(data_dir / "orgstate.jsonl")
    gold = _rows(data_dir / "gold.jsonl")
    cases = _rows(data_dir / "cases.jsonl")

    # score the pure logic — enable every decoder + generous max_severity so the eval measures
    # the DECISION, not the family gate (which is a deployment control, tested elsewhere).
    settings = ShadowSettings(
        families=frozenset({"__all__"}), min_days=5, max_severity=15, lookback_days=3650
    )

    scored = 0
    would_close = 0
    false_negatives: list[dict[str, Any]] = []
    fn_dims: Counter[str] = Counter()
    n_escalate = 0

    for cid, row in org_states.items():
        if row.get("track") != "account":
            continue
        activity = row["activity"]
        org = row["org_state"]
        g = gold[cid]
        alert = cases[cid]["alert"]
        rule = alert.get("rule", {})

        obs = _matching_observation(org, activity)
        seen_days = int(obs.get("seen_count", 0)) if obs else 0
        history_ioc = bool(obs.get("ioc")) if obs else False
        # goldens carries the threat-intel signal on the SIGHTING, not as an alert-level IOC
        # (data.* is srcip/dstuser, never a TI hit) — that asymmetry is the whole red-team point.
        initial_iocs = [i for i in alert.get("data", {}).get("iocs", []) if i]

        result = evaluate_shadow(
            seen_days=seen_days,
            severity=int(rule.get("level", 0)),
            # --relax-mitre is a DIAGNOSTIC: every synthetic goldens alert is MITRE-tagged, so
            # the blanket MITRE exclusion closes nothing on this data (FN=0 trivially, by
            # uselessness). Relaxing it isolates the routine/IOC-taint dimension the red-team
            # set actually tests. It does NOT reflect production config.
            mitre=None if relax_mitre else rule.get("mitre"),
            initial_iocs=initial_iocs,
            host=activity["host"],
            account=activity["account"],
            action=activity["action"],
            ts=datetime.fromisoformat(activity["time"].replace("Z", "+00:00")),
            settings=settings,
            history_ioc=False if ignore_history_ioc else history_ioc,
        )
        if g["decision"] == "escalate":
            n_escalate += 1
        if result["would_close"]:
            scored += 1
            would_close += 1
            if g["decision"] == "escalate":
                dim = g["metadata"]["flipped_dimension"]
                fn_dims[dim] += 1
                false_negatives.append(
                    {"id": cid, "dimension": dim, "seen_days": seen_days,
                     "history_ioc": history_ioc, "excluded": result["excluded"]}
                )

    return {
        "data_dir": str(data_dir),
        "account_cases": sum(1 for r in org_states.values() if r.get("track") == "account"),
        "gold_escalate": n_escalate,
        "would_close": would_close,
        "false_negatives": len(false_negatives),
        "false_negative_rate": (len(false_negatives) / n_escalate) if n_escalate else 0.0,
        "fn_by_dimension": dict(fn_dims),
        "fn_cases": false_negatives[:50],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--data", required=True, type=Path, help="goldens dataset dir")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--ignore-history-ioc", action="store_true",
                        help="demo the pre-fix gap: ignore the sighting IOC-taint signal")
    parser.add_argument("--relax-mitre", action="store_true",
                        help="diagnostic: drop the MITRE exclusion to isolate routine/IOC-taint "
                             "(every synthetic goldens alert is MITRE-tagged)")
    args = parser.parse_args(argv)

    report = run_redteam(
        args.data,
        ignore_history_ioc=args.ignore_history_ioc,
        relax_mitre=args.relax_mitre,
    )
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(f"account cases:        {report['account_cases']}")
        print(f"gold escalate:        {report['gold_escalate']}")
        print(f"shadow would_close:   {report['would_close']}")
        print(f"FALSE NEGATIVES:      {report['false_negatives']}  "
              f"(rate {report['false_negative_rate']:.4f})")
        if report["fn_by_dimension"]:
            print(f"  by dimension:       {report['fn_by_dimension']}")
    # non-zero FN is a failing M2 gate
    return 1 if report["false_negatives"] else 0


if __name__ == "__main__":
    sys.exit(main())
