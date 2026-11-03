#!/usr/bin/env python3
"""Vendor a deterministic, license-clean snapshot of soctalk-goldens cases
into this repo (issue #72 demo seeding; never depend on a
developer's gitignored data_* dirs).

Reads the sibling checkout's data_m0/ (cases + gold + orgstate), selects a
balanced subset of counterfactual groups, strips anything license-adjacent
(sourced rule descriptions are already stripped upstream; we re-author
titles/descriptions at inject time from our own templates), and writes
corpus/goldens/{cases,gold,orgstate}.jsonl + SHA256SUMS.

Selection is seed-deterministic: same goldens snapshot in → same vendored
subset out. Re-run after regenerating goldens (see soctalk-goldens README;
synthetic path is offline, sourced catalogs need the Modal live-Wazuh).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import random
from collections import defaultdict
from pathlib import Path

DEFAULT_SRC = Path.home() / "Development/wa/soctalk-goldens/data_m0"
OUT = Path(__file__).parent / "corpus" / "goldens"

# Per-family group quotas: balanced across rules and, within traps, split
# between paperwork contradictions (guard-veto family) and
# actor-genuine-false (scripted-escalation family) per review item C3.
GROUPS_PER_RULE = 6


def load_jsonl(p: Path) -> list[dict]:
    return [json.loads(line) for line in p.read_text().splitlines() if line.strip()]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--src", type=Path, default=DEFAULT_SRC)
    ap.add_argument("--seed", type=int, default=72)
    args = ap.parse_args()

    cases = {c["id"]: c for c in load_jsonl(args.src / "cases.jsonl")}
    gold = {g["id"]: g for g in load_jsonl(args.src / "gold.jsonl")}
    org = {o["id"]: o for o in load_jsonl(args.src / "orgstate.jsonl")}

    by_group: dict[str, list[str]] = defaultdict(list)
    for cid, g in gold.items():
        by_group[g["metadata"]["counterfactual_group"]].append(cid)

    # Bucket groups by hosting rule id.
    def rule_of(group_ids: list[str]) -> str:
        alert = cases[group_ids[0]]["alert"]
        return str(alert.get("rule", {}).get("id", "?"))

    groups_by_rule: dict[str, list[str]] = defaultdict(list)
    for grp, ids in sorted(by_group.items()):
        groups_by_rule[rule_of(ids)].append(grp)

    rng = random.Random(args.seed)
    selected_groups: list[str] = []
    for rule, groups in sorted(groups_by_rule.items()):
        pick = sorted(groups)
        rng.shuffle(pick)
        selected_groups.extend(pick[:GROUPS_PER_RULE])

    selected_ids = sorted(
        cid for grp in selected_groups for cid in by_group[grp]
    )

    OUT.mkdir(parents=True, exist_ok=True)
    manifests = {}
    for name, table in (
        ("cases.jsonl", cases),
        ("gold.jsonl", gold),
        ("orgstate.jsonl", org),
    ):
        rows = [table[cid] for cid in selected_ids if cid in table]
        body = "\n".join(json.dumps(r, sort_keys=True) for r in rows) + "\n"
        (OUT / name).write_text(body)
        manifests[name] = hashlib.sha256(body.encode()).hexdigest()

    # Provenance: record the source COMMIT (not a developer-local absolute
    # path) so the snapshot is reproducible and license-traceable. Sourced
    # rule descriptions are stripped upstream and re-authored at inject time.
    src_commit = "unknown"
    try:
        import subprocess

        src_commit = subprocess.check_output(
            ["git", "-C", str(args.src.parent), "rev-parse", "HEAD"],
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
    except Exception:
        pass

    (OUT / "SHA256SUMS").write_text(
        "".join(f"{h}  {n}\n" for n, h in sorted(manifests.items()))
    )
    (OUT / "MANIFEST.json").write_text(
        json.dumps(
            {
                "source_repo": "github.com/soctalk/soctalk-goldens (private)",
                "source_dataset": args.src.name,
                "source_commit": src_commit,
                "license_note": (
                    "Generated benchmark data; sourced Wazuh rule descriptions "
                    "stripped upstream, titles/descriptions re-authored at inject "
                    "time. Regenerate per soctalk-goldens README."
                ),
                "seed": args.seed,
                "groups_per_rule": GROUPS_PER_RULE,
                "rules": {r: len(g) for r, g in sorted(groups_by_rule.items())},
                "selected_groups": len(selected_groups),
                "selected_cases": len(selected_ids),
            },
            indent=2,
        )
        + "\n"
    )
    print(
        f"vendored {len(selected_ids)} cases across {len(selected_groups)} groups "
        f"from {len(groups_by_rule)} rules -> {OUT}"
    )


if __name__ == "__main__":
    main()
