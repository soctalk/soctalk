"""Generate evals/golden_authorization.yaml from soctalk-goldens dataset files.

Consumes benchmark FILES only (cases.jsonl + gold.jsonl + orgstate.jsonl) — never imports the
soctalk-goldens package. The source datasets must be generated from RESERVED seed 200 (never
used for prompt tuning; §9 split hygiene):

    cd ../soctalk-goldens
    python -m soctalk_goldens generate --seed 200 --groups 1 --out data_golden_seed200_account/
    python -m soctalk_goldens generate --fim-catalog data/fim_catalog.jsonl \
        --seed 200 --groups 1 --out data_golden_seed200_fim/

    python scripts/make_golden_authorization.py \
        --account-data ../soctalk-goldens/data_golden_seed200_account \
        --fim-data ../soctalk-goldens/data_golden_seed200_fim \
        --out evals/golden_authorization.yaml

Picks one plain-render case per whitelisted flipped dimension per track (12 + 12) and appends
two hand-authored §8.2 override cases (covering authorization + malicious enrichment MUST still
escalate). Expect policy: gold close -> [close]; escalate from contradicted paperwork ->
[escalate]; escalate from pure absence -> [escalate, needs_more_info] (the product's third
class is exactly right for genuinely-missing evidence).

Manual-run only; the output YAML is committed. Scoring costs tokens:
    python -m soctalk.evals.triage --golden evals/golden_authorization.yaml --json
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from soctalk.authorization.adapter import facts_from_row  # noqa: E402
from soctalk.models.authorization import AuthorizationContext  # noqa: E402
from soctalk.models.enums import Severity  # noqa: E402

ACCOUNT_DIMS = [
    "base", "ticket_absent", "window", "host", "expiry", "multi_record",
    "policy", "waiver", "freeze_active", "freeze_exception", "routine_scanner", "break_glass_ok",
]
FIM_DIMS = [
    "base", "cr_absent", "path_mismatch", "cab_not_approved", "baseline", "baseline_frozen",
    "freeze_exception", "policy", "waiver", "path_contained", "multi_record", "security_forbidden",
]
ABSENCE_DIMS = {"ticket_absent", "cr_absent"}


def _load(d: Path) -> tuple[dict[str, dict], dict[str, dict], dict[str, dict]]:
    def rows(name: str) -> dict[str, dict]:
        return {
            j["id"]: j
            for j in (
                json.loads(x) for x in (d / name).read_text().splitlines() if x.strip()
            )
        }

    return rows("cases.jsonl"), rows("gold.jsonl"), rows("orgstate.jsonl")


def _alert_entry(alert: dict[str, Any]) -> dict[str, Any]:
    level = int(alert.get("rule", {}).get("level", 0))
    return {
        "severity": Severity.from_wazuh_level(level).value,
        "level": level,
        "rule_description": alert.get("rule", {}).get("description", ""),
        "source": {"agent_name": alert.get("agent", {}).get("name", "unknown")},
        "timestamp": alert.get("timestamp", ""),
    }


def _expect(gold: dict[str, Any]) -> dict[str, Any]:
    dim = gold["metadata"]["flipped_dimension"]
    if gold["decision"] == "close":
        return {"verdict_decisions": ["close"]}
    if dim in ABSENCE_DIMS:
        return {"verdict_decisions": ["escalate", "needs_more_info"]}
    return {"verdict_decisions": ["escalate"]}


def _pick(golds: dict[str, dict], dims: list[str]) -> list[dict]:
    picked = []
    for dim in dims:
        match = next(
            (
                g
                for g in golds.values()
                if g["metadata"]["flipped_dimension"] == dim
                and g["metadata"]["render_style"] == "plain"
                and not g["metadata"].get("paraphrase_of")
            ),
            None,
        )
        if match is None:
            raise SystemExit(f"no plain case for dimension {dim!r} — regenerate the dataset")
        picked.append(match)
    return picked


def _build_case(gold: dict, cases: dict[str, dict], org_rows: dict[str, dict]) -> dict[str, Any]:
    row = org_rows[gold["id"]]
    alert = cases[gold["id"]]["alert"]
    activity, facts = facts_from_row(row)
    ctx = AuthorizationContext(activity=activity, facts=facts)
    track = row["track"]
    dim = gold["metadata"]["flipped_dimension"]
    trap = " (trap)" if gold["metadata"]["is_trap"] else ""
    subject = activity.path if track == "fim" else f"{activity.account}@{activity.host}"
    return {
        "id": f"authz-{track}-{dim.replace('_', '-')}-{gold['id'][:6]}",
        "kind": "verdict",
        "description": f"{track}/{dim}{trap} — gold: {gold['decision']}",
        "iteration_count": 2,
        "investigation": {
            "title": f"Authorization review: {activity.action or activity.change_type.value} "
                     f"on {subject}",
            "alerts": [_alert_entry(alert)],
            "enrichments": [],
            "findings": [],
            "observables": [],
            "authorization_context": ctx.model_dump(mode="json", exclude_none=True),
        },
        "supervisor_assessment": {
            "next_action": "VERDICT",
            "tp_confidence": 0.5,
            "action_reasoning": "Authorization evidence gathered; ready for verdict",
        },
        "expect": _expect(gold),
    }


def _override_case(base_case: dict[str, Any], track: str) -> dict[str, Any]:
    """§8.2 axis: a fully covering grant + malicious enrichment must STILL escalate."""
    case = json.loads(json.dumps(base_case))  # deep copy
    case["id"] = f"authz-override-{track}"
    case["description"] = (
        f"{track}: covering authorization + malicious IOC — authorization must never "
        "override malicious signal (guardrail §8.2); gold: escalate"
    )
    case["investigation"]["enrichments"] = [
        {
            "observable": {"type": "ip", "value": "185.220.101.34"},
            "verdict": "malicious",
            "analyzer": "VirusTotal",
            "confidence": 0.97,
        }
    ]
    case["investigation"]["misp_context"] = {
        "checked_iocs": ["185.220.101.34"],
        "matches": [{"value": "185.220.101.34", "type": "ip", "to_ids": True,
                     "event_ids": ["31337"]}],
        "threat_actors": ["FIN12"],
        "campaigns": [],
        "warninglist_hits": [],
    }
    case["expect"] = {"verdict_decisions": ["escalate"], "confidence_min": 0.5}
    return case


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--account-data", required=True, type=Path)
    parser.add_argument("--fim-data", required=True, type=Path)
    parser.add_argument("--out", type=Path,
                        default=Path(__file__).resolve().parents[1] / "evals"
                        / "golden_authorization.yaml")
    args = parser.parse_args(argv)

    out_cases: list[dict[str, Any]] = []
    base_by_track: dict[str, dict[str, Any]] = {}
    for d, dims, track in ((args.account_data, ACCOUNT_DIMS, "account"),
                           (args.fim_data, FIM_DIMS, "fim")):
        cases, golds, org_rows = _load(d)
        for gold in _pick(golds, dims):
            built = _build_case(gold, cases, org_rows)
            out_cases.append(built)
            if gold["metadata"]["flipped_dimension"] == "base":
                base_by_track[track] = built
    for track in ("account", "fim"):
        out_cases.append(_override_case(base_by_track[track], track))

    try:
        goldens_rev = subprocess.run(
            ["git", "-C", str(args.account_data.resolve().parent), "rev-parse", "--short", "HEAD"],
            capture_output=True, text=True, check=True,
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        goldens_rev = "unknown"

    header = (
        "# Authorization/expectedness golden set (epic M1) — a SEPARATE eval axis from\n"
        "# golden_alerts.yaml. Generated by scripts/make_golden_authorization.py from\n"
        f"# soctalk-goldens rev {goldens_rev}, reserved seed 200 — do not hand-edit.\n"
        "# Expect policy: gold close -> [close]; contradicted paperwork -> [escalate];\n"
        "# pure absence -> [escalate, needs_more_info]; authz-override-* -> [escalate] (§8.2).\n"
        "# Score (costs tokens): python -m soctalk.evals.triage "
        "--golden evals/golden_authorization.yaml\n"
    )
    args.out.write_text(header + yaml.safe_dump({"cases": out_cases}, sort_keys=False,
                                                width=100, allow_unicode=True))
    print(f"wrote {len(out_cases)} cases -> {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
