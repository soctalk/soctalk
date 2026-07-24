#!/usr/bin/env python3
"""Generate the frontend's static ATT&CK lookup (issue #71).

Wazuh emits ``rule.mitre`` as three flat, unpaired arrays (ids / tactic
names / technique names), so the UI needs its own technique->tactic pairing
to render the evidence rail. This distills the enterprise ATT&CK STIX
bundle into a compact JSON the frontend imports statically.

Usage:
    curl -sLo /tmp/enterprise-attack.json \
        https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json
    uv run python scripts/gen-attack-lookup.py /tmp/enterprise-attack.json

Writes frontend/src/lib/mitre/attack-lookup.json (deterministic: sorted
keys, compact separators) — commit the regenerated file when bumping the
pinned ATT&CK version.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

OUT = Path(__file__).resolve().parents[1] / "frontend" / "src" / "lib" / "mitre" / "attack-lookup.json"
DESC_CAP = 240


def _attack_id(obj: dict) -> str | None:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id")
    return None


def _first_sentence(text: str) -> str:
    # Strip markdown links, citations, and code spans; keep the first sentence.
    text = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", text or "")
    text = re.sub(r"\(Citation:[^)]*\)", "", text)
    text = text.replace("<code>", "").replace("</code>", "").strip()
    m = re.match(r"(.+?[.!?])(?:\s|$)", text, re.S)
    out = (m.group(1) if m else text).strip()
    if len(out) > DESC_CAP:
        out = out[: DESC_CAP - 1].rstrip() + "…"
    return out


def main() -> None:
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    bundle = json.loads(Path(sys.argv[1]).read_text())
    objects = bundle["objects"]

    version = next(
        (o.get("x_mitre_version") for o in objects if o["type"] == "x-mitre-collection"),
        "unknown",
    )

    # Tactics: shortname (kill_chain_phases key) -> TA id + display name.
    tactics_by_stix: dict[str, dict] = {}
    tactics_by_short: dict[str, dict] = {}
    for o in objects:
        if o["type"] != "x-mitre-tactic":
            continue
        tid = _attack_id(o)
        if not tid:
            continue
        entry = {"id": tid, "name": o["name"], "short": o["x_mitre_shortname"]}
        tactics_by_stix[o["id"]] = entry
        tactics_by_short[o["x_mitre_shortname"]] = entry

    # Canonical column order comes from the enterprise matrix, not sorting.
    matrix = next(o for o in objects if o["type"] == "x-mitre-matrix")
    tactic_order = [
        {"id": tactics_by_stix[ref]["id"], "name": tactics_by_stix[ref]["name"]}
        for ref in matrix["tactic_refs"]
        if ref in tactics_by_stix
    ]

    techniques: dict[str, dict] = {}
    for o in objects:
        if o["type"] != "attack-pattern":
            continue
        tid = _attack_id(o)
        if not tid:
            continue
        entry: dict = {
            "name": o["name"],
            "tactics": sorted(
                {
                    tactics_by_short[p["phase_name"]]["id"]
                    for p in o.get("kill_chain_phases", [])
                    if p.get("kill_chain_name") == "mitre-attack"
                    and p["phase_name"] in tactics_by_short
                }
            ),
            "desc": _first_sentence(o.get("description", "")),
        }
        if o.get("x_mitre_is_subtechnique"):
            entry["parent"] = tid.split(".")[0]
        if o.get("x_mitre_deprecated") or o.get("revoked"):
            entry["deprecated"] = True
        techniques[tid] = entry

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(
        json.dumps(
            {"version": version, "tactics": tactic_order, "techniques": techniques},
            separators=(",", ":"),
            sort_keys=True,
            ensure_ascii=False,
        )
        + "\n"
    )
    print(f"{OUT}: v{version}, {len(tactic_order)} tactics, {len(techniques)} techniques")


if __name__ == "__main__":
    main()
