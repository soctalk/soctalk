"""File-fed parity vs the soctalk-goldens benchmark — M1 exit criterion 1.

soctalk never imports the soctalk-goldens package (it is a local-only benchmark repo);
parity runs over its emitted dataset files instead. Point SOCTALK_AUTHZ_PARITY_DATA at one
or more dataset directories (colon-separated), each containing gold.jsonl + orgstate.jsonl
generated from the RESERVED seed range (>=100, never used for prompt tuning):

    python -m soctalk_goldens generate --seed 100 --groups 5 --out data_parity_account/
    python -m soctalk_goldens generate --fim-catalog data/fim_catalog.jsonl \
        --seed 100 --groups 3 --out data_parity_fim/
    SOCTALK_AUTHZ_PARITY_DATA=.../data_parity_account:.../data_parity_fim pytest ...

For every case, the adapter+engine must reproduce the benchmark's four gold component
booleans AND the decision exactly. Skips (with this message) when the env var is unset,
so CI — which has no benchmark checkout — is unaffected; the engine unit tests are the
CI floor.
"""

import json
import os
from pathlib import Path

import pytest

from soctalk.authorization.adapter import facts_from_row, stackless_facts_from_row
from soctalk.authorization.engine import evaluate_authorization
from soctalk.models.authorization import AUTHORIZATION_FACT_ADAPTER

_ENV = "SOCTALK_AUTHZ_PARITY_DATA"

pytestmark = pytest.mark.skipif(
    not os.environ.get(_ENV),
    reason=f"{_ENV} not set — point it at goldens dataset dir(s) with orgstate.jsonl + gold.jsonl",
)


def _dirs() -> list[Path]:
    dirs = [Path(p) for p in os.environ[_ENV].split(":") if p]
    for d in dirs:
        if not (d / "orgstate.jsonl").is_file() or not (d / "gold.jsonl").is_file():
            pytest.fail(f"{d} is missing orgstate.jsonl/gold.jsonl — regenerate the parity dataset")
    return dirs


def _rows(d: Path) -> tuple[list[dict], dict[str, dict]]:
    rows = [json.loads(x) for x in (d / "orgstate.jsonl").read_text().splitlines() if x.strip()]
    gold = {
        j["id"]: j
        for j in (json.loads(x) for x in (d / "gold.jsonl").read_text().splitlines() if x.strip())
    }
    assert rows and len(rows) == len(gold)
    return rows, gold


def _components_dict(c) -> dict:
    return {
        "sanctioned_or_routine": c.sanctioned_or_routine,
        "in_scope": c.in_scope,
        "actor_genuine": c.actor_genuine,
        "policy_allowed": c.policy_allowed,
    }


def test_every_fact_and_activity_validates():
    """Wire-shape half of parity: every adapted fact revalidates through the discriminated
    union from its JSON dump (i.e. the wire format is losslessly parseable)."""
    seen_tracks = set()
    for d in _dirs():
        rows, _ = _rows(d)
        for row in rows:
            activity, facts = facts_from_row(row)
            seen_tracks.add(activity.track.value)
            for fact in facts:
                dumped = fact.model_dump(mode="json")
                again = AUTHORIZATION_FACT_ADAPTER.validate_python(dumped)
                assert again.model_dump(mode="json") == dumped
    assert seen_tracks, "no parity rows found"


def test_engine_reproduces_gold_components():
    """Semantic half of parity: adapter + engine == benchmark answer key, case for case."""
    total = 0
    by_track = {"account": 0, "fim": 0}
    mismatches = []
    for d in _dirs():
        rows, gold = _rows(d)
        for row in rows:
            total += 1
            by_track[row["track"]] += 1
            g = gold[row["id"]]
            activity, facts = facts_from_row(row)
            comps = evaluate_authorization(activity, facts)
            if _components_dict(comps) != g["components"] or comps.decision != g["decision"]:
                mismatches.append(
                    (
                        row["id"],
                        row["track"],
                        g["metadata"]["flipped_dimension"],
                        _components_dict(comps),
                        g["components"],
                    )
                )
    assert not mismatches, (
        f"{len(mismatches)}/{total} parity mismatches; first 10: {mismatches[:10]}"
    )
    assert by_track["account"] and by_track["fim"], f"both tracks required, got {by_track}"


def test_stackless_projection_never_closes_beyond_full_state():
    """Safety property of the M0 projection: removing evidence can only remove closes.
    A stackless close on a full-state escalate would mean the projection invented
    authorization out of thin air."""
    for d in _dirs():
        rows, gold = _rows(d)
        for row in rows:
            g = gold[row["id"]]
            activity, facts = stackless_facts_from_row(row)
            comps = evaluate_authorization(activity, facts)
            if comps.decision == "close":
                assert g["decision"] == "close", (
                    f"stackless closed {row['id']} ({g['metadata']['flipped_dimension']}) "
                    "but full-state gold escalates"
                )
