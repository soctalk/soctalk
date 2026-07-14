"""M0 stackless eval: ask-once-memory simulation over a benchmark dataset (no LLM, no clock).

Answers the epic's go/no-go question — is an authorization memory worth building for orgs with
no ITSM/CMDB stack? — by simulating a SIEM-only deployment over the soctalk-goldens benchmark:

  1. Each case's org-state is projected to what a stackless org can know (adapter.stackless_*).
  2. The deterministic engine scores the case on projected facts + accumulated memory.
  3. When evidence is missing (and ONLY then), the simulated analyst is asked once; the answer
     comes from the benchmark's full-state gold label (a perfect oracle) and, on "authorized",
     is stored as a durable analyst_asserted grant scoped per --memory-scope.

Iteration order: paraphrase cases are skipped (facts-level byte-dupes would inflate reuse);
counterfactual groups act as tenant timelines — the group's trap variants (expired/frozen/
re-scoped worlds) hit AFTER its base close, which is the deliberate stale-memory probe. The
false-negative rate must therefore be read as "stale-memory failure under manufactured drift",
never as a steady-state FN rate; it is bucketed by cause (stale_memory vs projection) and the
§8.2 never-ask gate (compromised actor / IOC sighting) is scored in a separate
safety_override bucket so guardrail intent is not counted as model error.

Consumes goldens dataset dirs (gold.jsonl + orgstate.jsonl) by FILE only — soctalk never
imports the benchmark package. Deterministic end to end: no RNG, no wall clock, no tokens.

    python -m soctalk.evals.authorization_m0 \
        --data .../data_parity_account:.../data_parity_fim \
        --memory-scope ticket_terms --passes 2 --out runs/m0_ticket_terms.json
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from soctalk.authorization.adapter import facts_from_row, stackless_facts_from_row
from soctalk.authorization.engine import evaluate_authorization, find_covering_grants
from soctalk.models.authorization import (
    TRUST_TIER,
    AuthorizationActivity,
    AuthorizationFact,
    AuthorizationSourceType,
    FactScope,
    GrantClass,
    GrantFact,
    GrantStatus,
)

MEMORY_SCOPES = ("ticket_terms", "tuple_forever")
_ANALYST_TRUST = TRUST_TIER[AuthorizationSourceType.ANALYST_ASSERTED]


@dataclass
class SimCase:
    row: dict[str, Any]
    gold: dict[str, Any]
    activity: AuthorizationActivity
    full_facts: list[AuthorizationFact]
    stackless_facts: list[AuthorizationFact]

    @property
    def id(self) -> str:
        return str(self.row["id"])

    @property
    def track(self) -> str:
        return str(self.row["track"])

    @property
    def dimension(self) -> str:
        return str(self.gold["metadata"]["flipped_dimension"])

    @property
    def group(self) -> str:
        return str(self.gold["metadata"]["counterfactual_group"])


@dataclass
class Memory:
    scope_policy: str
    facts: list[GrantFact] = field(default_factory=list)
    uses: dict[str, int] = field(default_factory=dict)

    def remember(self, case: SimCase) -> None:
        """Store the analyst's 'yes, authorized' as a durable analyst_asserted grant."""
        covering = find_covering_grants(case.activity, case.full_facts)
        source = covering[0] if covering else None
        mem_id = f"MEM-{len(self.facts)}"
        if self.scope_policy == "ticket_terms" and source is not None:
            # The analyst transcribed the real authorization's terms: same scope tuple,
            # window, and calendar validity as the record they consulted. A routine-history
            # source becomes a standing baseline (an analyst answer is a standing assertion,
            # not a sighting count) — decided BEFORE construction: the GrantFact validator
            # rejects a routine_observation without seen_count.
            grant_class = (
                GrantClass.STANDING_BASELINE
                if source.grant_class == GrantClass.ROUTINE_OBSERVATION
                else source.grant_class
            )
            fact = GrantFact(
                id=mem_id,
                track=case.activity.track,
                scope=source.scope.model_copy(deep=True),
                grant_class=grant_class,
                status=GrantStatus.APPROVED,
                valid_from=source.valid_from,
                valid_until=source.valid_until,
                source_type=AuthorizationSourceType.ANALYST_ASSERTED,
                trust=_ANALYST_TRUST,
                created_by="ask-once-simulation",
            )
        else:
            # Naive memory: the exact activity tuple, no window, unbounded validity.
            a = case.activity
            fact = GrantFact(
                id=mem_id,
                track=a.track,
                scope=FactScope(
                    subject=a.account, target=a.host if a.host else a.path, action=a.action,
                    change_type=a.change_type,
                ),
                grant_class=GrantClass.STANDING_BASELINE,
                source_type=AuthorizationSourceType.ANALYST_ASSERTED,
                trust=_ANALYST_TRUST,
                created_by="ask-once-simulation",
            )
        self.facts.append(fact)
        self.uses[mem_id] = 0


def _load_cases(data_dirs: list[Path]) -> list[SimCase]:
    cases: list[SimCase] = []
    for d in data_dirs:
        gold_by_id = {
            j["id"]: j
            for j in (
                json.loads(x) for x in (d / "gold.jsonl").read_text().splitlines() if x.strip()
            )
        }
        for line in (d / "orgstate.jsonl").read_text().splitlines():
            if not line.strip():
                continue
            row = json.loads(line)
            gold = gold_by_id[row["id"]]
            if gold["metadata"].get("paraphrase_of"):
                continue  # byte-duplicate at the facts level; would inflate reuse for free
            activity, full = facts_from_row(row)
            _, stackless = stackless_facts_from_row(row)
            cases.append(SimCase(row, gold, activity, full, stackless))
    # counterfactual groups as timelines: groups in stable id order, file order within a group
    grouped: dict[str, list[SimCase]] = {}
    for c in cases:
        grouped.setdefault(c.group, []).append(c)
    return [c for g in sorted(grouped) for c in grouped[g]]


def _has_ioc_sighting(case: SimCase) -> bool:
    a = case.activity
    return any(
        isinstance(f, GrantFact)
        and f.grant_class == GrantClass.ROUTINE_OBSERVATION
        and f.ioc
        and f.scope.subject == a.account
        and f.scope.target == a.host
        and f.scope.action == a.action
        for f in case.stackless_facts
    )


def run_simulation(
    data_dirs: list[Path], memory_scope: str = "ticket_terms", passes: int = 2
) -> dict[str, Any]:
    if memory_scope not in MEMORY_SCOPES:
        raise ValueError(f"memory_scope must be one of {MEMORY_SCOPES}")
    cases = _load_cases(data_dirs)
    gold_close = [c for c in cases if c.gold["decision"] == "close"]
    gold_esc = [c for c in cases if c.gold["decision"] == "escalate"]

    # Pass-independent floor: what SIEM telemetry alone closes (no memory, no questions).
    siem_only_closes = sum(
        1
        for c in gold_close
        if evaluate_authorization(c.activity, c.stackless_facts).decision == "close"
    )

    memory = Memory(scope_policy=memory_scope)
    asked: set[str] = set()
    pass_reports: list[dict[str, Any]] = []
    fn_cases: list[dict[str, Any]] = []
    cardinality_timeline: list[int] = []
    closes_by_tier: dict[str, int] = {}

    for pass_no in range(1, passes + 1):
        outcomes: dict[str, str] = {}
        questions = repeat_questions = 0
        safety_overrides: list[str] = []
        seen_groups: set[str] = set()

        for case in cases:
            working = case.stackless_facts + list(memory.facts)
            comps = evaluate_authorization(case.activity, working)

            if not comps.actor_genuine or _has_ioc_sighting(case):
                # §8.2 gate FIRST — before any close is accepted: authorization evidence never
                # overrides malicious signal, and asking "was this authorized?" is the wrong
                # response to a compromised actor/target or an IOC-flagged sighting.
                outcomes[case.id] = "escalate_no_ask"
                if case.gold["decision"] == "close":
                    safety_overrides.append(case.id)
            elif comps.decision == "close":
                covering = find_covering_grants(case.activity, working)
                mem_hit = next((g for g in covering if g.id.startswith("MEM-")), None)
                if mem_hit is not None:
                    memory.uses[mem_hit.id] += 1
                    outcomes[case.id] = "close_memory"
                else:
                    outcomes[case.id] = "close_telemetry"
                for g in covering[:1]:
                    tier = g.source_type.value
                    closes_by_tier[tier] = closes_by_tier.get(tier, 0) + 1
            elif case.id in asked:
                repeat_questions += 1
                outcomes[case.id] = (
                    "ask_yes_repeat" if case.gold["decision"] == "close" else "ask_no_repeat"
                )
            else:
                asked.add(case.id)
                questions += 1
                if case.gold["decision"] == "close":
                    outcomes[case.id] = "ask_yes"
                    memory.remember(case)
                else:
                    outcomes[case.id] = "ask_no"  # a 'no' is not a standing prohibition (§8.4)

            if pass_no == 1 and case.group not in seen_groups:
                seen_groups.add(case.group)
                cardinality_timeline.append(len(memory.facts))

        auto_closed = [
            c for c in cases if outcomes[c.id] in ("close_telemetry", "close_memory")
        ]
        fns = [c for c in auto_closed if c.gold["decision"] == "escalate"]
        for c in fns:
            fn_cases.append(
                {
                    "pass": pass_no,
                    "id": c.id,
                    "track": c.track,
                    "dimension": c.dimension,
                    "cause": "stale_memory" if outcomes[c.id] == "close_memory" else "projection",
                }
            )
        n_close, n_esc = len(gold_close), len(gold_esc)
        adjusted_target = n_close - len(safety_overrides)
        closes_on_gold_close = sum(1 for c in auto_closed if c.gold["decision"] == "close")

        def _per_track(track: str) -> dict[str, Any]:
            tc = [c for c in gold_close if c.track == track]
            closes = sum(
                1
                for c in tc
                if outcomes[c.id] in ("close_telemetry", "close_memory")
            )
            return {
                "gold_close": len(tc),
                "auto_close_rate": closes / len(tc) if tc else None,
                "questions": sum(
                    1 for c in cases if c.track == track and outcomes[c.id] in ("ask_yes", "ask_no")
                ),
            }

        pass_reports.append(
            {
                "pass": pass_no,
                "auto_close_rate": closes_on_gold_close / n_close if n_close else None,
                "auto_close_gain": (closes_on_gold_close - siem_only_closes) / n_close
                if n_close
                else None,
                "auto_close_rate_safety_adjusted": closes_on_gold_close / adjusted_target
                if adjusted_target
                else None,
                "false_negative_rate": len(fns) / n_esc if n_esc else None,
                "false_negatives": len(fns),
                "question_volume": questions,
                "repeat_questions": repeat_questions,
                "safety_override_escalations": len(safety_overrides),
                "outcome_counts": {
                    k: sum(1 for v in outcomes.values() if v == k)
                    for k in sorted(set(outcomes.values()))
                },
                "per_track": {t: _per_track(t) for t in ("account", "fim")},
            }
        )

    stored = len(memory.facts)
    used = sum(1 for n in memory.uses.values() if n > 0)
    n_close = len(gold_close)
    return {
        "config": {
            "memory_scope": memory_scope,
            "passes": passes,
            "data_dirs": [str(d) for d in data_dirs],
        },
        "totals": {
            "cases": len(cases),
            "gold_close": n_close,
            "gold_escalate": len(gold_esc),
            "paraphrases_skipped": True,
        },
        "stackless": {
            "siem_only_close_rate": siem_only_closes / n_close if n_close else None,
            "siem_only_closes": siem_only_closes,
        },
        "passes": pass_reports,
        "memory": {
            "facts_stored": stored,
            "facts_reused": used,
            "pct_facts_reused": used / stored if stored else None,
            "reuse_rate": (sum(memory.uses.values()) / stored) if stored else None,
            "questions_per_gold_close": (len(asked) / n_close) if n_close else None,
            "cardinality_after_each_group": cardinality_timeline,
        },
        "closes_by_trust_tier": closes_by_tier,
        "false_negative_cases": fn_cases,
        "framing": (
            "false_negative_rate measures stale-memory failure under manufactured drift "
            "(counterfactual worlds share one timestamp); it is not a steady-state FN rate. "
            "safety_override_escalations are §8.2 guardrail intent, not model error."
        ),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--data", required=True, help="colon-separated goldens dataset dirs (gold+orgstate jsonl)"
    )
    parser.add_argument("--memory-scope", choices=MEMORY_SCOPES, default="ticket_terms")
    parser.add_argument("--passes", type=int, default=2)
    parser.add_argument("--out", help="write the report JSON here")
    parser.add_argument("--json", action="store_true", help="print the full report to stdout")
    args = parser.parse_args(argv)

    dirs = [Path(p) for p in args.data.split(":") if p]
    for d in dirs:
        if not (d / "orgstate.jsonl").is_file():
            print(f"error: {d} has no orgstate.jsonl — regenerate the dataset", file=sys.stderr)
            return 2
    report = run_simulation(dirs, memory_scope=args.memory_scope, passes=args.passes)

    if args.out:
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.out).write_text(json.dumps(report, indent=2) + "\n")
        print(f"wrote {args.out}")
    if args.json or not args.out:
        print(json.dumps(report, indent=2))
    else:
        first, last = report["passes"][0], report["passes"][-1]
        print(f"cases={report['totals']['cases']} close={report['totals']['gold_close']} "
              f"escalate={report['totals']['gold_escalate']}")
        print(f"siem_only_close_rate={report['stackless']['siem_only_close_rate']:.3f}")
        for p in (first, last):
            print(f"pass {p['pass']}: auto_close_rate={p['auto_close_rate']:.3f} "
                  f"gain={p['auto_close_gain']:.3f} FN_rate={p['false_negative_rate']:.3f} "
                  f"questions={p['question_volume']} repeats={p['repeat_questions']}")
        print(f"memory: stored={report['memory']['facts_stored']} "
              f"reuse_rate={report['memory']['reuse_rate']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
