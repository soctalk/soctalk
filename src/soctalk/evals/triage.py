"""Triage quality evaluation harness.

Drives the *actual* supervisor and verdict nodes (same prompts, schemas,
and LLM factory as production) against a golden set of fabricated
investigation states, and scores routing + verdict accuracy.

This costs real LLM tokens — it never runs implicitly. Invoke it:

    # env: provider key + SOCTALK_FAST_MODEL / SOCTALK_REASONING_MODEL
    python -m soctalk.evals.triage                 # full golden set
    python -m soctalk.evals.triage --case <id>     # one case
    python -m soctalk.evals.triage --trials 3      # consistency check

Exit code is non-zero when accuracy falls below the thresholds
(SOCTALK_EVAL_ROUTING_THRESHOLD / SOCTALK_EVAL_VERDICT_THRESHOLD,
default 0.8 each), so it can gate prompt/model changes in a manual or
scheduled pipeline. Point SOCTALK_FAST_MODEL at a candidate model (or
OPENAI_BASE_URL at a self-hosted endpoint) to run the same set as a
backend compatibility check.
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import yaml

DEFAULT_GOLDEN_PATH = Path(__file__).resolve().parents[3] / "evals" / "golden_alerts.yaml"


# ---------------------------------------------------------------------------
# Case loading / state building (pure — unit-testable without an LLM)
# ---------------------------------------------------------------------------


@dataclass
class GoldenCase:
    id: str
    kind: str  # routing | verdict | both
    description: str
    investigation: dict[str, Any]
    iteration_count: int = 0
    pending_observables: list[dict[str, Any]] = field(default_factory=list)
    supervisor_assessment: dict[str, Any] = field(default_factory=dict)
    expect: dict[str, Any] = field(default_factory=dict)


def load_cases(path: Path | str = DEFAULT_GOLDEN_PATH) -> list[GoldenCase]:
    raw = yaml.safe_load(Path(path).read_text())
    cases = []
    for c in raw["cases"]:
        kind = c.get("kind", "both")
        if kind not in ("routing", "verdict", "both", "playbook"):
            raise ValueError(f"case {c.get('id')}: invalid kind {kind!r}")
        if kind in ("routing", "both") and not c.get("expect", {}).get("routing_actions"):
            raise ValueError(f"case {c.get('id')}: routing case needs expect.routing_actions")
        if kind in ("verdict", "both") and not c.get("expect", {}).get("verdict_decisions"):
            raise ValueError(f"case {c.get('id')}: verdict case needs expect.verdict_decisions")
        if kind == "playbook" and not c.get("expect", {}).get("playbook_route"):
            raise ValueError(f"case {c.get('id')}: playbook case needs expect.playbook_route")
        cases.append(
            GoldenCase(
                id=c["id"],
                kind=kind,
                description=c.get("description", ""),
                investigation=c.get("investigation", {}),
                iteration_count=int(c.get("iteration_count", 0)),
                pending_observables=list(c.get("pending_observables", [])),
                supervisor_assessment=dict(c.get("supervisor_assessment", {})),
                expect=dict(c.get("expect", {})),
            )
        )
    return cases


def build_supervisor_state(case: GoldenCase) -> dict[str, Any]:
    """State shape consumed by _build_context_summary()."""
    return {
        "investigation": case.investigation,
        "pending_observables": case.pending_observables,
        "iteration_count": case.iteration_count,
        "current_phase": "triage",
    }


def build_verdict_state(case: GoldenCase) -> dict[str, Any]:
    """State shape consumed by _build_verdict_context()."""
    started = datetime.now(timezone.utc) - timedelta(minutes=max(case.iteration_count, 1))
    return {
        "investigation": {"id": f"eval-{case.id}", **case.investigation},
        "supervisor_decision": case.supervisor_assessment,
        "iteration_count": case.iteration_count,
        "started_at": started.isoformat(),
    }


# ---------------------------------------------------------------------------
# Scoring (pure)
# ---------------------------------------------------------------------------


@dataclass
class TrialResult:
    case_id: str
    kind: str  # routing | verdict
    passed: bool
    got: str
    expected: list[str]
    detail: str = ""


def score_routing(case: GoldenCase, action: str) -> TrialResult:
    expected = [str(a) for a in case.expect["routing_actions"]]
    return TrialResult(
        case_id=case.id,
        kind="routing",
        passed=action in expected,
        got=action,
        expected=expected,
    )


def score_triage_policy(case: GoldenCase) -> TrialResult:
    """Deterministic playbook-layer scoring (issue #43) — no LLM, no tokens.

    Runs the resolver match + the resolve-playbook route over the fabricated
    investigation and scores the route (``operational_close`` = the deterministic
    disposition fired and the case never reaches the model; ``supervisor`` = full
    triage). ``expect.triage_policy_id`` optionally pins WHICH playbook matched. This
    keeps "class X never reaches the LLM" pinned in the same golden set that
    scores the LLM's own judgment.
    """
    from soctalk.graph.builder import route_from_resolve_triage_policy
    from soctalk.triage_policy.registry import match_triage_policy

    playbook = match_triage_policy(case.investigation)
    state: dict[str, Any] = {"investigation": case.investigation}
    if playbook is not None:
        state["playbook"] = playbook.model_dump()
    route = route_from_resolve_triage_policy(state)

    expected = [str(r) for r in case.expect["playbook_route"]]
    expected_id = case.expect.get("triage_policy_id")
    matched_id = playbook.id if playbook else None
    passed = route in expected and (expected_id is None or matched_id == expected_id)
    detail = ""
    if expected_id is not None and matched_id != expected_id:
        detail = f"matched playbook {matched_id!r}, expected {expected_id!r}"
    return TrialResult(
        case_id=case.id,
        kind="playbook",
        passed=passed,
        got=f"{route} ({matched_id or 'no-playbook'})",
        expected=expected,
        detail=detail,
    )


def score_verdict(case: GoldenCase, decision: str, confidence: float) -> TrialResult:
    expected = [str(d) for d in case.expect["verdict_decisions"]]
    lo = float(case.expect.get("confidence_min", 0.0))
    hi = float(case.expect.get("confidence_max", 1.0))
    decision_ok = decision in expected
    conf_ok = lo <= confidence <= hi
    detail = "" if conf_ok else f"confidence {confidence:.2f} outside [{lo},{hi}]"
    return TrialResult(
        case_id=case.id,
        kind="verdict",
        passed=decision_ok and conf_ok,
        got=f"{decision}@{confidence:.2f}",
        expected=expected,
        detail=detail,
    )


def summarize(results: list[TrialResult]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for kind in ("routing", "verdict", "playbook"):
        subset = [r for r in results if r.kind == kind]
        if subset:
            # A trial whose `got` starts with ERROR: crashed rather than
            # returning a value — most often a schema-validation failure on a
            # model that can't hold the output contract. Break those out so a
            # backend-compatibility run can tell "wrong answer" (model reasoned
            # badly) from "invalid output" (model can't produce the schema).
            errors = [r for r in subset if r.got.startswith("ERROR:")]
            schema_errors = [r for r in subset if r.got == "ERROR:SchemaValidationError"]
            out[kind] = {
                "total": len(subset),
                "passed": sum(r.passed for r in subset),
                "accuracy": sum(r.passed for r in subset) / len(subset),
                "errors": len(errors),
                "schema_errors": len(schema_errors),
            }
    return out


# ---------------------------------------------------------------------------
# Live execution (costs tokens)
# ---------------------------------------------------------------------------


async def _run_routing_trial(case: GoldenCase, config: Any) -> TrialResult:
    from soctalk.triage_policy.registry import match_triage_policy
    from soctalk.supervisor.node import _build_context_summary, _get_supervisor_decision

    state = build_supervisor_state(case)
    # Production-equivalence (#45): resolve the playbook exactly as the graph's
    # entry node would, so a playbook-matched case runs with the same narrowed
    # action schema production uses. Without this, the harness could score an
    # action production can no longer sample.
    playbook = match_triage_policy(case.investigation)
    if playbook is not None:
        state["playbook"] = playbook.model_dump()
    decision = await _get_supervisor_decision(
        config, _build_context_summary(state), state
    )
    return score_routing(case, str(decision.next_action))


async def _run_verdict_trial(case: GoldenCase, config: Any) -> TrialResult:
    from soctalk.supervisor.verdict import _build_verdict_context, _get_verdict

    state = build_verdict_state(case)
    verdict = await _get_verdict(config, _build_verdict_context(state))
    return score_verdict(case, verdict.decision.value, float(verdict.confidence))


async def run_evals(
    cases: list[GoldenCase], *, trials: int = 1, concurrency: int = 4
) -> list[TrialResult]:
    from soctalk.config import get_config

    config = get_config()
    sem = asyncio.Semaphore(concurrency)

    async def guarded(coro_fn, case):
        async with sem:
            try:
                return await coro_fn(case, config)
            except Exception as e:  # noqa: BLE001 — a crashed trial is a failed trial
                kind = "routing" if coro_fn is _run_routing_trial else "verdict"
                return TrialResult(
                    case_id=case.id, kind=kind, passed=False,
                    got=f"ERROR:{type(e).__name__}", expected=[], detail=str(e)[:200],
                )

    # Triage-policy cases are deterministic (no LLM): score once, outside the
    # semaphore/trials machinery — repeated trials of a pure function are noise.
    deterministic = [score_triage_policy(c) for c in cases if c.kind == "playbook"]

    tasks = []
    for case in cases:
        for _ in range(trials):
            if case.kind in ("routing", "both"):
                tasks.append(guarded(_run_routing_trial, case))
            if case.kind in ("verdict", "both"):
                tasks.append(guarded(_run_verdict_trial, case))
    return deterministic + list(await asyncio.gather(*tasks))


def print_scorecard(results: list[TrialResult], stream: Any = None) -> dict[str, Any]:
    stream = stream if stream is not None else sys.stdout
    summary = summarize(results)
    p = lambda *a: print(*a, file=stream)  # noqa: E731
    p()
    p("=" * 72)
    p("TRIAGE EVAL SCORECARD")
    p("=" * 72)
    for r in sorted(results, key=lambda r: (r.kind, r.case_id)):
        mark = "PASS" if r.passed else "FAIL"
        line = f"[{mark}] {r.kind:8s} {r.case_id:32s} got={r.got}"
        if not r.passed:
            line += f"  expected={r.expected} {r.detail}"
        p(line)
    p("-" * 72)
    for kind, s in summary.items():
        extra = ""
        if s.get("errors"):
            extra = f"  ({s['schema_errors']} schema / {s['errors']} total errors)"
        p(f"{kind:8s} accuracy: {s['passed']}/{s['total']} = {s['accuracy']:.0%}{extra}")
    p("=" * 72)
    return summary


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m soctalk.evals.triage")
    parser.add_argument("--golden", default=str(DEFAULT_GOLDEN_PATH))
    parser.add_argument("--case", default=None, help="Run a single case id.")
    parser.add_argument("--trials", type=int, default=1)
    parser.add_argument("--concurrency", type=int, default=4)
    parser.add_argument(
        "--json", action="store_true",
        help="Emit machine-readable JSON {summary, trials} to stdout; the human "
             "scorecard goes to stderr. For benchmark/CI consumption.",
    )
    parser.add_argument(
        "--label", default=None,
        help="Optional label (e.g. the model name) carried through in --json output.",
    )
    args = parser.parse_args(argv)

    cases = load_cases(args.golden)
    if args.case:
        cases = [c for c in cases if c.id == args.case]
        if not cases:
            print(f"no case with id {args.case!r}", file=sys.stderr)
            return 2

    results = asyncio.run(run_evals(cases, trials=args.trials, concurrency=args.concurrency))
    if args.json:
        # Human scorecard to stderr so stdout is clean JSON.
        summary = print_scorecard(results, stream=sys.stderr)
        import json
        from dataclasses import asdict
        json.dump(
            {"label": args.label, "summary": summary, "trials": [asdict(r) for r in results]},
            sys.stdout,
        )
        sys.stdout.write("\n")
    else:
        summary = print_scorecard(results)

    routing_threshold = float(os.getenv("SOCTALK_EVAL_ROUTING_THRESHOLD", "0.8"))
    verdict_threshold = float(os.getenv("SOCTALK_EVAL_VERDICT_THRESHOLD", "0.8"))
    ok = True
    if "routing" in summary and summary["routing"]["accuracy"] < routing_threshold:
        ok = False
    if "verdict" in summary and summary["verdict"]["accuracy"] < verdict_threshold:
        ok = False
    # Triage-policy cases are deterministic — anything below 100% is a code regression,
    # not model variance, so there is no tunable threshold.
    if "playbook" in summary and summary["playbook"]["accuracy"] < 1.0:
        ok = False
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
