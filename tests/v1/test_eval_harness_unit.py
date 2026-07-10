"""DB-free, LLM-free unit tests for the triage eval harness (#9).

Covers golden-set loading/validation, state building against the real
node context builders, and the scoring math. The live LLM run is opt-in
via ``python -m soctalk.evals.triage``.
"""

from __future__ import annotations

import pytest

from soctalk.evals.triage import (
    DEFAULT_GOLDEN_PATH,
    GoldenCase,
    build_supervisor_state,
    build_verdict_state,
    load_cases,
    score_routing,
    score_verdict,
    summarize,
)


def test_golden_set_loads_and_validates():
    cases = load_cases(DEFAULT_GOLDEN_PATH)
    assert len(cases) >= 8
    ids = [c.id for c in cases]
    assert len(ids) == len(set(ids)), "case ids must be unique"
    kinds = {c.kind for c in cases}
    assert "routing" in kinds and "verdict" in kinds


def test_golden_states_feed_real_context_builders():
    from soctalk.supervisor.node import _build_context_summary
    from soctalk.supervisor.verdict import _build_verdict_context

    for case in load_cases(DEFAULT_GOLDEN_PATH):
        if case.kind in ("routing", "both"):
            ctx = _build_context_summary(build_supervisor_state(case))
            assert "### Alerts" in ctx
        if case.kind in ("verdict", "both"):
            ctx = _build_verdict_context(build_verdict_state(case))
            # formats without KeyError and carries the alert evidence
            assert ctx["alert_count"] >= 1
            assert ctx["investigation_id"].startswith("eval-")


def test_load_rejects_missing_expectations(tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text("cases:\n  - id: x\n    kind: routing\n    expect: {}\n")
    with pytest.raises(ValueError, match="routing_actions"):
        load_cases(bad)


def _case(**expect) -> GoldenCase:
    return GoldenCase(id="c", kind="both", description="", investigation={}, expect=expect)


def test_score_routing():
    case = _case(routing_actions=["ENRICH", "INVESTIGATE"])
    assert score_routing(case, "ENRICH").passed
    assert not score_routing(case, "CLOSE").passed


def test_score_verdict_decision_and_confidence_band():
    case = _case(verdict_decisions=["escalate"], confidence_min=0.6)
    assert score_verdict(case, "escalate", 0.9).passed
    assert not score_verdict(case, "close", 0.9).passed
    r = score_verdict(case, "escalate", 0.3)
    assert not r.passed and "confidence" in r.detail


def test_summarize_accuracy():
    case = _case(routing_actions=["ENRICH"], verdict_decisions=["close"])
    results = [
        score_routing(case, "ENRICH"),
        score_routing(case, "VERDICT"),
        score_verdict(case, "close", 0.8),
    ]
    s = summarize(results)
    assert s["routing"] == {
        "total": 2, "passed": 1, "accuracy": 0.5, "errors": 0, "schema_errors": 0,
    }
    assert s["verdict"]["accuracy"] == 1.0
