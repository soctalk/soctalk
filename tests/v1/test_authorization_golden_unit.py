"""golden_authorization.yaml stays loadable, typed, and self-consistent — without tokens.

The live scoring run (python -m soctalk.evals.triage --golden evals/golden_authorization.yaml)
costs tokens and is manual; this test keeps the committed YAML honest in CI: it must load
through the real harness loader, every authorization_context must validate into the typed
contract, the deterministic engine must agree with each case's expected verdicts, and both
prompt builders must actually render the section.
"""

from pathlib import Path

from soctalk.authorization.engine import evaluate_authorization
from soctalk.authorization.render import MALICIOUS_SIGNAL_WARNING
from soctalk.evals.triage import build_supervisor_state, build_verdict_state, load_cases
from soctalk.models.authorization import AuthorizationContext
from soctalk.supervisor.node import _build_context_summary
from soctalk.supervisor.verdict import VERDICT_USER_PROMPT_TEMPLATE, _build_verdict_context

GOLDEN = Path(__file__).resolve().parents[2] / "evals" / "golden_authorization.yaml"


def _cases():
    return load_cases(GOLDEN)


def test_loads_with_both_tracks_and_overrides():
    cases = _cases()
    assert len(cases) == 26
    assert all(c.kind == "verdict" and c.expect.get("verdict_decisions") for c in cases)
    ids = {c.id for c in cases}
    assert "authz-override-account" in ids and "authz-override-fim" in ids
    tracks = {c.investigation["authorization_context"]["activity"]["track"] for c in cases}
    assert tracks == {"account", "fim"}


def test_contexts_validate_into_typed_contract():
    for c in _cases():
        ctx = AuthorizationContext.model_validate(c.investigation["authorization_context"])
        assert ctx.facts or "absent" in c.description or "cr_absent" in c.id or ctx.facts == []


def test_engine_agrees_with_expected_verdicts():
    """Self-consistency: for benchmark-derived cases the deterministic engine's decision
    direction must match the expects (close in expect iff engine closes). Override cases are
    excluded — their escalate comes from malicious signal the engine deliberately ignores."""
    for c in _cases():
        if c.id.startswith("authz-override-"):
            continue
        ctx = AuthorizationContext.model_validate(c.investigation["authorization_context"])
        decision = evaluate_authorization(ctx.activity, ctx.facts, ctx.tenant).decision
        expected = c.expect["verdict_decisions"]
        if decision == "close":
            assert expected == ["close"], f"{c.id}: engine closes but expects {expected}"
        else:
            assert "close" not in expected, f"{c.id}: engine escalates but close in {expected}"


def test_override_cases_carry_malicious_signal_and_expect_escalate():
    for c in _cases():
        if not c.id.startswith("authz-override-"):
            continue
        assert any(
            e.get("verdict") == "malicious" for e in c.investigation["enrichments"]
        ), f"{c.id} must carry a malicious enrichment"
        assert c.expect["verdict_decisions"] == ["escalate"]
        # engine (authorization axis alone) says close — precisely why the case exists
        ctx = AuthorizationContext.model_validate(c.investigation["authorization_context"])
        assert evaluate_authorization(ctx.activity, ctx.facts, ctx.tenant).decision == "close"


def test_cases_render_through_real_prompt_builders():
    for c in _cases():
        summary = _build_context_summary(build_supervisor_state(c))
        assert "### Authorization Context" in summary, c.id
        verdict_ctx = _build_verdict_context(build_verdict_state(c))
        prompt = VERDICT_USER_PROMPT_TEMPLATE.format(**verdict_ctx)
        assert "## Authorization Context" in prompt, c.id
        if c.id.startswith("authz-override-"):
            assert MALICIOUS_SIGNAL_WARNING in summary and MALICIOUS_SIGNAL_WARNING in prompt
