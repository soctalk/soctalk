"""Authorization prompt rendering: section content, placement, and the absence guardrail.

DB-free, LLM-free. Covers both real prompt builders (_build_context_summary and
_build_verdict_context) plus the render helpers directly.
"""

from soctalk.authorization.render import (
    MALICIOUS_SIGNAL_WARNING,
    NO_EVIDENCE_LINE,
    supervisor_authorization_lines,
    to_authorization_case_lines,
    verdict_authorization_detail,
)
from soctalk.models.authorization import AuthorizationContext
from soctalk.supervisor.node import _build_context_summary
from soctalk.supervisor.verdict import VERDICT_USER_PROMPT_TEMPLATE, _build_verdict_context

TS = "2026-07-11T03:00:12+00:00"


def _authz_context(facts=None) -> dict:
    ctx = {
        "activity": {
            "track": "account", "host": "app-01", "account": "svc-a",
            "action": "ssh-remote-exec", "time": TS,
        },
        "facts": facts if facts is not None else [
            {
                "id": "CHG-1187", "kind": "grant", "track": "account",
                "grant_class": "change_ticket",
                "scope": {"subject": "svc-a", "target": "app-01", "action": "ssh-remote-exec",
                          "recurring_window": {"start": "01:00", "end": "04:00"}},
                "valid_until": "2026-07-31T00:00:00+00:00",
                "source_type": "system_asserted", "trust": 80,
            },
            {
                "id": "ENT-U0", "kind": "entity_context", "track": "account",
                "entity_type": "account", "name": "svc-a", "account_type": "service",
            },
        ],
    }
    return ctx


def _state(investigation_extra=None, **state_extra) -> dict:
    investigation = {
        "id": "inv-1",
        "alerts": [{"severity": "medium", "level": 6, "rule_description": "sshd session",
                    "source": {"agent_name": "app-01"}}],
        "enrichments": [],
        "findings": [],
        "observables": [],
    }
    investigation.update(investigation_extra or {})
    state = {"investigation": investigation, "iteration_count": 2, "current_phase": "investigate"}
    state.update(state_extra)
    return state


def test_supervisor_section_renders_between_misp_and_volatile_tail():
    state = _state({"authorization_context": _authz_context()})
    summary = _build_context_summary(state)
    section = summary.index("### Authorization Context")
    assert summary.index("change_ticket CHG-1187") > section
    assert "[system_asserted, trust 80]" in summary
    assert section < summary.index("**Iteration:**")
    # component groups appear by name; computed booleans never do
    assert "Sanction & scope evidence" in summary
    assert "sanctioned_or_routine=" not in summary


def test_no_key_renders_nothing_and_stays_byte_identical():
    inv_with = _state({"authorization_context": _authz_context()})
    with_key = _build_context_summary(inv_with)
    without_key = _build_context_summary(_state())
    assert "### Authorization Context" not in without_key
    assert supervisor_authorization_lines(_state()["investigation"]) == []
    # removing the section (the exact lines the helper emits) is the ONLY difference
    section = "\n".join(supervisor_authorization_lines(inv_with["investigation"]))
    assert section in with_key
    assert with_key.replace("\n" + section, "", 1) == without_key


def test_present_but_empty_context_renders_absence_guardrail():
    state = _state({"authorization_context": _authz_context(facts=[])})
    summary = _build_context_summary(state)
    assert NO_EVIDENCE_LINE in summary


def test_invalid_context_is_dropped_not_half_rendered():
    state = _state({"authorization_context": {"activity": {"track": "account"}}})  # invalid
    summary = _build_context_summary(state)
    assert "Authorization Context" not in summary


def test_malicious_signal_warning_is_deterministic():
    inv = {"authorization_context": _authz_context(),
           "enrichments": [{"verdict": "malicious", "observable": {"value": "1.2.3.4"}}]}
    lines = "\n".join(supervisor_authorization_lines(inv))
    assert MALICIOUS_SIGNAL_WARNING in lines
    misp_inv = {"authorization_context": _authz_context(),
                "misp_context": {"matches": [{"value": "1.2.3.4"}]}}
    assert MALICIOUS_SIGNAL_WARNING in verdict_authorization_detail(misp_inv)
    clean = {"authorization_context": _authz_context()}
    assert MALICIOUS_SIGNAL_WARNING not in verdict_authorization_detail(clean)


def test_verdict_template_places_section_before_supervisor_assessment():
    state = _state({"authorization_context": _authz_context()},
                   supervisor_decision={"next_action": "VERDICT", "tp_confidence": 0.4,
                                        "confidence_reasoning": "covered"})
    prompt = VERDICT_USER_PROMPT_TEMPLATE.format(**_build_verdict_context(state))
    assert prompt.index("## Findings") < prompt.index("## Authorization Context")
    assert prompt.index("## Authorization Context") < prompt.index("## Supervisor's Assessment")
    # absent key -> the placeholder collapses with no stray heading
    empty = VERDICT_USER_PROMPT_TEMPLATE.format(**_build_verdict_context(_state()))
    assert "## Authorization Context" not in empty


def test_fact_cap_and_overflow_line():
    facts = [
        {
            "id": f"CHG-{i}", "kind": "grant", "track": "account",
            "grant_class": "change_ticket",
            "scope": {"subject": "svc-a", "target": "app-01", "action": "ssh-remote-exec"},
            "valid_until": "2026-07-31T00:00:00+00:00",
        }
        for i in range(11)
    ]
    lines = "\n".join(supervisor_authorization_lines(
        {"authorization_context": _authz_context(facts=facts)}
    ))
    assert "... and 3 more" in lines


def test_validity_bounds_render_in_full():
    """A future-effective ticket must be visibly not-yet-effective (Codex #4): both ISO
    bounds appear, not just an expiry date."""
    facts = [{
        "id": "CHG-9", "kind": "grant", "track": "account", "grant_class": "change_ticket",
        "scope": {"subject": "svc-a", "target": "app-01", "action": "ssh-remote-exec"},
        "valid_from": "2026-08-01T00:00:00+00:00",
        "valid_until": "2026-08-31T00:00:00+00:00",
    }]
    lines = "\n".join(supervisor_authorization_lines(
        {"authorization_context": _authz_context(facts=facts)}
    ))
    assert "effective_from=2026-08-01T00:00:00+00:00" in lines
    assert "valid_until=2026-08-31T00:00:00+00:00" in lines


def test_malicious_signal_detected_across_shapes():
    """Typed EnrichmentResult objects and enum verdicts must trigger the warning too."""
    from soctalk.models.enums import Verdict as VerdictType
    from soctalk.models.observables import EnrichmentResult, Observable

    typed = EnrichmentResult(
        observable=Observable(type="ip", value="1.2.3.4", source="wazuh"),
        verdict=VerdictType.MALICIOUS,
        analyzer="VirusTotal",
    )
    inv = {"authorization_context": _authz_context(), "enrichments": [typed]}
    assert MALICIOUS_SIGNAL_WARNING in "\n".join(supervisor_authorization_lines(inv))


def test_thehive_case_lines_state_components():
    ctx = AuthorizationContext.model_validate(_authz_context())
    lines = to_authorization_case_lines(ctx)
    joined = "\n".join(lines)
    assert "## Authorization Context" in joined
    assert "sanctioned_or_routine=True" in joined  # audit artifact MAY state components
    assert "change_ticket CHG-1187" in joined
