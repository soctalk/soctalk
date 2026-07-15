"""Playbook layer (issue #43) — the guardrails, in code, DB-free.

Covers the pure decision surface case-for-case (same discipline as the expectedness
parity test): playbook matching, the pre-verdict gate, the guard-result classifier,
the post-verdict guard node, the worker-plane safety floor, and a stubbed-LLM
end-to-end run of the compiled graph proving the reroute + override actually wire.
The IR-plane floor (DB lookups) is covered by the integration triage tests.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import soctalk.graph.builder as builder
from soctalk.graph.builder import (
    build_secops_graph,
    missing_required_steps,
    route_from_resolve_playbook,
    route_from_supervisor,
)
from soctalk.models.authorization import (
    AuthorizationActivity,
    AuthorizationContext,
    AuthorizationEntityKind,
    AuthorizationTrack,
    EntityContextFact,
    FactScope,
    GrantClass,
    GrantFact,
    PolicyPriority,
    ProhibitionFact,
)
from soctalk.playbook.floor import (
    VETO_ACTIVE_INCIDENT,
    VETO_AUTHZ_CONTRADICTED,
    VETO_IOC,
    VETO_UNVERIFIED_IOC,
    apply_worker_floor,
    worker_close_vetoes,
)
from soctalk.playbook.guard import (
    GUARDRAIL_AUTHZ_CONTRADICTED,
    GUARDRAIL_IOC_OVER_CLOSE,
    derive_authz_class,
    evaluate_guard,
)
from soctalk.playbook.models import CLOSE_OPERATIONAL, GATHER_AUTHORIZATION_CONTEXT
from soctalk.playbook.nodes import (
    gather_authorization_context_node,
    operational_close_node,
    resolve_playbook_node,
    verdict_guard_node,
)
from soctalk.playbook.operational import (
    VETO_MALICIOUS,
    VETO_MITRE,
    VETO_OBSERVABLES,
    VETO_SEVERITY,
    VETO_UNATTESTED_CLASS,
    operational_close_vetoes,
)
from soctalk.playbook.registry import (
    AGENT_HEALTH_PLAYBOOK,
    PRIVILEGED_EXEC_PLAYBOOK,
    match_playbook,
)
from soctalk.runs_worker.main import _disposition_from_final

T = datetime(2026, 7, 14, 14, 32, tzinfo=UTC)

ACTIVITY = AuthorizationActivity(
    track=AuthorizationTrack.ACCOUNT,
    host="db-01",
    account="svc-deploy",
    action="sudo-exec",
    time=T,
)


def _ticket(**kw) -> GrantFact:
    base: dict[str, Any] = dict(
        id="CHG-991",
        track=AuthorizationTrack.ACCOUNT,
        scope=FactScope(subject="svc-deploy", target="db-01", action="sudo-exec"),
        grant_class=GrantClass.CHANGE_TICKET,
        valid_until=datetime(2026, 12, 31, tzinfo=UTC),
    )
    base.update(kw)
    return GrantFact(**base)


def _prohibition() -> ProhibitionFact:
    return ProhibitionFact(
        id="POL-PCI-EXEC",
        track=AuthorizationTrack.ACCOUNT,
        forbid_action="sudo-exec",
        priority=PolicyPriority.HIGH,
    )


def _context(facts: list) -> AuthorizationContext:
    return AuthorizationContext(activity=ACTIVITY, facts=facts)


def _verdict(decision: str = "close") -> dict[str, Any]:
    return {
        "decision": decision,
        "confidence": 0.85,
        "threat_assessment": "looks routine",
        "evidence_strength": "moderate",
        "potential_impact": "low",
        "urgency": "routine",
        "recommendation": "close as routine admin activity",
    }


def _sudo_investigation(ctx: AuthorizationContext | None = None) -> dict[str, Any]:
    inv: dict[str, Any] = {
        "id": "run-1",
        "alerts": [
            {
                "id": "a1",
                "severity": "medium",
                "level": 5,
                "rule_description": "sudo exec by svc-deploy on db-01",
                "rule_groups": ["syslog", "sudo"],
                "source": {"agent_name": "db-01"},
            }
        ],
        "enrichments": [],
        "findings": [],
        "observables": [],
        "misp_context": {},
    }
    if ctx is not None:
        inv["authorization_context"] = ctx.model_dump(mode="json")
    return inv


# ---------------------------------------------------------------------------
# Playbook matching
# ---------------------------------------------------------------------------


def test_match_playbook_on_sudo_rule_groups():
    pb = match_playbook(_sudo_investigation())
    assert pb is not None and pb.id == PRIVILEGED_EXEC_PLAYBOOK.id


def test_match_playbook_on_account_track_context():
    inv = _sudo_investigation(_context([]))
    inv["alerts"][0]["rule_groups"] = ["fim"]  # no group match — track carries it
    pb = match_playbook(inv)
    assert pb is not None and pb.id == PRIVILEGED_EXEC_PLAYBOOK.id


def test_match_playbook_none_for_unrelated_alert():
    inv = _sudo_investigation()
    inv["alerts"][0]["rule_groups"] = ["web", "accesslog"]
    assert match_playbook(inv) is None


# ---------------------------------------------------------------------------
# Pre-verdict gate (pure routing)
# ---------------------------------------------------------------------------


def _gate_state(steps_run: list[str] | None = None, playbook: bool = True) -> dict[str, Any]:
    state: dict[str, Any] = {
        "supervisor_decision": {"next_action": "VERDICT"},
    }
    if playbook:
        state["playbook"] = PRIVILEGED_EXEC_PLAYBOOK.model_dump()
    if steps_run is not None:
        state["playbook_steps_run"] = steps_run
    return state


def test_gate_reroutes_verdict_until_required_step_ran():
    assert route_from_supervisor(_gate_state()) == GATHER_AUTHORIZATION_CONTEXT


def test_gate_allows_verdict_after_step_ran():
    assert (
        route_from_supervisor(_gate_state(steps_run=[GATHER_AUTHORIZATION_CONTEXT]))
        == "verdict"
    )


def test_gate_inert_without_playbook():
    assert route_from_supervisor(_gate_state(playbook=False)) == "verdict"


def test_gate_never_touches_non_verdict_actions():
    state = _gate_state()
    state["supervisor_decision"] = {"next_action": "ENRICH"}
    assert route_from_supervisor(state) == "cortex_worker"


def test_unknown_required_step_is_skipped_not_deadlocked():
    state = _gate_state()
    state["playbook"]["required_steps"] = ["no_such_node", GATHER_AUTHORIZATION_CONTEXT]
    assert missing_required_steps(state) == [GATHER_AUTHORIZATION_CONTEXT]
    state["playbook"]["required_steps"] = ["no_such_node"]
    assert route_from_supervisor(state) == "verdict"


def test_gate_reroutes_supervisor_close_too():
    """Codex round-1 blocker: the supervisor's auto-FP CLOSE maps to close_fp
    downstream, so it must not skip the playbook's required evidence step."""
    state = _gate_state()
    state["supervisor_decision"] = {"next_action": "CLOSE"}
    assert route_from_supervisor(state) == GATHER_AUTHORIZATION_CONTEXT
    state["playbook_steps_run"] = [GATHER_AUTHORIZATION_CONTEXT]
    assert route_from_supervisor(state) == "close_investigation"


def test_gate_exempts_budget_terminated_close():
    state = _gate_state()
    state["supervisor_decision"] = {"next_action": "CLOSE"}
    state["budget_terminated"] = True
    assert route_from_supervisor(state) == "close_investigation"


# ---------------------------------------------------------------------------
# Guard-result classifier
# ---------------------------------------------------------------------------


def test_authz_class_absent_when_no_context_or_facts():
    assert derive_authz_class(None)[0] == "absent"
    assert derive_authz_class(_context([]))[0] == "absent"


def test_authz_class_absent_when_only_entity_context():
    asset = EntityContextFact(
        id="ENT-1",
        track=AuthorizationTrack.ACCOUNT,
        entity_type=AuthorizationEntityKind.ASSET,
        name="db-01",
        environment="prod",
    )
    assert derive_authz_class(_context([asset]))[0] == "absent"


def test_authz_class_covered_by_valid_ticket():
    cls, components = derive_authz_class(_context([_ticket()]))
    assert cls == "covered"
    assert components is not None and components.in_scope


def test_authz_class_contradicted_by_expired_ticket():
    expired = _ticket(valid_until=datetime(2026, 7, 13, tzinfo=UTC))
    cls, components = derive_authz_class(_context([expired]))
    assert cls == "contradicted"
    assert components is not None and not components.in_scope


def test_authz_class_contradicted_by_prohibition():
    cls, _ = derive_authz_class(_context([_prohibition()]))
    assert cls == "contradicted"
    # even alongside a covering grant, a forbidding policy contradicts
    cls2, _ = derive_authz_class(_context([_ticket(), _prohibition()]))
    assert cls2 == "contradicted"


def test_authz_class_ignores_facts_the_engine_would_not_select():
    """Codex round-1 minor: "records present" must be judged over engine-selected
    facts — a superseded or foreign-tenant grant is not a record on file and must
    not manufacture a contradiction (false guard escalation)."""
    superseded = _ticket(superseded_by="CHG-992")
    assert derive_authz_class(_context([superseded]))[0] == "absent"

    foreign = _ticket(tenant="tenant-b")
    ctx = AuthorizationContext(tenant="tenant-a", activity=ACTIVITY, facts=[foreign])
    assert derive_authz_class(ctx)[0] == "absent"


# ---------------------------------------------------------------------------
# Guard decision (pure)
# ---------------------------------------------------------------------------


def test_guard_overrides_close_on_contradicted():
    expired = _ticket(valid_until=datetime(2026, 7, 13, tzinfo=UTC))
    result = evaluate_guard(
        verdict_decision="close", context=_context([expired]), malicious_signal=False
    )
    assert result.final_decision == "escalate"
    assert [o.guardrail for o in result.overrides] == [GUARDRAIL_AUTHZ_CONTRADICTED]


def test_guard_overrides_close_on_ioc_and_floor_outranks_authz():
    result = evaluate_guard(
        verdict_decision="close", context=_context([_ticket()]), malicious_signal=True
    )
    assert result.final_decision == "escalate"
    assert [o.guardrail for o in result.overrides] == [GUARDRAIL_IOC_OVER_CLOSE]


def test_guard_commits_covered_close():
    result = evaluate_guard(
        verdict_decision="close", context=_context([_ticket()]), malicious_signal=False
    )
    assert result.final_decision == "close" and not result.overridden


def test_guard_never_touches_absent_or_non_close():
    # absent evidence: the prompt rubric owns it, the guard does not force
    assert (
        evaluate_guard(
            verdict_decision="close", context=None, malicious_signal=False
        ).final_decision
        == "close"
    )
    for decision in ("escalate", "needs_more_info"):
        result = evaluate_guard(
            verdict_decision=decision,
            context=_context([_prohibition()]),
            malicious_signal=True,
        )
        assert result.final_decision == decision and not result.overridden


# ---------------------------------------------------------------------------
# Nodes
# ---------------------------------------------------------------------------


async def test_resolve_playbook_node_writes_state():
    state = {"investigation": _sudo_investigation()}
    state = await resolve_playbook_node(state)
    assert state["playbook"]["id"] == PRIVILEGED_EXEC_PLAYBOOK.id
    state2 = await resolve_playbook_node(
        {"investigation": {"alerts": [{"rule_groups": ["web"]}]}}
    )
    assert "playbook" not in state2


async def test_gather_node_marks_step_even_when_context_absent():
    state = {"investigation": _sudo_investigation()}
    state = await gather_authorization_context_node(state)
    assert state["playbook_steps_run"] == [GATHER_AUTHORIZATION_CONTEXT]
    assert state["authorization_gathered"]["status"] == "absent"
    # idempotent: a second pass never duplicates the step record
    state = await gather_authorization_context_node(state)
    assert state["playbook_steps_run"] == [GATHER_AUTHORIZATION_CONTEXT]


async def test_gather_node_stamps_engine_components():
    state = {"investigation": _sudo_investigation(_context([_ticket()]))}
    state = await gather_authorization_context_node(state)
    gathered = state["authorization_gathered"]
    assert gathered["status"] == "present" and gathered["facts"] == 1
    stamped = state["investigation"]["authorization_context"]["components"]
    assert stamped["in_scope"] is True and stamped["policy_allowed"] is True


async def test_verdict_guard_node_overrides_contradicted_close_with_audit():
    expired = _ticket(valid_until=datetime(2026, 7, 13, tzinfo=UTC))
    state = {
        "playbook": PRIVILEGED_EXEC_PLAYBOOK.model_dump(),
        "investigation": _sudo_investigation(_context([expired])),
        "verdict": _verdict("close"),
    }
    state = await verdict_guard_node(state)
    assert state["verdict"]["decision"] == "escalate"
    assert state["verdict_overridden_by_guard"] is True
    assert state["verdict"]["recommendation"].startswith("[GUARD OVERRIDE")
    (audit,) = state["playbook_audit"]
    assert audit["playbook"] == PRIVILEGED_EXEC_PLAYBOOK.id
    assert audit["llm_draft_decision"] == "close"
    assert audit["final_decision"] == "escalate"
    assert audit["authz_class"] == "contradicted"
    assert audit["overrides"][0]["guardrail"] == GUARDRAIL_AUTHZ_CONTRADICTED


async def test_verdict_guard_node_lets_covered_close_stand():
    state = {
        "investigation": _sudo_investigation(_context([_ticket()])),
        "verdict": _verdict("close"),
    }
    state = await verdict_guard_node(state)
    assert state["verdict"]["decision"] == "close"
    assert "playbook_audit" not in state
    assert state["authz_class"] == "covered"


async def test_verdict_guard_node_enforces_ioc_over_close():
    inv = _sudo_investigation(_context([_ticket()]))
    inv["enrichments"] = [{"observable": {"value": "1.2.3.4"}, "verdict": "malicious"}]
    state = {"investigation": inv, "verdict": _verdict("close")}
    state = await verdict_guard_node(state)
    assert state["verdict"]["decision"] == "escalate"
    assert state["playbook_audit"][0]["overrides"][0]["guardrail"] == (
        GUARDRAIL_IOC_OVER_CLOSE
    )


async def test_verdict_guard_node_passthrough_on_error_or_missing_verdict():
    state = {"verdict_error": {"category": "rate_limit"}, "verdict": _verdict("close")}
    out = await verdict_guard_node(dict(state))
    assert out["verdict"]["decision"] == "close"
    out2 = await verdict_guard_node({"investigation": {}})
    assert "verdict" not in out2 or not out2.get("verdict")


# ---------------------------------------------------------------------------
# Worker-plane safety floor
# ---------------------------------------------------------------------------


def test_floor_vetoes_close_on_malicious_enrichment():
    inv = _sudo_investigation()
    inv["enrichments"] = [{"observable": {}, "verdict": "malicious"}]
    final = {"investigation": inv}
    assert worker_close_vetoes(final) == [VETO_IOC]
    assert apply_worker_floor(final, "close_fp") == ("escalate", [VETO_IOC])


def test_floor_vetoes_close_on_misp_match_and_active_incident_flag():
    inv = _sudo_investigation()
    inv["misp_context"] = {"matches": [{"value": "evil.example"}]}
    final = {"investigation": inv, "correlation": {"active_incident": True}}
    assert worker_close_vetoes(final) == [VETO_IOC, VETO_ACTIVE_INCIDENT]


def test_floor_passes_clean_close_and_other_dispositions():
    final = {"investigation": _sudo_investigation()}
    assert apply_worker_floor(final, "close_fp") == ("close_fp", [])
    dirty = {"investigation": {"enrichments": [{"verdict": "malicious"}]}}
    for disp in ("escalate", "leave_open", None):
        assert apply_worker_floor(dirty, disp) == (disp, [])


def test_floor_vetoes_router_only_close_over_unenriched_iocs():
    """Codex round-2: the router-tier CLOSE short-circuit (no verdict) must not
    commit a close while IOC observables were never enriched — nothing ever looked
    at them. A verdict-tier close over the same state commits: the reasoning model
    saw the un-enriched indicators in its prompt and judged them."""
    inv = _sudo_investigation()
    inv["observables"] = [{"type": "ip", "value": "203.0.113.7"}]
    no_verdict = {"investigation": inv}
    assert apply_worker_floor(no_verdict, "close_fp") == (
        "escalate",
        [VETO_UNVERIFIED_IOC],
    )
    with_verdict = {"investigation": inv, "verdict": _verdict("close")}
    assert apply_worker_floor(with_verdict, "close_fp") == ("close_fp", [])
    # enriched-benign observables never trip it, even on the router path
    inv2 = _sudo_investigation()
    inv2["observables"] = [{"type": "ip", "value": "203.0.113.7"}]
    inv2["enrichments"] = [
        {"observable": {"value": "203.0.113.7"}, "verdict": "benign"}
    ]
    assert apply_worker_floor({"investigation": inv2}, "close_fp") == ("close_fp", [])


def test_floor_vetoes_close_on_contradicted_authorization():
    """Codex round-1 blocker: a supervisor CLOSE short-circuit never passes the
    verdict guard, so the terminal floor must hold the contradicted edge too."""
    expired = _ticket(valid_until=datetime(2026, 7, 13, tzinfo=UTC))
    final = {"investigation": _sudo_investigation(_context([expired]))}
    assert apply_worker_floor(final, "close_fp") == (
        "escalate",
        [VETO_AUTHZ_CONTRADICTED],
    )
    # covered paperwork does not veto
    covered = {"investigation": _sudo_investigation(_context([_ticket()]))}
    assert apply_worker_floor(covered, "close_fp") == ("close_fp", [])


# ---------------------------------------------------------------------------
# Stubbed-LLM end-to-end: reroute + guard on the compiled graph
# ---------------------------------------------------------------------------


async def test_graph_reroutes_gather_then_guard_overrides_close(monkeypatch):
    """A sudo alert whose only change record is expired: the supervisor proposes
    VERDICT immediately, the gate reroutes through gather_authorization_context,
    the verdict LLM drafts close, and the guard enforces escalate."""

    supervisor_calls: list[int] = []

    async def fake_supervisor(state: dict[str, Any]) -> dict[str, Any]:
        supervisor_calls.append(1)
        state["iteration_count"] = state.get("iteration_count", 0) + 1
        state["supervisor_decision"] = {
            "next_action": "VERDICT",
            "action_reasoning": "stub",
            "tp_confidence": 0.4,
            "confidence_reasoning": "stub",
        }
        return state

    async def fake_verdict(state: dict[str, Any]) -> dict[str, Any]:
        state["verdict"] = _verdict("close")
        return state

    async def fake_human_review(state: dict[str, Any]) -> dict[str, Any]:
        state["human_review_reached"] = True
        return state

    monkeypatch.setattr(builder, "supervisor_node", fake_supervisor)
    monkeypatch.setattr(builder, "verdict_node", fake_verdict)
    monkeypatch.setattr(builder, "human_review_node", fake_human_review)

    expired = _ticket(valid_until=datetime(2026, 7, 13, tzinfo=UTC))
    state = {
        "investigation": _sudo_investigation(_context([expired])),
        "iteration_count": 0,
    }
    graph = build_secops_graph()
    final = await graph.ainvoke(state, {"recursion_limit": 50})

    # rerouted exactly once: supervisor → gather → supervisor → verdict
    assert len(supervisor_calls) == 2
    assert final["playbook_steps_run"] == [GATHER_AUTHORIZATION_CONTEXT]
    assert final["verdict"]["decision"] == "escalate"
    assert final["verdict_overridden_by_guard"] is True
    assert final["human_review_reached"] is True
    assert _disposition_from_final(final, "completed") == "escalate"


async def test_graph_supervisor_close_gathers_then_floor_escalates(monkeypatch):
    """Codex round-1 blocker, end-to-end: the supervisor never proposes VERDICT —
    it CLOSEs a playbook-matched sudo alert whose only ticket is expired. The gate
    still forces the evidence step first, and even though no verdict guard runs
    (no verdict), the worker floor turns the close_fp into an escalate."""

    calls: list[str] = []

    async def fake_supervisor(state: dict[str, Any]) -> dict[str, Any]:
        calls.append("supervisor")
        state["supervisor_decision"] = {
            "next_action": "CLOSE",
            "action_reasoning": "looks like routine admin",
            "tp_confidence": 0.1,
        }
        return state

    monkeypatch.setattr(builder, "supervisor_node", fake_supervisor)

    expired = _ticket(valid_until=datetime(2026, 7, 13, tzinfo=UTC))
    graph = build_secops_graph()
    final = await graph.ainvoke(
        {"investigation": _sudo_investigation(_context([expired]))},
        {"recursion_limit": 50},
    )

    assert final["playbook_steps_run"] == [GATHER_AUTHORIZATION_CONTEXT]
    assert calls == ["supervisor", "supervisor"]
    assert "verdict" not in final or not final.get("verdict")

    disposition = _disposition_from_final(final, "completed")
    assert disposition == "close_fp"  # supervisor short-circuit maps to close
    assert apply_worker_floor(final, disposition) == (
        "escalate",
        [VETO_AUTHZ_CONTRADICTED],
    )


async def test_graph_without_playbook_goes_straight_to_verdict(monkeypatch):
    async def fake_supervisor(state: dict[str, Any]) -> dict[str, Any]:
        state["supervisor_decision"] = {"next_action": "VERDICT"}
        return state

    async def fake_verdict(state: dict[str, Any]) -> dict[str, Any]:
        state["verdict"] = _verdict("close")
        return state

    monkeypatch.setattr(builder, "supervisor_node", fake_supervisor)
    monkeypatch.setattr(builder, "verdict_node", fake_verdict)

    inv = _sudo_investigation()
    inv["alerts"][0]["rule_groups"] = ["web"]
    graph = build_secops_graph()
    final = await graph.ainvoke({"investigation": inv}, {"recursion_limit": 50})

    assert "playbook" not in final
    assert final.get("playbook_steps_run") is None
    # clean close commits: no context, no IOC — guard stays out of the way
    assert final["verdict"]["decision"] == "close"
    assert _disposition_from_final(final, "completed") == "close_fp"


# ---------------------------------------------------------------------------
# agent-health-operational playbook (the representative second playbook)
# ---------------------------------------------------------------------------


def _flooding_investigation(**alert_overrides: Any) -> dict[str, Any]:
    alert = {
        "id": "a-flood",
        "severity": "high",
        "level": 9,
        "rule_id": "202",
        "rule_description": "Agent event queue is flooded",
        "rule_groups": ["wazuh", "agent_flooding"],
        "mitre": {},
        "source": {"agent_name": "web-01"},
    }
    alert.update(alert_overrides)
    return {
        "id": "run-flood",
        "alerts": [alert],
        "enrichments": [],
        "findings": [],
        "observables": [],
        "misp_context": {},
    }


def test_match_playbook_agent_health_by_group_and_rule_id():
    pb = match_playbook(_flooding_investigation())
    assert pb is not None and pb.id == AGENT_HEALTH_PLAYBOOK.id
    # rule id alone still ROUTES to the playbook when the groups drift — but the
    # deterministic close then fails class attestation (tested below), so the
    # only effect is playbook governance, never a close
    pb2 = match_playbook(_flooding_investigation(rule_groups=["wazuh"]))
    assert pb2 is not None and pb2.id == AGENT_HEALTH_PLAYBOOK.id


def test_security_playbook_outranks_operational_on_double_match():
    inv = _flooding_investigation(rule_groups=["sudo", "agent_flooding"])
    pb = match_playbook(inv)
    assert pb is not None and pb.id == PRIVILEGED_EXEC_PLAYBOOK.id


_CLASS_GROUPS = AGENT_HEALTH_PLAYBOOK.applies_to.rule_groups


def test_operational_vetoes_mirror_security_indicators():
    assert operational_close_vetoes(_flooding_investigation(), _CLASS_GROUPS) == []
    assert VETO_MITRE in operational_close_vetoes(
        _flooding_investigation(mitre={"ids": ["T1499"]}), _CLASS_GROUPS
    )
    # legacy singular MITRE key counts too — a missed key is a bypass
    assert VETO_MITRE in operational_close_vetoes(
        _flooding_investigation(mitre={"id": "T1499"}), _CLASS_GROUPS
    )
    inv = _flooding_investigation()
    inv["observables"] = [{"type": "ip", "value": "203.0.113.5"}]
    assert VETO_OBSERVABLES in operational_close_vetoes(inv, _CLASS_GROUPS)
    assert VETO_SEVERITY in operational_close_vetoes(
        _flooding_investigation(level=12), _CLASS_GROUPS
    )
    inv2 = _flooding_investigation()
    inv2["misp_context"] = {"matches": [{"value": "evil.example"}]}
    assert VETO_MALICIOUS in operational_close_vetoes(inv2, _CLASS_GROUPS)


def test_operational_close_requires_every_alert_to_attest_the_class():
    """Codex full-module blocker: a correlated investigation with one agent-health
    alert plus ANY other alert must never be closed as operational — every member
    must carry a class group. Rule-id-only identity (groups drifted) fails the
    attestation too, and so does an investigation with no alerts at all."""
    mixed = _flooding_investigation()
    mixed["alerts"].append(
        {
            "id": "a-auth",
            "level": 9,
            "rule_id": "5710",
            "rule_description": "sshd: brute force trying to get access",
            "rule_groups": ["syslog", "sshd"],
            "mitre": {},
        }
    )
    assert VETO_UNATTESTED_CLASS in operational_close_vetoes(mixed, _CLASS_GROUPS)
    assert route_from_resolve_playbook(
        {"playbook": AGENT_HEALTH_PLAYBOOK.model_dump(), "investigation": mixed}
    ) == "supervisor"

    id_only = _flooding_investigation(rule_groups=["wazuh"])
    assert VETO_UNATTESTED_CLASS in operational_close_vetoes(id_only, _CLASS_GROUPS)

    empty = {"alerts": [], "observables": []}
    assert VETO_UNATTESTED_CLASS in operational_close_vetoes(empty, _CLASS_GROUPS)


def test_route_from_resolve_playbook_fails_closed_toward_triage():
    clean = {
        "playbook": AGENT_HEALTH_PLAYBOOK.model_dump(),
        "investigation": _flooding_investigation(),
    }
    assert route_from_resolve_playbook(clean) == "operational_close"
    # any veto -> full triage
    vetoed = dict(clean)
    vetoed["investigation"] = _flooding_investigation(mitre={"ids": ["T1499"]})
    assert route_from_resolve_playbook(vetoed) == "supervisor"
    # no playbook / no disposition / unknown capability name -> full triage
    assert route_from_resolve_playbook({"investigation": {}}) == "supervisor"
    no_disp = dict(clean)
    no_disp["playbook"] = PRIVILEGED_EXEC_PLAYBOOK.model_dump()
    assert route_from_resolve_playbook(no_disp) == "supervisor"
    unknown = dict(clean)
    unknown["playbook"] = {**AGENT_HEALTH_PLAYBOOK.model_dump(),
                           "deterministic_disposition": "wipe_all_alerts"}
    assert route_from_resolve_playbook(unknown) == "supervisor"


async def test_operational_close_node_writes_close_and_audit():
    state = {
        "playbook": AGENT_HEALTH_PLAYBOOK.model_dump(),
        "investigation": _flooding_investigation(),
    }
    state = await operational_close_node(state)
    assert state["supervisor_decision"]["next_action"] == "CLOSE"
    assert state["operational_close"] is True
    (audit,) = state["playbook_audit"]
    assert audit["playbook"] == AGENT_HEALTH_PLAYBOOK.id
    assert audit["disposition"] == CLOSE_OPERATIONAL


async def test_graph_operational_close_never_touches_the_llm(monkeypatch):
    """Representative e2e: a clean agent-health alert closes deterministically —
    the supervisor and verdict nodes are never invoked, the worker maps it to
    close_fp, and the terminal floor lets it commit."""

    async def exploding_supervisor(state: dict[str, Any]) -> dict[str, Any]:
        raise AssertionError("supervisor must not run for an operational close")

    async def exploding_verdict(state: dict[str, Any]) -> dict[str, Any]:
        raise AssertionError("verdict must not run for an operational close")

    monkeypatch.setattr(builder, "supervisor_node", exploding_supervisor)
    monkeypatch.setattr(builder, "verdict_node", exploding_verdict)

    graph = build_secops_graph()
    final = await graph.ainvoke(
        {"investigation": _flooding_investigation()}, {"recursion_limit": 50}
    )

    assert final["operational_close"] is True
    assert final["playbook_audit"][0]["disposition"] == CLOSE_OPERATIONAL
    disposition = _disposition_from_final(final, "completed")
    assert disposition == "close_fp"
    assert apply_worker_floor(final, disposition) == ("close_fp", [])


async def test_graph_operational_close_vetoed_falls_back_to_triage(monkeypatch):
    """The same alert carrying a MITRE mapping is more than its class: it goes
    through normal LLM triage (supervisor -> verdict -> guard) instead."""

    async def fake_supervisor(state: dict[str, Any]) -> dict[str, Any]:
        state["supervisor_decision"] = {"next_action": "VERDICT"}
        return state

    async def fake_verdict(state: dict[str, Any]) -> dict[str, Any]:
        state["verdict"] = _verdict("escalate")
        return state

    async def fake_human_review(state: dict[str, Any]) -> dict[str, Any]:
        return state

    monkeypatch.setattr(builder, "supervisor_node", fake_supervisor)
    monkeypatch.setattr(builder, "verdict_node", fake_verdict)
    monkeypatch.setattr(builder, "human_review_node", fake_human_review)

    graph = build_secops_graph()
    final = await graph.ainvoke(
        {"investigation": _flooding_investigation(mitre={"ids": ["T1499"]})},
        {"recursion_limit": 50},
    )

    assert final.get("operational_close") is None
    assert final["verdict"]["decision"] == "escalate"
    assert _disposition_from_final(final, "completed") == "escalate"


# ---------------------------------------------------------------------------
# issue #46: kill switch (pure surface)
# ---------------------------------------------------------------------------


def test_auto_close_killed_env_and_policy(monkeypatch):
    from soctalk.playbook.floor import auto_close_killed

    monkeypatch.delenv("SOCTALK_AUTO_CLOSE_KILL", raising=False)
    assert auto_close_killed({}) is False
    assert auto_close_killed(None) is False
    assert auto_close_killed({"auto_close_kill": True}) is True
    # stringly/truthy values are NOT the boolean True — a JSON "true" string in
    # a policy row must not silently arm (same discipline as the shadow flags)
    assert auto_close_killed({"auto_close_kill": "true"}) is False
    assert auto_close_killed({"auto_close_kill": 1}) is False
    for v in ("1", "true", "YES"):
        monkeypatch.setenv("SOCTALK_AUTO_CLOSE_KILL", v)
        assert auto_close_killed({}) is True
    monkeypatch.setenv("SOCTALK_AUTO_CLOSE_KILL", "0")
    assert auto_close_killed({}) is False


def test_volume_cap_policy_parse_rejects_booleans_and_garbage():
    """Codex #46 finding: tenant policies are unvalidated JSONB — a stray JSON
    ``true`` must fall back to the install default, not become cap=1 (which
    would shut off auto-close after a single close)."""
    from soctalk.core.ir.triage import _int_policy

    assert _int_policy({}, "auto_close_volume_cap", 500) == 500
    assert _int_policy({"auto_close_volume_cap": True}, "auto_close_volume_cap", 500) == 500
    assert _int_policy({"auto_close_volume_cap": None}, "auto_close_volume_cap", 500) == 500
    assert _int_policy({"auto_close_volume_cap": "50"}, "auto_close_volume_cap", 500) == 50
    assert _int_policy({"auto_close_volume_cap": "junk"}, "auto_close_volume_cap", 500) == 500
    # explicit 0 / negative = operator intent to disable (passed through)
    assert _int_policy({"auto_close_volume_cap": 0}, "auto_close_volume_cap", 500) == 0
