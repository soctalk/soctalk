"""Deterministic playbook nodes for the SecOps graph (issue #43).

Three plain LangGraph nodes — no LLM calls, no I/O beyond state:

- ``resolve_playbook_node``: entry node; matches the investigation against the
  built-in registry and writes the active playbook into state.
- ``gather_authorization_context_node``: the required step the pre-verdict gate
  reroutes to. Connectors are separate work, so today it gathers from the sources
  that exist — the claim payload / fixture context already on the investigation —
  validates it, stamps the engine components, and records absence explicitly
  (absence is first-class evidence, never implicit approval).
- ``verdict_guard_node``: runs the guard over the verdict draft; on override it
  rewrites the decision, appends the audit record to ``state["playbook_audit"]``,
  and annotates the recommendation so the analyst sees both the LLM draft and why
  it did not stand.
- ``operational_close_node``: the ``close_operational`` deterministic disposition —
  closes an operational-class alert without any LLM call, reached only when
  ``route_from_resolve_playbook`` found no security-indicator veto.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import structlog

from soctalk.authorization.engine import evaluate_authorization
from soctalk.authorization.render import has_malicious_signal, parse_authorization_context
from soctalk.playbook.guard import decision_value, evaluate_guard
from soctalk.playbook.models import CLOSE_OPERATIONAL, GATHER_AUTHORIZATION_CONTEXT
from soctalk.playbook.registry import match_playbook

logger = structlog.get_logger()


async def resolve_playbook_node(state: dict[str, Any]) -> dict[str, Any]:
    """Match the alert against the playbook registry; write the winner into state."""
    investigation = state.get("investigation", {}) or {}
    playbook = match_playbook(investigation)
    if playbook is not None:
        state["playbook"] = playbook.model_dump()
        logger.info(
            "playbook_resolved",
            playbook=playbook.id,
            version=playbook.version,
            required_steps=playbook.required_steps,
        )
    else:
        logger.debug("playbook_none_matched")
    return state


async def gather_authorization_context_node(state: dict[str, Any]) -> dict[str, Any]:
    """Load authorization evidence into state and mark the required step as run.

    The step is recorded as run UNCONDITIONALLY (first line, before any work) — the
    pre-verdict gate reroutes here whenever the step is missing, so a step that could
    fail without recording itself would loop the graph forever.
    """
    steps: list[str] = state.setdefault("playbook_steps_run", [])
    if GATHER_AUTHORIZATION_CONTEXT not in steps:
        steps.append(GATHER_AUTHORIZATION_CONTEXT)

    investigation = state.get("investigation", {}) or {}
    ctx = parse_authorization_context(investigation)
    if ctx is None:
        # Absence is the gathered answer, stated explicitly: no record of the right
        # kind exists in any connected source. The verdict prompt's absent-vs-
        # contradicted rubric takes it from here.
        state["authorization_gathered"] = {"status": "absent", "facts": 0}
        logger.info("authorization_context_gathered", status="absent")
        return state

    components = evaluate_authorization(ctx.activity, ctx.facts, ctx.tenant)
    ctx.components = components
    investigation["authorization_context"] = ctx.model_dump(mode="json")
    state["investigation"] = investigation
    state["authorization_gathered"] = {
        "status": "present",
        "facts": len(ctx.facts),
        "components": components.model_dump(),
    }
    logger.info(
        "authorization_context_gathered",
        status="present",
        facts=len(ctx.facts),
        engine_decision=components.decision,
    )
    return state


async def operational_close_node(state: dict[str, Any]) -> dict[str, Any]:
    """Deterministically close an operational-class alert — no LLM involved.

    Reached only via ``route_from_resolve_playbook`` after the security-indicator
    check came back clean. Writes a supervisor-shaped CLOSE decision (the worker's
    disposition mapping and the close node already understand that shape) plus a
    playbook_audit record, so the close reason and the audit trail both say this
    was a playbook disposition, not a model judgment. The terminal safety floor in
    the runs-worker still applies to the resulting ``close_fp``, unchanged.
    """
    playbook = state.get("playbook") or {}
    reasoning = (
        f"playbook {playbook.get('id')}: operational alert class (agent health) "
        "with no security indicators — deterministic close, no LLM invoked"
    )
    state["supervisor_decision"] = {
        "next_action": "CLOSE",
        "action_reasoning": reasoning,
        "tp_confidence": 0.0,
        "confidence_reasoning": "deterministic playbook disposition",
    }
    state.setdefault("playbook_audit", []).append(
        {
            "at": datetime.now(UTC).isoformat(),
            "playbook": playbook.get("id"),
            "effect": "deterministic_disposition",
            "disposition": CLOSE_OPERATIONAL,
            "reason": reasoning,
        }
    )
    state["operational_close"] = True
    logger.info("operational_close_applied", playbook=playbook.get("id"))
    return state


async def verdict_guard_node(state: dict[str, Any]) -> dict[str, Any]:
    """Post-verdict guard: LLM proposed, this node disposes.

    Runs on every verdict (the floor edges are unconditional; playbook presence only
    gates the pre-verdict reroute). Provider errors and missing verdicts pass through
    untouched — the worker's failed-run contract owns those.
    """
    verdict = state.get("verdict") or {}
    if state.get("verdict_error") or not verdict:
        return state

    playbook = state.get("playbook") or {}
    playbook_id = playbook.get("id")
    investigation = state.get("investigation", {}) or {}
    # Each verdict pass gets a fresh guard ruling — a stale interrupt flag from a
    # prior pass (e.g. human MORE_INFO -> supervisor -> new verdict) must not
    # route an uninterrupted draft to review.
    state.pop("verdict_interrupted", None)
    state.pop("verdict_overridden_by_guard", None)
    draft_decision = decision_value(verdict.get("decision"))
    result = evaluate_guard(
        verdict_decision=draft_decision,
        context=parse_authorization_context(investigation),
        malicious_signal=has_malicious_signal(investigation),
        close_signoff_data_classes=playbook.get("close_signoff_data_classes") or (),
    )
    state["authz_class"] = result.authz_class

    if not result.overrides:
        logger.debug(
            "verdict_guard_pass", decision=draft_decision, authz_class=result.authz_class
        )
        return state

    audit = {
        "at": datetime.now(UTC).isoformat(),
        "playbook": playbook_id,
        "authz_class": result.authz_class,
        "components": result.components.model_dump() if result.components else None,
        "llm_draft_decision": draft_decision,
        "final_decision": result.final_decision,
        "overrides": [o.model_dump() for o in result.overrides],
    }
    state.setdefault("playbook_audit", []).append(audit)

    if result.interrupted:
        # The draft stands untouched — a human disposes. Routing (and the
        # worker's disposition mapping) read the flag, not the verdict.
        state["verdict_interrupted"] = True
    if result.overridden:
        reasons = "; ".join(
            o.reason for o in result.overrides if o.effect == "override"
        )
        verdict = dict(verdict)
        verdict["decision"] = result.final_decision
        verdict["recommendation"] = (
            f"[GUARD OVERRIDE: LLM drafted '{draft_decision}', enforced '"
            f"{result.final_decision}' — {reasons}] "
            f"{verdict.get('recommendation') or ''}"
        ).strip()[:2048]
        state["verdict"] = verdict
        state["verdict_overridden_by_guard"] = True

    for o in result.overrides:
        logger.warning(
            "verdict_guard_" + o.effect,
            guardrail=o.guardrail,
            playbook=playbook_id,
            from_decision=o.from_decision,
            to_decision=o.to_decision,
            authz_class=result.authz_class,
        )
    return state
