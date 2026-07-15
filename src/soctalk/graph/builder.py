"""LangGraph builder for SecOps agent."""

from __future__ import annotations

from typing import Any, Literal

import structlog
from langgraph.checkpoint.base import BaseCheckpointSaver
from langgraph.graph import END, StateGraph

from soctalk.graph.close import close_investigation_node
from soctalk.graph.hil import human_review_node
from soctalk.models.enums import HumanDecision, VerdictDecision
from soctalk.playbook.models import (
    GATHER_AUTHORIZATION_CONTEXT,
    KNOWN_DISPOSITIONS,
    KNOWN_STEP_NODES,
)
from soctalk.playbook.nodes import (
    gather_authorization_context_node,
    operational_close_node,
    resolve_playbook_node,
    verdict_guard_node,
)
from soctalk.playbook.operational import operational_close_vetoes
from soctalk.supervisor.node import supervisor_node
from soctalk.supervisor.verdict import verdict_node
from soctalk.workers.cortex import cortex_worker_node
from soctalk.workers.misp import misp_worker_node
from soctalk.workers.thehive import thehive_worker_node
from soctalk.workers.wazuh import wazuh_worker_node

logger = structlog.get_logger()


def missing_required_steps(state: dict[str, Any]) -> list[str]:
    """Playbook-required deterministic steps that have not run yet (pure).

    Only step names the graph actually has nodes for count — an unknown name in a
    playbook is logged and skipped rather than deadlocking the run (there is nowhere
    to route to, and the post-verdict guard still enforces the floor edges).
    """
    playbook = state.get("playbook") or {}
    required = playbook.get("required_steps") or []
    done = set(state.get("playbook_steps_run") or [])
    missing = []
    for step in required:
        if step in done:
            continue
        if step not in KNOWN_STEP_NODES:
            logger.warning(
                "playbook_unknown_required_step",
                playbook=playbook.get("id"),
                step=step,
            )
            continue
        missing.append(step)
    return missing


def route_from_resolve_playbook(state: dict[str, Any]) -> Literal[
    "operational_close",
    "supervisor",
]:
    """Route from the resolver: a playbook with a deterministic disposition and a
    clean security-indicator check skips the LLM entirely; everything else — no
    playbook, no disposition, an unknown capability name, or any veto — goes to
    full triage. Unknown names fail closed TOWARD triage: a close capability that
    cannot be resolved must never close (pure; unit-tested).
    """
    playbook = state.get("playbook") or {}
    disposition = playbook.get("deterministic_disposition")
    if not disposition:
        return "supervisor"
    if disposition not in KNOWN_DISPOSITIONS:
        logger.warning(
            "playbook_unknown_disposition",
            playbook=playbook.get("id"),
            disposition=disposition,
        )
        return "supervisor"
    vetoes = operational_close_vetoes(
        state.get("investigation") or {},
        class_rule_groups=(playbook.get("applies_to") or {}).get("rule_groups"),
    )
    if vetoes:
        logger.info(
            "operational_close_vetoed",
            playbook=playbook.get("id"),
            vetoes=vetoes,
        )
        return "supervisor"
    return "operational_close"


def route_from_supervisor(state: dict[str, Any]) -> Literal[
    "wazuh_worker",
    "cortex_worker",
    "misp_worker",
    "gather_authorization_context",
    "verdict",
    "close_investigation",
]:
    """Route from supervisor to next node based on decision.

    Args:
        state: Current graph state.

    Returns:
        Next node name.
    """
    sup_err = state.get("supervisor_error") or {}
    if sup_err:
        # LLM failed in the supervisor — close without HIL; the worker
        # reports the run ``failed`` (mirrors verdict_error handling).
        logger.warning(
            "routing_from_supervisor_error",
            category=sup_err.get("category"),
            decision="forcing_close_no_hil",
        )
        return "close_investigation"

    decision = state.get("supervisor_decision", {})
    action = decision.get("next_action", "ENRICH")

    logger.debug("routing_from_supervisor", action=action)

    if action == "INVESTIGATE":
        return "wazuh_worker"
    elif action == "ENRICH":
        return "cortex_worker"
    elif action == "CONTEXTUALIZE":
        return "misp_worker"
    elif action in ("VERDICT", "CLOSE"):
        # Pre-decision gate (issue #43): a terminal proposal (VERDICT, or the
        # supervisor's auto-FP CLOSE — both can end in a close disposition) is
        # illegal until the active playbook's required deterministic steps have
        # run. The supervisor's action enum is fixed, so the gate reroutes to
        # the required node rather than expecting the LLM to select it; the
        # node marks itself as run, so this fires at most once per step. A
        # budget-terminated CLOSE is exempt — the run is out of money and the
        # extra supervisor pass after the step would burn more (the worker
        # reports it halted_budget/leave_open, never close_fp).
        if not state.get("budget_terminated"):
            missing = missing_required_steps(state)
            if missing:
                logger.info(
                    "pre_decision_gate_reroute",
                    playbook=(state.get("playbook") or {}).get("id"),
                    action=action,
                    step=missing[0],
                )
                return GATHER_AUTHORIZATION_CONTEXT
        return "verdict" if action == "VERDICT" else "close_investigation"
    else:
        # Default to enrichment
        return "cortex_worker"


def route_from_verdict(state: dict[str, Any]) -> Literal[
    "human_review",
    "close_investigation",
    "supervisor",
]:
    """Route from verdict to next node based on verdict decision.

    Args:
        state: Current graph state.

    Returns:
        Next node name.
    """
    verdict = state.get("verdict", {})
    decision = verdict.get("decision", VerdictDecision.NEEDS_MORE_INFO.value)

    # Provider failure (credit lack, rate limit, etc.) short-circuits
    # the route entirely — close the investigation instead of waking a
    # human reviewer on what is fundamentally an infrastructure
    # problem. The runs worker re-reads ``verdict_error`` and reports
    # the run as ``failed`` so no HIL row is created downstream.
    if state.get("verdict_error"):
        logger.warning(
            "routing_from_verdict_provider_error",
            category=(state.get("verdict_error") or {}).get("category"),
            decision="forcing_close_no_hil",
        )
        return "close_investigation"

    logger.debug("routing_from_verdict", decision=decision)

    if decision == VerdictDecision.ESCALATE.value:
        return "human_review"
    elif decision == VerdictDecision.CLOSE.value:
        return "close_investigation"
    elif decision == VerdictDecision.NEEDS_MORE_INFO.value:
        # Read verdict retry count (already incremented by verdict_node)
        verdict_retries = state.get("verdict_retry_count", 0)

        # After 1 retry, force escalation to human review. At depth >= 2 the
        # supervisor's own max_iterations gate fires repeatedly and the graph
        # spends its recursion budget bouncing supervisor→verdict without ever
        # surfacing to a human. One retry is enough to know the AI alone
        # cannot decide.
        if verdict_retries >= 1:
            logger.warning(
                "verdict_max_retries_reached",
                retries=verdict_retries,
                decision="forcing_human_review",
            )
            return "human_review"

        return "supervisor"
    else:
        return "human_review"


def route_from_human_review(state: dict[str, Any]) -> Literal[
    "thehive_worker",
    "close_investigation",
    "supervisor",
]:
    """Route from human review based on decision.

    Args:
        state: Current graph state.

    Returns:
        Next node name.
    """
    decision = state.get("human_decision")

    logger.debug("routing_from_human_review", decision=decision)

    if decision == HumanDecision.APPROVE.value:
        return "thehive_worker"
    elif decision == HumanDecision.REJECT.value:
        return "close_investigation"
    elif decision == HumanDecision.MORE_INFO.value:
        return "supervisor"
    else:
        # Default to close
        return "close_investigation"


def build_secops_graph(
    checkpointer: BaseCheckpointSaver | None = None,
) -> StateGraph:
    """Build the SecOps LangGraph.

    Args:
        checkpointer: Optional checkpoint saver for state persistence.
            When provided, enables workflow resumption and HIL pausing.

    Returns:
        Compiled StateGraph ready for execution.

    Graph structure:
        START -> resolve_playbook -> [operational_close | supervisor]
        operational_close -> close_investigation
        supervisor -> [wazuh_worker | cortex_worker | misp_worker |
                       gather_authorization_context | verdict | close_investigation]
        wazuh_worker -> supervisor
        cortex_worker -> supervisor
        misp_worker -> supervisor
        gather_authorization_context -> supervisor
        verdict -> verdict_guard
        verdict_guard -> [human_review | close_investigation | supervisor]
        human_review -> [thehive_worker | close_investigation | supervisor]
        thehive_worker -> close_investigation
        close_investigation -> END

    Playbook layer (issue #43): ``resolve_playbook`` writes the active playbook into
    state; the supervisor's conditional edge reroutes a VERDICT proposal to
    ``gather_authorization_context`` until the playbook's required steps have run; and
    every verdict passes through the deterministic ``verdict_guard`` before routing —
    the LLM proposes, the guard disposes.

    Example with checkpointing:
        async with get_checkpointer() as checkpointer:
            graph = build_secops_graph(checkpointer=checkpointer)
            config = get_checkpoint_config(investigation_id)
            result = await graph.ainvoke(state, config=config)
    """
    logger.info("building_secops_graph", checkpointer_enabled=checkpointer is not None)

    # Create graph with dict state
    graph = StateGraph(dict)

    # Add nodes
    graph.add_node("resolve_playbook", resolve_playbook_node)
    graph.add_node("operational_close", operational_close_node)
    graph.add_node("supervisor", supervisor_node)
    graph.add_node("wazuh_worker", wazuh_worker_node)
    graph.add_node("cortex_worker", cortex_worker_node)
    graph.add_node("misp_worker", misp_worker_node)
    graph.add_node(GATHER_AUTHORIZATION_CONTEXT, gather_authorization_context_node)
    graph.add_node("verdict", verdict_node)
    graph.add_node("verdict_guard", verdict_guard_node)
    graph.add_node("human_review", human_review_node)
    graph.add_node("thehive_worker", thehive_worker_node)
    graph.add_node("close_investigation", close_investigation_node)

    # Set entry point: deterministic playbook resolution before the first LLM look.
    # An operational-class alert with no security indicators closes without ever
    # reaching the supervisor; everything else proceeds to triage.
    graph.set_entry_point("resolve_playbook")
    graph.add_conditional_edges(
        "resolve_playbook",
        route_from_resolve_playbook,
        {
            "operational_close": "operational_close",
            "supervisor": "supervisor",
        },
    )
    graph.add_edge("operational_close", "close_investigation")

    # Add conditional edges from supervisor
    graph.add_conditional_edges(
        "supervisor",
        route_from_supervisor,
        {
            "wazuh_worker": "wazuh_worker",
            "cortex_worker": "cortex_worker",
            "misp_worker": "misp_worker",
            GATHER_AUTHORIZATION_CONTEXT: GATHER_AUTHORIZATION_CONTEXT,
            "verdict": "verdict",
            "close_investigation": "close_investigation",
        },
    )

    # Workers return to supervisor
    graph.add_edge("wazuh_worker", "supervisor")
    graph.add_edge("cortex_worker", "supervisor")
    graph.add_edge("misp_worker", "supervisor")

    # The required playbook step returns to the supervisor, which re-proposes with
    # the gathered authorization evidence now in its context.
    graph.add_edge(GATHER_AUTHORIZATION_CONTEXT, "supervisor")

    # Every verdict passes through the deterministic guard before routing.
    graph.add_edge("verdict", "verdict_guard")

    # The (possibly overridden) verdict routes to HIL, close, or back to supervisor
    graph.add_conditional_edges(
        "verdict_guard",
        route_from_verdict,
        {
            "human_review": "human_review",
            "close_investigation": "close_investigation",
            "supervisor": "supervisor",
        },
    )

    # Human review routes to TheHive, close, or back to supervisor
    graph.add_conditional_edges(
        "human_review",
        route_from_human_review,
        {
            "thehive_worker": "thehive_worker",
            "close_investigation": "close_investigation",
            "supervisor": "supervisor",
        },
    )

    # TheHive leads to close
    graph.add_edge("thehive_worker", "close_investigation")

    # Close leads to end
    graph.add_edge("close_investigation", END)

    # Compile the graph with optional checkpointer
    compiled = graph.compile(checkpointer=checkpointer)

    logger.info("secops_graph_built", checkpointer_enabled=checkpointer is not None)

    return compiled
