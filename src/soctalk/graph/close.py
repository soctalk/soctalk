"""Close investigation node."""

from __future__ import annotations

from datetime import datetime
from typing import Any

import structlog

from soctalk.models.enums import InvestigationStatus, Phase, HumanDecision, VerdictDecision

logger = structlog.get_logger()


async def close_investigation_node(
    state: dict[str, Any],
) -> dict[str, Any]:
    """Close investigation node.

    Finalizes the investigation with appropriate status and closure reason.

    Args:
        state: Current graph state.

    Returns:
        Updated state with closed investigation.
    """
    logger.info("closing_investigation")

    investigation = state.get("investigation", {})
    verdict = state.get("verdict", {})
    human_decision = state.get("human_decision")
    human_feedback = state.get("human_feedback")
    supervisor_decision = state.get("supervisor_decision", {})

    # Determine closure reason and status
    closure_reason = _determine_closure_reason(
        verdict,
        human_decision,
        human_feedback,
        supervisor_decision,
    )

    # Update investigation status
    investigation["status"] = InvestigationStatus.CLOSED.value
    investigation["closed_at"] = datetime.now().isoformat()
    investigation["closure_reason"] = closure_reason

    # Log closure details
    logger.info(
        "investigation_closed",
        investigation_id=investigation.get("id"),
        closure_reason=closure_reason[:100],
        human_decision=human_decision,
        verdict_decision=verdict.get("decision") if verdict else None,
    )

    state["investigation"] = investigation
    state["current_phase"] = Phase.CLOSED.value
    state["last_updated"] = datetime.now().isoformat()

    return state


def _determine_closure_reason(
    verdict: dict,
    human_decision: str | None,
    human_feedback: str | None,
    supervisor_decision: dict,
) -> str:
    """Determine the closure reason based on various factors.

    Args:
        verdict: Verdict from reasoning LLM.
        human_decision: Decision from human review.
        human_feedback: Feedback from human review.
        supervisor_decision: Decision from supervisor.

    Returns:
        Closure reason string.
    """
    reasons = []

    # Check human decision
    if human_decision:
        if human_decision == HumanDecision.REJECT.value:
            reasons.append("Rejected by analyst during human review")
            if human_feedback:
                reasons.append(f"Analyst feedback: {human_feedback}")
        elif human_decision == HumanDecision.APPROVE.value:
            reasons.append("Approved by analyst - incident created")
        elif human_decision == HumanDecision.MORE_INFO.value:
            reasons.append("Analyst requested more information but investigation closed")
            if human_feedback:
                reasons.append(f"Analyst feedback: {human_feedback}")

    # Check verdict
    elif verdict:
        verdict_decision = verdict.get("decision")
        if verdict_decision == VerdictDecision.CLOSE.value:
            reasons.append("Closed by AI verdict - likely false positive")
            if verdict.get("recommendation"):
                reasons.append(f"AI recommendation: {verdict['recommendation'][:200]}")
        elif verdict_decision == VerdictDecision.ESCALATE.value:
            reasons.append("Escalation process completed")

    # Check supervisor decision
    elif supervisor_decision:
        action = supervisor_decision.get("next_action")
        if action == "CLOSE":
            reasons.append("Closed by supervisor - insufficient evidence of threat")
            confidence = supervisor_decision.get("tp_confidence", 0)
            reasons.append(f"True positive confidence: {confidence:.0%}")
            if supervisor_decision.get("confidence_reasoning"):
                reasons.append(f"Reasoning: {supervisor_decision['confidence_reasoning'][:200]}")

    # Default reason
    if not reasons:
        reasons.append("Investigation completed - no action required")

    return " | ".join(reasons)
