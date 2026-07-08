"""Human-in-the-Loop review node."""

from __future__ import annotations

import asyncio
import sys
from datetime import datetime
from typing import Any

import structlog
from langgraph.errors import GraphInterrupt
from langgraph.types import interrupt

from soctalk.models.enums import HumanDecision
from soctalk.models.investigation import InvestigationRunState
from soctalk.models.verdict import Verdict

logger = structlog.get_logger()


async def human_review_node(
    state: dict[str, Any],
) -> dict[str, Any]:
    """Human-in-the-Loop review node.

    Presents the investigation summary and verdict to a human analyst
    for approval before creating an incident.

    Supports two backends:
    - Dashboard: Uses LangGraph interrupt + UI decision
    - CLI: Local interactive prompt (falls back to dashboard when not a TTY)

    Args:
        state: Current graph state.

    Returns:
        Updated state with human decision.
    """
    logger.info("human_review_started")

    state["awaiting_human_approval"] = True

    # Get investigation and verdict
    investigation_data = state.get("investigation", {})
    verdict_data = state.get("verdict", {})

    investigation = InvestigationRunState(**investigation_data) if isinstance(investigation_data, dict) else investigation_data
    verdict = Verdict(**verdict_data) if verdict_data and isinstance(verdict_data, dict) else None

    try:
        decision, feedback = await _handle_noninteractive_review(
            investigation=investigation,
            verdict=verdict,
        )

        state["human_decision"] = decision.value
        state["human_feedback"] = feedback
        state["awaiting_human_approval"] = False

        logger.info(
            "human_decision_received",
            decision=decision.value,
            has_feedback=bool(feedback),
        )

    except GraphInterrupt:
        raise
    except Exception as e:
        logger.error("human_review_error", error=str(e))
        # Default to requiring more info on error
        state["human_decision"] = HumanDecision.MORE_INFO.value
        state["human_feedback"] = f"Error during review: {str(e)}"
        state["awaiting_human_approval"] = False

    state["last_updated"] = datetime.now().isoformat()
    return state


async def _handle_noninteractive_review(
    *,
    investigation: InvestigationRunState,
    verdict: Verdict | None,
) -> tuple[HumanDecision, str | None]:
    if sys.stdin and sys.stdin.isatty():
        return await _prompt_cli_decision(investigation, verdict)

    try:
        resume_value = interrupt(
            {
                "type": "human_review",
                "investigation_id": investigation.id,
                "title": investigation.title,
                "verdict": verdict.model_dump() if verdict else None,
            }
        )
    except GraphInterrupt:
        raise
    except Exception as e:
        logger.error("hil_interrupt_failed", error=str(e))
        return HumanDecision.MORE_INFO, "HIL interrupt failed - manual follow-up required"

    payload = resume_value if isinstance(resume_value, dict) else {"decision": resume_value}
    decision = _coerce_human_decision(payload.get("decision"))
    feedback = payload.get("feedback")
    return decision, feedback


def _coerce_human_decision(value: Any) -> HumanDecision:
    if isinstance(value, HumanDecision):
        return value
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized == HumanDecision.APPROVE.value:
            return HumanDecision.APPROVE
        if normalized == HumanDecision.REJECT.value:
            return HumanDecision.REJECT
        if normalized == HumanDecision.MORE_INFO.value:
            return HumanDecision.MORE_INFO
    return HumanDecision.MORE_INFO


async def _prompt_cli_decision(
    investigation: InvestigationRunState,
    verdict: Verdict | None,
) -> tuple[HumanDecision, str | None]:
    prompt_lines = [
        "",
        f"Human review required for: {investigation.title} ({investigation.id})",
    ]
    if verdict:
        prompt_lines.append(
            f"Verdict: {verdict.decision.value} (confidence {verdict.confidence:.0%})"
        )
    prompt_lines.append("Decision [a]pprove / [r]eject / [m]ore info (default: m): ")

    def _read() -> str:
        return input("\n".join(prompt_lines))

    choice = (await asyncio.get_running_loop().run_in_executor(None, _read)).strip().lower()
    if choice in ("a", "approve"):
        return HumanDecision.APPROVE, None
    if choice in ("r", "reject"):
        return HumanDecision.REJECT, None
    return HumanDecision.MORE_INFO, None
