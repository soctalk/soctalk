"""Per-case_run LLM token budget.

``SOCTALK_CASE_RUN_TOKEN_BUDGET`` (default 15000) caps total
input+output tokens per case_run. Nodes call ``track`` after every
``ainvoke``; the supervisor short-circuits to CLOSE on ``over_budget``.
"""

from __future__ import annotations

import os
from typing import Any

import structlog


logger = structlog.get_logger()


_DEFAULT_BUDGET = 15_000


def _budget_default() -> int:
    raw = os.getenv("SOCTALK_CASE_RUN_TOKEN_BUDGET")
    if not raw:
        return _DEFAULT_BUDGET
    try:
        v = int(raw)
    except ValueError:
        return _DEFAULT_BUDGET
    return v if v > 0 else _DEFAULT_BUDGET


def ensure(state: dict[str, Any]) -> None:
    state.setdefault("tokens_used", 0)
    state.setdefault("tokens_budget", _budget_default())


def _extract_usage(response: Any) -> int:
    um = getattr(response, "usage_metadata", None)
    if isinstance(um, dict):
        return int(um.get("input_tokens") or 0) + int(um.get("output_tokens") or 0)
    rm = getattr(response, "response_metadata", None)
    if isinstance(rm, dict):
        usage = rm.get("usage") or rm.get("token_usage") or {}
        if isinstance(usage, dict):
            return int(usage.get("input_tokens") or usage.get("prompt_tokens") or 0) + int(
                usage.get("output_tokens") or usage.get("completion_tokens") or 0
            )
    return 0


def track(state: dict[str, Any], response: Any) -> int:
    ensure(state)
    delta = _extract_usage(response)
    state["tokens_used"] = int(state["tokens_used"]) + delta
    if delta:
        logger.debug(
            "tokens_tracked",
            delta=delta,
            total=state["tokens_used"],
            budget=state["tokens_budget"],
        )
    return state["tokens_used"]


def over_budget(state: dict[str, Any]) -> bool:
    ensure(state)
    return int(state["tokens_used"]) >= int(state["tokens_budget"])
