"""Per-case_run LLM cost budget — tokens and dollars.

Two caps are enforced per case_run:

* ``tokens_budget`` (default ``SOCTALK_CASE_RUN_TOKEN_BUDGET`` or 15000)
* ``dollars_budget`` (default ``SOCTALK_CASE_RUN_DOLLAR_BUDGET`` or 5.0)

The supervisor calls ``ensure`` before its loop body, then short-circuits
to ``CLOSE`` when ``over_budget`` returns True. Nodes that call into an
LLM call ``track`` after every ``ainvoke`` so accumulation happens at the
same place the cost is incurred.

The dollar cap is the load-bearing guardrail: token counts are a noisy
proxy for spend (input and output tokens differ in price by 5x for
Sonnet, 5x for Opus, etc., and Opus is ~10x Sonnet). The historical
``tokens_used`` field is preserved so existing dashboards and the
``halted_budget`` disposition keep working unchanged.
"""

from __future__ import annotations

import os
import re
from typing import Any

import structlog


logger = structlog.get_logger()


_DEFAULT_TOKEN_BUDGET = 15_000
_DEFAULT_DOLLAR_BUDGET = 5.0


# Approximate per-million-token prices for the models SocTalk supports.
# Kept conservative (round up where vendor pricing has tiers) so the cap
# fails closed rather than open. The cap doesn't need to be exact — it
# is a safety net, not a billing source of truth.
#
# Last reviewed: 2026-05.
#
# Keys are normalized model-family prefixes (see ``_normalize_model``).
# Both Anthropic and OpenAI return versioned model IDs — e.g.
# ``claude-3-5-sonnet-latest``, ``gpt-4o-2024-08-06`` — and we strip
# the version suffix before lookup. Without that strip every versioned
# response misses the table and gets billed at the Opus fallback rate,
# halting runs many times earlier than the configured dollar cap.
_MODEL_PRICES_PER_MTOK: dict[str, dict[str, float]] = {
    # Anthropic Claude — public list price, $/MTok
    "claude-opus-4": {"input": 15.0, "output": 75.0},
    "claude-opus-3": {"input": 15.0, "output": 75.0},
    "claude-sonnet-4": {"input": 3.0, "output": 15.0},
    "claude-3-5-sonnet": {"input": 3.0, "output": 15.0},
    "claude-3-7-sonnet": {"input": 3.0, "output": 15.0},
    "claude-haiku-4": {"input": 1.0, "output": 5.0},
    "claude-3-5-haiku": {"input": 0.8, "output": 4.0},
    # OpenAI — public list price, $/MTok
    "gpt-4o-mini": {"input": 0.15, "output": 0.6},
    "gpt-4o": {"input": 2.5, "output": 10.0},
    "gpt-4-turbo": {"input": 10.0, "output": 30.0},
    "gpt-4": {"input": 30.0, "output": 60.0},
    "o1-mini": {"input": 3.0, "output": 12.0},
    "o1": {"input": 15.0, "output": 60.0},
}

# Fall-back price applied when the model name isn't in the table. Picked
# to be on the high side — an unknown model is more likely to be a
# premium tier than a free one, and we prefer to halt early.
_UNKNOWN_MODEL_FALLBACK = {"input": 15.0, "output": 75.0}


_VERSION_SUFFIX_RE = re.compile(
    # Trailing ``-YYYYMMDD`` (Anthropic style), ``-YYYY-MM-DD`` (OpenAI
    # style), or the literal ``-latest`` alias. We strip ONLY these
    # known suffix shapes — never a free-form trailing token — because
    # variants like ``gpt-4-32k`` or ``gpt-4-vision`` are *different
    # SKUs* with different pricing and must not be folded into the
    # base family.
    r"(?:-(?:\d{8}|\d{4}-\d{2}-\d{2})|-latest)$"
)


def _normalize_model(model: str | None) -> str:
    """Strip date / latest suffixes so versioned model IDs hit the table.

    Examples:
      ``claude-3-5-sonnet-latest``      → ``claude-3-5-sonnet``
      ``claude-3-5-sonnet-20241022``    → ``claude-3-5-sonnet``
      ``gpt-4o-2024-08-06``             → ``gpt-4o``
      ``gpt-4o-mini-2024-07-18``        → ``gpt-4o-mini``
      ``gpt-4-32k``                     → ``gpt-4-32k`` (unchanged — different SKU)

    If the stripped result doesn't exactly match a price-table key, the
    caller falls through to ``_UNKNOWN_MODEL_FALLBACK`` (the Opus rate).
    This is deliberately fail-closed: a model variant we don't recognize
    gets the conservative price so the dollar cap halts early rather
    than billing a $30/MTok model at $3 because of a fuzzy prefix.
    """
    if not model:
        return ""
    stripped = _VERSION_SUFFIX_RE.sub("", model, count=1)
    if stripped in _MODEL_PRICES_PER_MTOK:
        return stripped
    # No suffix match — try the raw name in case the caller passed a
    # base ID already.
    if model in _MODEL_PRICES_PER_MTOK:
        return model
    return model  # cost lookup will fall back to _UNKNOWN_MODEL_FALLBACK


def _token_budget_default() -> int:
    raw = os.getenv("SOCTALK_CASE_RUN_TOKEN_BUDGET")
    if not raw:
        return _DEFAULT_TOKEN_BUDGET
    try:
        v = int(raw)
    except ValueError:
        return _DEFAULT_TOKEN_BUDGET
    return v if v > 0 else _DEFAULT_TOKEN_BUDGET


def _dollar_budget_default() -> float:
    raw = os.getenv("SOCTALK_CASE_RUN_DOLLAR_BUDGET")
    if not raw:
        return _DEFAULT_DOLLAR_BUDGET
    try:
        v = float(raw)
    except ValueError:
        return _DEFAULT_DOLLAR_BUDGET
    return v if v > 0 else _DEFAULT_DOLLAR_BUDGET


def ensure(state: dict[str, Any]) -> None:
    state.setdefault("tokens_used", 0)
    state.setdefault("tokens_budget", _token_budget_default())
    state.setdefault("dollars_used", 0.0)
    state.setdefault("dollars_budget", _dollar_budget_default())


def extract_usage(response: Any) -> tuple[int, int]:
    """Return (input_tokens, output_tokens) from an LLM response.

    Handles langchain ``usage_metadata`` (both providers normalize into
    input_tokens/output_tokens; Anthropic folds cache read/creation tokens
    into input_tokens) and falls back to raw ``response_metadata`` shapes.
    Public: chat and any future call sites share this one extractor.
    """
    um = getattr(response, "usage_metadata", None)
    if isinstance(um, dict):
        return (
            int(um.get("input_tokens") or 0),
            int(um.get("output_tokens") or 0),
        )
    rm = getattr(response, "response_metadata", None)
    if isinstance(rm, dict):
        usage = rm.get("usage") or rm.get("token_usage") or {}
        if isinstance(usage, dict):
            return (
                int(usage.get("input_tokens") or usage.get("prompt_tokens") or 0),
                int(usage.get("output_tokens") or usage.get("completion_tokens") or 0),
            )
    return (0, 0)


def _model_name(response: Any) -> str | None:
    """Pull the model identifier from the response (langchain populates this)."""
    rm = getattr(response, "response_metadata", None)
    if isinstance(rm, dict):
        for key in ("model_name", "model", "model_id"):
            v = rm.get(key)
            if isinstance(v, str) and v:
                return v
    return None


def _cost_dollars(input_tokens: int, output_tokens: int, model: str | None) -> float:
    normalized = _normalize_model(model)
    price = _MODEL_PRICES_PER_MTOK.get(normalized, _UNKNOWN_MODEL_FALLBACK)
    return (
        (input_tokens / 1_000_000.0) * price["input"]
        + (output_tokens / 1_000_000.0) * price["output"]
    )


def track(state: dict[str, Any], response: Any) -> int:
    """Accumulate token + dollar usage from a single LLM response.

    Returns the cumulative ``tokens_used`` for back-compat with the
    previous return shape; callers that need the dollar figure read
    ``state["dollars_used"]`` directly.
    """
    ensure(state)
    input_tokens, output_tokens = extract_usage(response)
    delta_tokens = input_tokens + output_tokens
    model = _model_name(response)
    delta_dollars = _cost_dollars(input_tokens, output_tokens, model)

    state["tokens_used"] = int(state["tokens_used"]) + delta_tokens
    state["dollars_used"] = float(state["dollars_used"]) + delta_dollars

    if delta_tokens or delta_dollars:
        logger.debug(
            "llm_call_tracked",
            model=model,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            delta_dollars=round(delta_dollars, 6),
            tokens_used=state["tokens_used"],
            tokens_budget=state["tokens_budget"],
            dollars_used=round(state["dollars_used"], 4),
            dollars_budget=state["dollars_budget"],
        )
    return state["tokens_used"]


def over_budget(state: dict[str, Any]) -> bool:
    """True when EITHER the token cap OR the dollar cap is exceeded.

    Either-or rather than and-and: dollars is the load-bearing cap, but
    keeping the token check lets the existing 30k-token demo override
    still bite even when the model name isn't priced.
    """
    ensure(state)
    if int(state["tokens_used"]) >= int(state["tokens_budget"]):
        return True
    if float(state["dollars_used"]) >= float(state["dollars_budget"]):
        return True
    return False


def reason(state: dict[str, Any]) -> str:
    """Human-readable explanation of which cap fired."""
    ensure(state)
    parts: list[str] = []
    if int(state["tokens_used"]) >= int(state["tokens_budget"]):
        parts.append(f"tokens={state['tokens_used']}/{state['tokens_budget']}")
    if float(state["dollars_used"]) >= float(state["dollars_budget"]):
        parts.append(
            f"dollars=${state['dollars_used']:.2f}/${state['dollars_budget']:.2f}"
        )
    return "; ".join(parts) if parts else "within budget"
