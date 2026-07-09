"""DB-free unit tests for prompt-cache stability (#2) and cache-aware
accounting / cache_control opt-in (#6)."""

from __future__ import annotations

import os
from types import SimpleNamespace

from langchain_core.messages import AIMessage

from soctalk.config import LLMConfig
from soctalk.graph.budget import _cost_dollars, extract_cache_details, track
from soctalk.llm import make_system_message


def _cfg(provider: str) -> LLMConfig:
    key = {"anthropic": "anthropic_api_key", "openai": "openai_api_key"}[provider]
    return LLMConfig(
        provider=provider, fast_model="m", reasoning_model="m", **{key: "test"}
    )


# ---------------------------------------------------------------------------
# make_system_message: cache_control opt-in per provider
# ---------------------------------------------------------------------------


def test_system_message_anthropic_carries_cache_control():
    msg = make_system_message("STATIC RUBRIC", _cfg("anthropic"))
    assert isinstance(msg.content, list)
    block = msg.content[0]
    assert block["text"] == "STATIC RUBRIC"
    assert block["cache_control"] == {"type": "ephemeral"}


def test_system_message_openai_stays_plain():
    msg = make_system_message("STATIC RUBRIC", _cfg("openai"))
    assert msg.content == "STATIC RUBRIC"


# ---------------------------------------------------------------------------
# Prompt ordering: static head, volatile tail
# ---------------------------------------------------------------------------


def test_supervisor_context_prefix_stable_across_iterations():
    from soctalk.supervisor.node import _build_context_summary

    base = {
        "investigation": {
            "alerts": [
                {"severity": 9, "rule_description": "ssh brute force",
                 "source": {"agent_name": "agent-1"}},
            ],
        },
    }
    o1 = _build_context_summary({**base, "iteration_count": 1, "current_phase": "triage"})
    o2 = _build_context_summary({**base, "iteration_count": 7, "current_phase": "analysis"})

    common = os.path.commonprefix([o1, o2])
    # Everything except the volatile tail must be byte-identical.
    assert o1.startswith("### Alerts")
    assert "**Iteration:**" in o1[len(common) - 20:]
    assert o1.rstrip().endswith("**Phase:** triage")


def test_verdict_template_metadata_at_tail():
    from soctalk.supervisor.verdict import VERDICT_USER_PROMPT_TEMPLATE as T

    assert T.index("{alerts_detail}") < T.index("{supervisor_action}")
    assert T.index("{supervisor_action}") < T.index("{investigation_id}")
    assert T.index("{investigation_id}") < T.index("{duration}")


def test_supervisor_user_template_is_context_only():
    from soctalk.supervisor.prompts import (
        SUPERVISOR_SYSTEM_PROMPT,
        SUPERVISOR_USER_PROMPT_TEMPLATE,
    )

    # Task instructions moved to the cacheable system prompt.
    assert "next_action" in SUPERVISOR_SYSTEM_PROMPT
    assert "next_action" not in SUPERVISOR_USER_PROMPT_TEMPLATE
    assert "{context_summary}" in SUPERVISOR_USER_PROMPT_TEMPLATE


# ---------------------------------------------------------------------------
# Cache-aware accounting
# ---------------------------------------------------------------------------


def _anthropic_msg(inp, out, read=0, creation=0):
    return AIMessage(
        content="x",
        usage_metadata={
            "input_tokens": inp,
            "output_tokens": out,
            "total_tokens": inp + out,
            "input_token_details": {"cache_read": read, "cache_creation": creation},
        },
        response_metadata={"model_name": "claude-sonnet-4-6"},
    )


def test_extract_cache_details():
    assert extract_cache_details(_anthropic_msg(3000, 100, read=2500, creation=200)) == (2500, 200)
    assert extract_cache_details(AIMessage(content="x")) == (0, 0)
    assert extract_cache_details(SimpleNamespace(usage_metadata=None)) == (0, 0)


def test_cached_call_costs_less_than_uncached():
    uncached = _cost_dollars(10_000, 500, "claude-sonnet-4-6")
    cached = _cost_dollars(
        10_000, 500, "claude-sonnet-4-6", cache_read_tokens=9_000
    )
    assert cached < uncached
    # 9k of 10k input at 10% rate: expected ratio on the input component.
    assert cached / uncached < 0.5


def test_cache_write_costs_more_than_plain_input():
    plain = _cost_dollars(10_000, 0, "claude-sonnet-4-6")
    writing = _cost_dollars(
        10_000, 0, "claude-sonnet-4-6", cache_creation_tokens=10_000
    )
    assert writing > plain
    assert abs(writing / plain - 1.25) < 0.01


def test_cache_tokens_clamped_to_input():
    # Malformed metadata (cache > input) must not produce negative cost.
    v = _cost_dollars(1_000, 0, "claude-sonnet-4-6", cache_read_tokens=5_000)
    assert v > 0


def test_track_accumulates_cache_stats():
    state: dict = {}
    track(state, _anthropic_msg(3000, 100, read=2500, creation=200))
    track(state, _anthropic_msg(3000, 100, read=2700, creation=0))
    assert state["cache_read_tokens"] == 5200
    assert state["cache_creation_tokens"] == 200
    assert state["tokens_used"] == 2 * 3100
