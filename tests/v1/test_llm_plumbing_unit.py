"""DB-free unit tests for the Tier-2 LLM plumbing.

Covers error classification, transport bounds, usage extraction across
provider metadata shapes, structured-output retry semantics, and the
supervisor failure path (no fabricated decisions).
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest
from langchain_core.messages import AIMessage, HumanMessage

from soctalk.config import LLMConfig
from soctalk.graph.budget import extract_usage
from soctalk.graph.builder import route_from_supervisor
from soctalk.llm import (
    SchemaValidationError,
    ainvoke_structured,
    classify_llm_error,
    create_chat_model,
)
from soctalk.models.state import SupervisorDecision

# ---------------------------------------------------------------------------
# classify_llm_error
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "exc,expected",
    [
        (Exception("Your credit balance is too low"), "insufficient_credit"),
        (Exception("insufficient_quota for this org"), "insufficient_credit"),
        (Exception("rate limit exceeded, tokens per minute"), "rate_limited"),
        (TimeoutError("request timed out"), "timeout"),
        (SchemaValidationError("2 validation errors"), "schema_validation"),
        (Exception("something odd"), "unknown"),
    ],
)
def test_classify_llm_error(exc, expected):
    assert classify_llm_error(exc) == expected


def test_classify_llm_error_status_code():
    e = Exception("boom")
    e.status_code = 503
    assert classify_llm_error(e) == "provider_error"
    e429 = Exception("slow down")
    e429.status_code = 429
    assert classify_llm_error(e429) == "rate_limited"


# ---------------------------------------------------------------------------
# create_chat_model transport bounds
# ---------------------------------------------------------------------------


def test_create_chat_model_bounds_timeout_and_retries():
    cfg = LLMConfig(
        provider="anthropic",
        anthropic_api_key="test-key",
        fast_model="m",
        reasoning_model="m",
        timeout_seconds=45.0,
        max_retries=1,
    )
    m = create_chat_model(cfg, model="claude-sonnet-4-6", temperature=0, max_tokens=64)
    assert m.default_request_timeout == 45.0
    assert m.max_retries == 1


def test_create_chat_model_openai_passes_scoped_api_key():
    # The OpenAI branch must pass the configured key explicitly (not rely on
    # ambient OPENAI_API_KEY) so per-tier scoped api_key overlays (#32) reach
    # the client — regression for a key that was validated but never forwarded.
    cfg = LLMConfig(
        provider="openai",
        openai_api_key="sk-scoped-xyz",
        fast_model="gpt-4o",
        reasoning_model="gpt-4o",
    )
    m = create_chat_model(cfg, model="gpt-4o", temperature=0, max_tokens=64)
    assert m.openai_api_key.get_secret_value() == "sk-scoped-xyz"


# ---------------------------------------------------------------------------
# extract_usage across provider shapes
# ---------------------------------------------------------------------------


def test_extract_usage_langchain_usage_metadata_anthropic_shape():
    msg = AIMessage(
        content="x",
        usage_metadata={
            "input_tokens": 2500,
            "output_tokens": 150,
            "total_tokens": 2650,
            "input_token_details": {"cache_read": 2000, "cache_creation": 300},
        },
    )
    assert extract_usage(msg) == (2500, 150)


def test_extract_usage_langchain_usage_metadata_openai_shape():
    msg = AIMessage(
        content="x",
        usage_metadata={
            "input_tokens": 900,
            "output_tokens": 80,
            "total_tokens": 980,
            "input_token_details": {"audio": 0, "cache_read": 512},
            "output_token_details": {"reasoning": 20},
        },
    )
    assert extract_usage(msg) == (900, 80)


def test_extract_usage_raw_response_metadata_fallbacks():
    openai_raw = SimpleNamespace(
        usage_metadata=None,
        response_metadata={"token_usage": {"prompt_tokens": 11, "completion_tokens": 7}},
    )
    assert extract_usage(openai_raw) == (11, 7)
    empty = SimpleNamespace(usage_metadata=None, response_metadata=None)
    assert extract_usage(empty) == (0, 0)


# ---------------------------------------------------------------------------
# ainvoke_structured: retry-once-then-fail semantics
# ---------------------------------------------------------------------------


class _FakeStructured:
    """Stands in for llm.with_structured_output(...) — returns queued results."""

    def __init__(self, results: list[dict[str, Any]]):
        self.results = results
        self.calls: list[Any] = []

    async def ainvoke(self, messages):
        self.calls.append(messages)
        return self.results[len(self.calls) - 1]


class _FakeLLM:
    def __init__(self, results):
        self.structured = _FakeStructured(results)

    def with_structured_output(self, schema, include_raw=False):
        assert include_raw is True, "must keep raw for usage tracking"
        return self.structured


def _decision(**over):
    base = dict(next_action="ENRICH", action_reasoning="r", tp_confidence=0.5)
    base.update(over)
    return SupervisorDecision(**base)


async def test_ainvoke_structured_happy_path_tracks_usage():
    raw = AIMessage(content="", usage_metadata={"input_tokens": 5, "output_tokens": 3, "total_tokens": 8})
    llm = _FakeLLM([{"raw": raw, "parsed": _decision(), "parsing_error": None}])
    tracked = []
    out = await ainvoke_structured(
        llm, SupervisorDecision, [HumanMessage(content="go")], on_response=tracked.append
    )
    assert out.next_action == "ENRICH"
    assert tracked == [raw]


async def test_ainvoke_structured_retries_once_with_error_feedback():
    bad_raw = AIMessage(content="garbage")
    good_raw = AIMessage(content="")
    llm = _FakeLLM([
        {"raw": bad_raw, "parsed": None, "parsing_error": "bad enum"},
        {"raw": good_raw, "parsed": _decision(next_action="VERDICT"), "parsing_error": None},
    ])
    tracked = []
    out = await ainvoke_structured(
        llm, SupervisorDecision, [HumanMessage(content="go")], on_response=tracked.append
    )
    assert out.next_action == "VERDICT"
    # both raw messages tracked (retry usage is not lost)
    assert tracked == [bad_raw, good_raw]
    # retry message carries the validation error back to the model
    retry_msgs = llm.structured.calls[1]
    assert "bad enum" in retry_msgs[-1].content
    assert "SupervisorDecision" in retry_msgs[-1].content


async def test_ainvoke_structured_fails_after_second_validation_error():
    llm = _FakeLLM([
        {"raw": AIMessage(content="g1"), "parsed": None, "parsing_error": "err1"},
        {"raw": AIMessage(content="g2"), "parsed": None, "parsing_error": "err2"},
    ])
    with pytest.raises(SchemaValidationError):
        await ainvoke_structured(llm, SupervisorDecision, [HumanMessage(content="go")])
    assert classify_llm_error(SchemaValidationError("x")) == "schema_validation"


# ---------------------------------------------------------------------------
# Supervisor failure path: no fabricated decisions, routes to close
# ---------------------------------------------------------------------------


async def test_supervisor_error_sets_category_not_decision(monkeypatch):
    from soctalk.supervisor import node as sup_node

    async def _boom(config, context, state=None):
        e = Exception("rate limit exceeded")
        e.status_code = 429
        raise e

    monkeypatch.setattr(sup_node, "_get_supervisor_decision", _boom)
    monkeypatch.setattr(sup_node, "get_config", lambda: SimpleNamespace(llm=None))

    state = {"investigation": {"alerts": []}, "pending_observables": [{"type": "ip", "value": "1.2.3.4"}]}
    out = await sup_node.supervisor_node(state)

    assert out["supervisor_error"] == {"category": "rate_limited"}
    assert out["last_error"] == "supervisor_failed:rate_limited"
    assert "supervisor_decision" not in out, "must not fabricate a decision"


def test_route_from_supervisor_error_goes_to_close():
    assert route_from_supervisor({"supervisor_error": {"category": "timeout"}}) == "close_investigation"
    assert route_from_supervisor({"supervisor_decision": {"next_action": "INVESTIGATE"}}) == "wazuh_worker"
