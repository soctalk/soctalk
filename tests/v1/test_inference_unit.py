"""DB-free unit tests for the InferenceRequest seam (issue #32).

Covers tier resolution (legacy mappings + per-tier overlay + provider
scoping), decoding-mode resolution across engines/providers, and the
ainvoke_request dispatcher: schema-validation retry parity with the old
ainvoke_structured, single-funnel accounting through budget.track, the
unconstrained path, and reason-then-extract (reasoning unconstrained, only
the extraction carries the schema).
"""

from __future__ import annotations

from typing import Any

import pytest
from langchain_core.messages import AIMessage, HumanMessage

from soctalk.config import LLMConfig
from soctalk.inference import (
    DecodingMode,
    ExtractionPolicy,
    InferenceAccounting,
    InferenceRequest,
    InferenceTier,
    ProviderEngine,
    SamplingParams,
    ainvoke_request,
    resolve_decoding_mode,
    resolve_tier,
)
from soctalk.llm import SchemaValidationError
from soctalk.models.state import SupervisorDecision

# --------------------------------------------------------------- tier resolve


def _cfg(**over) -> LLMConfig:
    base = dict(
        provider="anthropic", anthropic_api_key="a-key",
        fast_model="fast-m", reasoning_model="reason-m",
    )
    base.update(over)
    return LLMConfig(**base)


def test_resolve_tier_legacy_model_mappings():
    cfg = _cfg(chat_model="chat-m")
    assert resolve_tier(cfg, InferenceTier.ROUTER).model == "fast-m"
    assert resolve_tier(cfg, InferenceTier.EXTRACTION).model == "fast-m"
    assert resolve_tier(cfg, InferenceTier.REASONING).model == "reason-m"
    assert resolve_tier(cfg, InferenceTier.CHAT).model == "chat-m"


def test_resolve_tier_chat_falls_back_to_fast_when_unset():
    cfg = _cfg()  # chat_model defaults to ""
    assert resolve_tier(cfg, InferenceTier.CHAT).model == "fast-m"


def test_resolve_tier_model_override_wins():
    cfg = _cfg()
    r = resolve_tier(cfg, InferenceTier.ROUTER, model_override="override-m")
    assert r.model == "override-m"


def test_resolve_tier_scopes_config_to_one_provider():
    # Both keys set globally (the multi-provider case #4 enables) — the scoped
    # config must carry only the chosen provider's key so create_chat_model's
    # both-keys guard never trips.
    cfg = LLMConfig(provider="anthropic", anthropic_api_key="a", openai_api_key="o",
                    fast_model="fm", reasoning_model="rm")
    r = resolve_tier(cfg, InferenceTier.ROUTER)
    assert r.provider == "anthropic"
    assert r.llm_config.anthropic_api_key == "a"
    assert r.llm_config.openai_api_key == ""


def test_resolve_tier_overlay_repoints_by_config_alone():
    # A tier can be repointed to a different provider/model without touching
    # any call site — the acceptance criterion.
    cfg = _cfg(tiers={
        "reasoning": {"provider": "openai", "model": "gpt-5", "api_key": "o-key",
                      "base_url": "https://gw.internal/v1"},
    })
    r = resolve_tier(cfg, InferenceTier.REASONING)
    assert r.provider == "openai"
    assert r.model == "gpt-5"
    assert r.llm_config.openai_api_key == "o-key"
    assert r.llm_config.openai_base_url == "https://gw.internal/v1"
    assert r.llm_config.anthropic_api_key == ""
    # Other tiers are untouched by the overlay.
    assert resolve_tier(cfg, InferenceTier.ROUTER).provider == "anthropic"


def test_resolve_tier_engine_defaults_and_override():
    cfg = _cfg()
    assert resolve_tier(cfg, InferenceTier.ROUTER).engine == ProviderEngine.FRONTIER
    cfg2 = _cfg(tiers={"extraction": {"engine": "vllm", "base_url": "http://vllm:8000/v1"}})
    assert resolve_tier(cfg2, InferenceTier.EXTRACTION).engine == ProviderEngine.VLLM


# ------------------------------------------------------------ decoding resolve


def test_resolve_decoding_auto_anthropic_schema_is_tool_use():
    assert resolve_decoding_mode(
        DecodingMode.AUTO, engine=ProviderEngine.FRONTIER, provider="anthropic",
        has_schema=True, has_grammar=False,
    ) == DecodingMode.TOOL_USE


def test_resolve_decoding_auto_openai_schema_is_json_schema():
    assert resolve_decoding_mode(
        DecodingMode.AUTO, engine=ProviderEngine.FRONTIER, provider="openai",
        has_schema=True, has_grammar=False,
    ) == DecodingMode.JSON_SCHEMA_STRICT


def test_resolve_decoding_auto_vllm_schema_is_guided_json():
    assert resolve_decoding_mode(
        DecodingMode.AUTO, engine=ProviderEngine.VLLM, provider="openai",
        has_schema=True, has_grammar=False,
    ) == DecodingMode.GUIDED_JSON


def test_resolve_decoding_auto_grammar_is_guided_grammar():
    assert resolve_decoding_mode(
        DecodingMode.AUTO, engine=ProviderEngine.SGLANG, provider="openai",
        has_schema=False, has_grammar=True,
    ) == DecodingMode.GUIDED_GRAMMAR


def test_resolve_decoding_auto_no_schema_is_none():
    assert resolve_decoding_mode(
        DecodingMode.AUTO, engine=ProviderEngine.FRONTIER, provider="anthropic",
        has_schema=False, has_grammar=False,
    ) == DecodingMode.NONE


def test_resolve_decoding_guided_rejected_on_frontier():
    with pytest.raises(ValueError):
        resolve_decoding_mode(
            DecodingMode.GUIDED_JSON, engine=ProviderEngine.FRONTIER, provider="openai",
            has_schema=True, has_grammar=False,
        )


def test_resolve_decoding_auto_grammar_rejected_on_frontier():
    # A raw grammar can't be honoured by a frontier API; AUTO must reject
    # rather than silently degrade to a schema-less tool_use.
    with pytest.raises(ValueError):
        resolve_decoding_mode(
            DecodingMode.AUTO, engine=ProviderEngine.FRONTIER, provider="openai",
            has_schema=False, has_grammar=True,
        )


def test_resolve_decoding_json_schema_on_anthropic_downgrades_to_tool_use():
    assert resolve_decoding_mode(
        DecodingMode.JSON_SCHEMA_STRICT, engine=ProviderEngine.FRONTIER, provider="anthropic",
        has_schema=True, has_grammar=False,
    ) == DecodingMode.TOOL_USE


# ------------------------------------------------------------ dispatcher fakes


class _FakeStructured:
    def __init__(self, results):
        self.results = results
        self.calls: list[Any] = []

    async def ainvoke(self, messages):
        self.calls.append(list(messages))
        return self.results[len(self.calls) - 1]


class _FakeLLM:
    def __init__(self, structured=None, plain=None):
        self._structured = _FakeStructured(structured or [])
        self._plain = plain or []
        self.plain_calls: list[Any] = []
        self.structured_schema = None
        self.bound_tools: list[Any] = []

    def with_structured_output(self, schema, include_raw=False):
        assert include_raw is True, "must keep raw for usage tracking"
        self.structured_schema = schema
        return self._structured

    async def ainvoke(self, messages):
        self.plain_calls.append(list(messages))
        return self._plain[len(self.plain_calls) - 1]

    def bind_tools(self, tools):
        self.bound_tools.extend(tools)
        return self


def _decision(**over):
    base = dict(next_action="ENRICH", action_reasoning="r", tp_confidence=0.5)
    base.update(over)
    return SupervisorDecision(**base)


@pytest.fixture
def patch_seams(monkeypatch):
    """Patch create_chat_model to return a supplied fake and capture tracks."""
    tracked: list[Any] = []
    monkeypatch.setattr("soctalk.graph.budget.track",
                        lambda state, raw: tracked.append(raw))

    def _install(fake):
        monkeypatch.setattr("soctalk.inference.create_chat_model",
                            lambda *a, **k: fake)
        return tracked

    return _install


def _req(**over):
    base = dict(
        tier=InferenceTier.ROUTER,
        metadata=InferenceAccounting(producer="test", budget_state={}),
        output_schema=SupervisorDecision,
        system="sys",
        messages=[HumanMessage(content="go")],
        sampling=SamplingParams(temperature=0.0, max_tokens=1024),
    )
    base.update(over)
    return InferenceRequest(**base)


# -------------------------------------------------------- dispatcher behaviour


async def test_dispatch_happy_path_parses_and_tracks_once(patch_seams):
    raw = AIMessage(content="", usage_metadata={"input_tokens": 5, "output_tokens": 3, "total_tokens": 8})
    fake = _FakeLLM(structured=[{"raw": raw, "parsed": _decision(), "parsing_error": None}])
    tracked = patch_seams(fake)

    res = await ainvoke_request(_req(), cfg=_cfg())

    assert res.parsed.next_action == "ENRICH"
    assert res.attempts == 1
    assert tracked == [raw], "raw funnelled through budget.track exactly once"
    assert res.resolved.model == "fast-m"


async def test_dispatch_no_budget_state_skips_tracking(patch_seams):
    raw = AIMessage(content="", usage_metadata={"input_tokens": 1, "output_tokens": 1, "total_tokens": 2})
    fake = _FakeLLM(structured=[{"raw": raw, "parsed": _decision(), "parsing_error": None}])
    tracked = patch_seams(fake)

    req = _req(metadata=InferenceAccounting(producer="test", budget_state=None))
    await ainvoke_request(req, cfg=_cfg())
    assert tracked == [], "budget_state=None means no accounting"


async def test_dispatch_retries_once_with_error_feedback(patch_seams):
    bad = AIMessage(content="garbage")
    good = AIMessage(content="")
    fake = _FakeLLM(structured=[
        {"raw": bad, "parsed": None, "parsing_error": "bad enum"},
        {"raw": good, "parsed": _decision(next_action="VERDICT"), "parsing_error": None},
    ])
    tracked = patch_seams(fake)

    res = await ainvoke_request(_req(), cfg=_cfg())

    assert res.parsed.next_action == "VERDICT"
    assert res.attempts == 2
    assert tracked == [bad, good], "both raws tracked (retry usage not lost)"
    retry_msgs = fake._structured.calls[1]
    assert "bad enum" in retry_msgs[-1].content
    assert "SupervisorDecision" in retry_msgs[-1].content


async def test_dispatch_fails_after_second_validation_error(patch_seams):
    fake = _FakeLLM(structured=[
        {"raw": AIMessage(content="g1"), "parsed": None, "parsing_error": "e1"},
        {"raw": AIMessage(content="g2"), "parsed": None, "parsing_error": "e2"},
    ])
    patch_seams(fake)
    with pytest.raises(SchemaValidationError):
        await ainvoke_request(_req(), cfg=_cfg())


async def test_dispatch_unconstrained_when_no_schema(patch_seams):
    raw = AIMessage(content="free text answer",
                    usage_metadata={"input_tokens": 4, "output_tokens": 6, "total_tokens": 10})
    fake = _FakeLLM(plain=[raw])
    tracked = patch_seams(fake)

    req = _req(output_schema=None)
    res = await ainvoke_request(req, cfg=_cfg())

    assert res.parsed is None
    assert res.text == "free text answer"
    assert res.resolved.decoding_mode == DecodingMode.NONE  # AUTO resolved to NONE (no schema)
    assert tracked == [raw]
    assert fake._structured.calls == [], "no schema => no with_structured_output"


async def test_reason_then_extract_reasoning_unconstrained_only_extract_carries_schema(patch_seams):
    reasoning = AIMessage(content="Here is my step-by-step analysis...",
                          usage_metadata={"input_tokens": 10, "output_tokens": 20, "total_tokens": 30})
    extract_raw = AIMessage(content="",
                            usage_metadata={"input_tokens": 30, "output_tokens": 5, "total_tokens": 35})
    fake = _FakeLLM(
        plain=[reasoning],
        structured=[{"raw": extract_raw, "parsed": _decision(next_action="VERDICT"), "parsing_error": None}],
    )
    tracked = patch_seams(fake)

    req = _req(extraction_policy=ExtractionPolicy.REASON_THEN_EXTRACT)
    res = await ainvoke_request(req, cfg=_cfg())

    # The reasoning call went through plain ainvoke (NO schema constraint).
    assert len(fake.plain_calls) == 1
    assert fake.structured_schema is SupervisorDecision  # schema bound only for extraction
    # The extraction call saw the reasoning output + an extract instruction.
    extract_msgs = fake._structured.calls[0]
    assert reasoning in extract_msgs
    assert any(
        isinstance(getattr(m, "content", None), str) and "extract" in m.content.lower()
        for m in extract_msgs
    )
    # Result is the extracted structure; both calls accounted for.
    assert res.parsed.next_action == "VERDICT"
    assert tracked == [reasoning, extract_raw]
    assert res.text == "Here is my step-by-step analysis..."
    # Returned usage sums BOTH calls (reasoning 10/20 + extraction 30/5).
    assert res.usage.input_tokens == 40
    assert res.usage.output_tokens == 25


async def test_dispatch_honors_tier_default_decoding_mode(patch_seams):
    # A tier that configures default_decoding_mode must have it take effect even
    # when the request leaves decoding_mode=AUTO. json_schema_strict on an
    # anthropic tier downgrades to tool_use (still a constrained structured call).
    raw = AIMessage(content="", usage_metadata={"input_tokens": 1, "output_tokens": 1, "total_tokens": 2})
    fake = _FakeLLM(structured=[{"raw": raw, "parsed": _decision(), "parsing_error": None}])
    patch_seams(fake)
    cfg = _cfg(tiers={"router": {"default_decoding_mode": "json_schema_strict"}})

    res = await ainvoke_request(_req(), cfg=cfg)  # req.decoding_mode stays AUTO
    assert res.parsed.next_action == "ENRICH"
    assert res.resolved.decoding_mode == DecodingMode.TOOL_USE  # json_schema on anthropic -> tool_use


async def test_dispatch_rejects_guided_modes_until_issue_13(patch_seams):
    # A vLLM tier resolves AUTO+schema to guided_json, which has no served-engine
    # shaping yet — the dispatcher must refuse loudly, not silently run it.
    fake = _FakeLLM(structured=[])
    patch_seams(fake)
    cfg = _cfg(tiers={"router": {"engine": "vllm", "base_url": "http://vllm:8000/v1"}})
    with pytest.raises(NotImplementedError):
        await ainvoke_request(_req(), cfg=cfg)
