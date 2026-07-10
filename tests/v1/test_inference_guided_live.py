"""Live behavioural test for served-engine native guided decoding (#13 seam),
parametrized over SGLang and vLLM.

The same ``InferenceRequest`` — one JSON-schema constraint, one EBNF grammar —
is run against whichever engine endpoints are provided, proving both that the
constraint is HONOURED by a real server and that the identical envelope works
across engines (the point of the abstraction). A fake client can't prove
either.

Provide one or both endpoints (weights served OpenAI-compatible):

    SGLANG_BASE_URL=https://<host>/v1  SGLANG_API_KEY=<bearer>  SGLANG_MODEL=Qwen/Qwen3-14B \
    VLLM_BASE_URL=https://<host>/v1    VLLM_API_KEY=<bearer>    VLLM_MODEL=Qwen/Qwen3-14B \
    pytest tests/v1/test_inference_guided_live.py -q
"""

from __future__ import annotations

import os
from typing import Literal

import pytest
from langchain_core.messages import HumanMessage
from pydantic import BaseModel

from soctalk.config import LLMConfig
from soctalk.inference import (
    DecodingMode,
    InferenceAccounting,
    InferenceRequest,
    InferenceTier,
    SamplingParams,
    ainvoke_request,
)


class _YesNo(BaseModel):
    """A tight, bounded schema: one enum field, so the constrained output is a
    few tokens and can't overrun the budget (unlike a schema with a free-text
    field)."""

    answer: Literal["yes", "no"]


# The xgrammar EBNF dialect is shared by SGLang and vLLM, so one grammar string
# works for both; only the request field that carries it differs (handled in
# inference.guided_request_kwargs).
_GRAMMAR = 'root ::= "yes" | "no"'
# Qwen3 is a reasoning model; ``/no_think`` disables its <think> block for the
# SGLang endpoint (the vLLM service disables thinking server-side).
_NO_THINK = " /no_think"


def _engines() -> list[tuple[str, str, str, str]]:
    out: list[tuple[str, str, str, str]] = []
    default_model = os.getenv("SGLANG_MODEL", "Qwen/Qwen3-14B")
    if os.getenv("SGLANG_BASE_URL"):
        out.append(("sglang", os.environ["SGLANG_BASE_URL"],
                    os.getenv("SGLANG_API_KEY", "x"),
                    os.getenv("SGLANG_MODEL", default_model)))
    if os.getenv("VLLM_BASE_URL"):
        out.append(("vllm", os.environ["VLLM_BASE_URL"],
                    os.getenv("VLLM_API_KEY", "x"),
                    os.getenv("VLLM_MODEL", default_model)))
    return out


_ENGINES = _engines()

pytestmark = pytest.mark.skipif(
    not _ENGINES,
    reason="set SGLANG_BASE_URL and/or VLLM_BASE_URL (+ *_API_KEY, *_MODEL) to live endpoints",
)


def _cfg(engine: str, base_url: str, api_key: str, model: str) -> LLMConfig:
    tier = {"engine": engine, "model": model, "base_url": base_url, "api_key": api_key}
    return LLMConfig(
        provider="openai", openai_api_key=api_key, openai_base_url=base_url,
        fast_model=model, reasoning_model=model,
        tiers={"router": tier, "reasoning": tier},
    )


def _meta() -> InferenceAccounting:
    return InferenceAccounting(producer="live-test", budget_state=None)


@pytest.mark.parametrize("engine,base_url,api_key,model", _ENGINES,
                         ids=[e[0] for e in _ENGINES])
async def test_ebnf_grammar_constrains_output(engine, base_url, api_key, model):
    # A grammar admitting only "yes"/"no" must force the output into that set,
    # even though the prompt asks for a detailed explanation.
    req = InferenceRequest(
        tier=InferenceTier.REASONING, metadata=_meta(),
        grammar=_GRAMMAR, output_schema=None,
        system="You answer questions.",
        messages=[HumanMessage(content="Is water wet? Explain in detail." + _NO_THINK)],
        sampling=SamplingParams(temperature=0.0, max_tokens=16),
    )
    res = await ainvoke_request(req, cfg=_cfg(engine, base_url, api_key, model))
    assert res.resolved.decoding_mode == DecodingMode.GUIDED_GRAMMAR
    assert (res.text or "").strip() in {"yes", "no"}, (
        f"[{engine}] grammar not honoured: {res.text!r}"
    )


@pytest.mark.parametrize("engine,base_url,api_key,model", _ENGINES,
                         ids=[e[0] for e in _ENGINES])
async def test_json_schema_constrains_output(engine, base_url, api_key, model):
    req = InferenceRequest(
        tier=InferenceTier.ROUTER, metadata=_meta(),
        output_schema=_YesNo,
        system="You answer questions.",
        messages=[HumanMessage(content=(
            "Is water wet? Answer at length with lots of detail." + _NO_THINK
        ))],
        sampling=SamplingParams(temperature=0.0, max_tokens=64),
    )
    res = await ainvoke_request(req, cfg=_cfg(engine, base_url, api_key, model))
    assert res.resolved.decoding_mode == DecodingMode.GUIDED_JSON
    assert res.parsed is not None, f"[{engine}] schema not honoured: {res.text!r}"
    assert isinstance(res.parsed, _YesNo)
    assert res.parsed.answer in {"yes", "no"}


@pytest.mark.parametrize("engine,base_url,api_key,model", _ENGINES,
                         ids=[e[0] for e in _ENGINES])
async def test_unconstrained_is_not_yes_or_no(engine, base_url, api_key, model):
    # The SAME prompt without a constraint produces free prose, proving the
    # constraint (not the prompt) bounds the output above.
    req = InferenceRequest(
        tier=InferenceTier.REASONING, metadata=_meta(),
        output_schema=None,
        system="You answer questions.",
        messages=[HumanMessage(content="Is water wet? Explain in detail." + _NO_THINK)],
        sampling=SamplingParams(temperature=0.0, max_tokens=64),
    )
    res = await ainvoke_request(req, cfg=_cfg(engine, base_url, api_key, model))
    assert res.resolved.decoding_mode == DecodingMode.NONE
    assert (res.text or "").strip() not in {"yes", "no"}, (
        f"[{engine}] unconstrained output was exactly yes/no — weaken this check"
    )
