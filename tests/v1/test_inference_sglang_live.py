"""Live behavioural test for SGLang native guided decoding (issue #13 seam).

Verifies that the constraint is actually HONOURED by a real SGLang server —
an EBNF grammar forces output into the grammar's language, and a JSON schema
forces valid, schema-conforming JSON — which a unit test with a fake client
cannot prove. This is the "EBNF constraints vs standard JSON schema" check.

Skipped unless a live SGLang OpenAI-compatible endpoint is provided:

    SGLANG_BASE_URL=https://<host>/v1 \
    SGLANG_API_KEY=<bearer> \
    SGLANG_MODEL=Qwen/Qwen3-14B \
    pytest tests/v1/test_inference_sglang_live.py -q
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
    """A minimal, tightly-bounded schema for the behavioural test: a single
    enum field, so the constrained output is a handful of tokens and can't
    overrun the budget (unlike a schema with a free-text reasoning field)."""

    answer: Literal["yes", "no"]


# Qwen3 is a reasoning model; ``/no_think`` disables its <think> block so a
# constrained answer isn't preceded by budget-consuming chain-of-thought. The
# grammar/schema is what we're testing, not the reasoning.
_NO_THINK = " /no_think"

BASE_URL = os.getenv("SGLANG_BASE_URL")
MODEL = os.getenv("SGLANG_MODEL", "Qwen/Qwen3-14B")

pytestmark = pytest.mark.skipif(
    not BASE_URL,
    reason="set SGLANG_BASE_URL (+ SGLANG_API_KEY, SGLANG_MODEL) to a live SGLang endpoint",
)


def _cfg() -> LLMConfig:
    # One tier pointed at the live SGLang endpoint via the OpenAI-compatible path.
    return LLMConfig(
        provider="openai",
        openai_api_key=os.getenv("SGLANG_API_KEY", "x"),
        openai_base_url=BASE_URL,
        fast_model=MODEL,
        reasoning_model=MODEL,
        tiers={
            "router": {"engine": "sglang", "model": MODEL,
                       "base_url": BASE_URL, "api_key": os.getenv("SGLANG_API_KEY", "x")},
            "reasoning": {"engine": "sglang", "model": MODEL,
                          "base_url": BASE_URL, "api_key": os.getenv("SGLANG_API_KEY", "x")},
        },
    )


def _meta() -> InferenceAccounting:
    return InferenceAccounting(producer="live-test", budget_state=None)


async def test_ebnf_grammar_constrains_output_to_its_language():
    # A grammar admitting only "yes" or "no" must force the output into that set,
    # regardless of what the model would otherwise say. The prompt deliberately
    # asks for a long explanation — the grammar must win anyway.
    grammar = 'root ::= "yes" | "no"'
    req = InferenceRequest(
        tier=InferenceTier.REASONING,
        metadata=_meta(),
        grammar=grammar,
        output_schema=None,
        system="You answer questions.",
        messages=[HumanMessage(content="Is water wet? Explain in detail." + _NO_THINK)],
        sampling=SamplingParams(temperature=0.0, max_tokens=16),
    )
    res = await ainvoke_request(req, cfg=_cfg())
    assert res.resolved.decoding_mode == DecodingMode.GUIDED_GRAMMAR
    assert (res.text or "").strip() in {"yes", "no"}, f"grammar not honoured: {res.text!r}"


async def test_json_schema_constrains_output_to_valid_schema():
    # The same endpoint, a JSON-schema constraint on a tight enum schema: the
    # parsed result must be a valid _YesNo. The prompt again invites a long
    # answer; the schema must force short, valid JSON.
    req = InferenceRequest(
        tier=InferenceTier.ROUTER,
        metadata=_meta(),
        output_schema=_YesNo,
        system="You answer questions.",
        messages=[HumanMessage(content=(
            "Is water wet? Answer at length with lots of detail." + _NO_THINK
        ))],
        sampling=SamplingParams(temperature=0.0, max_tokens=64),
    )
    res = await ainvoke_request(req, cfg=_cfg())
    assert res.resolved.decoding_mode == DecodingMode.GUIDED_JSON
    assert res.parsed is not None, f"schema not honoured: {res.text!r}"
    assert isinstance(res.parsed, _YesNo)
    assert res.parsed.answer in {"yes", "no"}


async def test_unconstrained_would_not_be_yes_or_no():
    # Contrast: the SAME prompt without a constraint produces free prose, proving
    # the constraint (not the prompt) is what bounds the output above.
    req = InferenceRequest(
        tier=InferenceTier.REASONING,
        metadata=_meta(),
        output_schema=None,
        system="You answer questions.",
        messages=[HumanMessage(content="Is water wet? Explain in detail." + _NO_THINK)],
        sampling=SamplingParams(temperature=0.0, max_tokens=64),
    )
    res = await ainvoke_request(req, cfg=_cfg())
    assert res.resolved.decoding_mode == DecodingMode.NONE
    assert (res.text or "").strip() not in {"yes", "no"}, (
        "unconstrained output happened to be exactly yes/no — weaken this check"
    )
