"""Unified structured-inference request abstraction (issue #32).

An LLM call has two sides. On the OUTPUT side, structured inference means the
model returns a value conforming to a schema (constrained via tool-use,
json-schema, or a served engine's guided decoding) — machine-consumable by
construction, or it fails loudly. On the INPUT side, the request is a typed
envelope carrying everything the call needs — tier, output schema, decoding
mode, sampling, tools, accounting — dispatched through ONE seam and funnelled
through the accounting that already exists (``graph/budget.track``).

This is the foundation the rest of the inference-alignment program builds on:
per-tier providers (#4), self-hosted serving via the decoding-mode seam (#13),
the chat agent (#10), and the compatibility harness (#9). ``llm.py`` stays the
provider factory; this module is the envelope + resolver + dispatcher.

Design note (research-grounded): schema enforcement is applied to the
EXTRACTION, never the reasoning. ``ExtractionPolicy.REASON_THEN_EXTRACT`` runs
an unconstrained reasoning call then a constrained extraction over its output
— "Let Me Speak Freely?" / dottxt "Say What You Mean" agree the harm is
premature serialization, not JSON.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from enum import Enum
from typing import Any, Generic, TypeVar

from langchain_core.messages import HumanMessage

from soctalk.config import LLMConfig
from soctalk.llm import (
    SchemaValidationError,
    create_chat_model,
    make_system_message,
)

T = TypeVar("T")


# --------------------------------------------------------------------- enums


class InferenceTier(str, Enum):
    ROUTER = "router"
    REASONING = "reasoning"
    CHAT = "chat"
    EXTRACTION = "extraction"


class ProviderEngine(str, Enum):
    FRONTIER = "frontier"                    # hosted Anthropic / OpenAI
    OPENAI_COMPATIBLE = "openai_compatible"  # generic gateway
    VLLM = "vllm"
    SGLANG = "sglang"


class DecodingMode(str, Enum):
    AUTO = "auto"
    NONE = "none"
    TOOL_USE = "tool_use"
    JSON_SCHEMA_STRICT = "json_schema_strict"
    GUIDED_JSON = "guided_json"
    GUIDED_GRAMMAR = "guided_grammar"


class ExtractionPolicy(str, Enum):
    SINGLE_CALL = "single_call"
    REASON_THEN_EXTRACT = "reason_then_extract"


# ------------------------------------------------------------- envelope types


@dataclass(frozen=True)
class SamplingParams:
    temperature: float = 0.0
    max_tokens: int = 1024


@dataclass(frozen=True)
class ToolSpec:
    """A tool binding passthrough (chat is the first real consumer, #10)."""

    tool: Any


@dataclass
class InferenceAccounting:
    """Where the response's usage is funnelled + who asked. ``budget_state``
    is the dict ``graph/budget.track`` reads usage into (the single accounting
    seam, #7); ``None`` means don't track (e.g. offline/eval calls)."""

    producer: str
    budget_state: dict[str, Any] | None = None
    investigation_id: str | None = None
    run_id: str | None = None
    conversation_id: str | None = None


@dataclass
class InferenceRequest:
    tier: InferenceTier
    metadata: InferenceAccounting
    decoding_mode: DecodingMode = DecodingMode.AUTO
    extraction_policy: ExtractionPolicy = ExtractionPolicy.SINGLE_CALL
    output_schema: type | None = None
    grammar: str | None = None
    # ``system`` is separate from ``messages`` so the dispatcher preserves the
    # provider-aware prompt-cache behaviour in make_system_message (Anthropic
    # block-form cache_control; OpenAI plain text).
    system: str | None = None
    messages: list[Any] = field(default_factory=list)
    sampling: SamplingParams = field(default_factory=SamplingParams)
    tools: list[ToolSpec] = field(default_factory=list)
    tool_choice: str | None = "auto"
    retry_schema_validation: int = 1
    model_override: str | None = None


@dataclass(frozen=True)
class ResolvedModel:
    tier: InferenceTier
    provider: str            # 'anthropic' | 'openai'
    engine: ProviderEngine
    model: str
    decoding_mode: DecodingMode
    llm_config: LLMConfig    # provider-scoped: only the chosen provider's key


@dataclass(frozen=True)
class UsageDelta:
    input_tokens: int
    output_tokens: int


@dataclass
class InferenceResult(Generic[T]):
    parsed: T | None
    raw_message: Any
    text: str | None
    tool_calls: list[Any]
    usage: UsageDelta
    resolved: ResolvedModel
    attempts: int
    parsing_error: str | None = None


# ------------------------------------------------------------- tier resolution


def _legacy_model_for_tier(cfg: LLMConfig, tier: InferenceTier) -> str:
    if tier == InferenceTier.REASONING:
        return cfg.reasoning_model
    if tier == InferenceTier.CHAT:
        return getattr(cfg, "chat_model", "") or cfg.fast_model
    # ROUTER / EXTRACTION
    return cfg.fast_model


def _scoped_config(cfg: LLMConfig, provider: str, base_url: str | None,
                   key: str | None) -> LLMConfig:
    """A per-tier LLMConfig carrying ONLY the chosen provider's key, so
    create_chat_model's both-keys guard never trips even when the global
    config has keys for multiple providers (the multi-provider seam #4 needs).
    """
    data = cfg.model_dump()
    data["provider"] = provider
    if provider == "anthropic":
        data["anthropic_api_key"] = key or cfg.anthropic_api_key
        data["anthropic_base_url"] = base_url or cfg.anthropic_base_url
        # Scrub the other provider entirely so create_chat_model's both-keys
        # guard can't trip and no stale base_url leaks across providers.
        data["openai_api_key"] = ""
        data["openai_base_url"] = None
    else:
        data["openai_api_key"] = key or cfg.openai_api_key
        data["openai_base_url"] = base_url or cfg.openai_base_url
        data["anthropic_api_key"] = ""
        data["anthropic_base_url"] = None
    return LLMConfig(**data)


def resolve_tier(
    cfg: LLMConfig, tier: InferenceTier, *, model_override: str | None = None,
) -> ResolvedModel:
    """Resolve a tier to provider/engine/model/decoding, overlaying the
    optional per-tier config field-by-field on legacy defaults.

    Legacy defaults preserve current behaviour: router/extraction -> global
    provider + fast_model; reasoning -> reasoning_model; chat -> chat_model.
    """
    tiers = getattr(cfg, "tiers", None) or {}
    tconf = tiers.get(tier.value) or tiers.get(tier) or {}

    provider = tconf.get("provider") or cfg.provider
    engine_raw = tconf.get("engine")
    engine = (
        ProviderEngine(engine_raw) if engine_raw
        else (ProviderEngine.FRONTIER if provider in ("anthropic", "openai")
              else ProviderEngine.OPENAI_COMPATIBLE)
    )
    model = model_override or tconf.get("model") or _legacy_model_for_tier(cfg, tier)
    decoding = DecodingMode(tconf.get("default_decoding_mode", "auto"))

    scoped = _scoped_config(
        cfg, provider,
        base_url=tconf.get("base_url"),
        key=tconf.get("api_key"),
    )
    return ResolvedModel(
        tier=tier, provider=provider, engine=engine, model=model,
        decoding_mode=decoding, llm_config=scoped,
    )


# --------------------------------------------------------- decoding-mode seam


def resolve_decoding_mode(
    requested: DecodingMode, *, engine: ProviderEngine, provider: str,
    has_schema: bool, has_grammar: bool,
) -> DecodingMode:
    """Resolve AUTO to a concrete mechanism once provider/engine is known
    (the #13 seam). Rejects modes an engine can't honour rather than
    silently degrading."""
    if requested != DecodingMode.AUTO:
        # Validate the explicit request against the engine.
        if requested in (DecodingMode.GUIDED_JSON, DecodingMode.GUIDED_GRAMMAR) \
                and engine in (ProviderEngine.FRONTIER,):
            raise ValueError(f"{requested.value} not available on {engine.value}")
        if requested == DecodingMode.JSON_SCHEMA_STRICT and provider == "anthropic":
            # Anthropic has no json-schema response_format; use tool_use.
            return DecodingMode.TOOL_USE
        return requested

    # AUTO resolution
    if not has_schema and not has_grammar:
        return DecodingMode.NONE
    if engine in (ProviderEngine.VLLM, ProviderEngine.SGLANG):
        return DecodingMode.GUIDED_GRAMMAR if has_grammar else DecodingMode.GUIDED_JSON
    if has_grammar:
        # Only served engines (vLLM/SGLang) can honour a raw grammar; a
        # frontier API can't, so don't silently degrade to a schema-less mode.
        raise ValueError(f"grammar decoding not available on {engine.value}")
    if provider == "anthropic":
        return DecodingMode.TOOL_USE
    # OpenAI frontier
    return DecodingMode.JSON_SCHEMA_STRICT if has_schema else DecodingMode.TOOL_USE


# ------------------------------------------------------------- the dispatcher


def _build_messages(req: InferenceRequest, resolved: ResolvedModel) -> list[Any]:
    msgs: list[Any] = []
    if req.system is not None:
        msgs.append(make_system_message(req.system, resolved.llm_config))
    msgs.extend(req.messages)
    return msgs


def _usage_of(raw: Any) -> UsageDelta:
    from soctalk.graph.budget import extract_usage
    i, o = extract_usage(raw)
    return UsageDelta(input_tokens=i, output_tokens=o)


def _track(req: InferenceRequest, raw: Any) -> None:
    if raw is not None and req.metadata.budget_state is not None:
        from soctalk.graph.budget import track
        track(req.metadata.budget_state, raw)


async def _invoke_structured(
    llm: Any, schema: type, messages: list[Any], req: InferenceRequest,
) -> tuple[Any, Any, str | None, int]:
    """Schema-enforced invoke with one validation retry (the ainvoke_structured
    logic, inlined so the dispatcher owns tracking + attempt counting).
    Returns (parsed, raw, parsing_error, attempts)."""
    structured = llm.with_structured_output(schema, include_raw=True)
    attempts = 0

    result = await structured.ainvoke(messages)
    attempts += 1
    raw = result.get("raw")
    _track(req, raw)
    if result.get("parsed") is not None:
        return result["parsed"], raw, None, attempts

    for _ in range(max(0, req.retry_schema_validation)):
        parsing_error = result.get("parsing_error")
        retry = list(messages)
        if raw is not None:
            retry.append(raw)
        retry.append(HumanMessage(content=(
            f"Your previous response failed validation against the "
            f"{getattr(schema, '__name__', 'output')} schema: {parsing_error}. "
            "Respond again, following the schema exactly."
        )))
        result = await structured.ainvoke(retry)
        attempts += 1
        raw = result.get("raw")
        _track(req, raw)
        if result.get("parsed") is not None:
            return result["parsed"], raw, None, attempts

    raise SchemaValidationError(str(result.get("parsing_error")))


async def ainvoke_request(
    req: InferenceRequest, *, cfg: LLMConfig,
) -> InferenceResult:
    """Execute an InferenceRequest through the single seam.

    Resolves tier -> provider/model/engine/decoding, constructs the model,
    builds prompt-cache-aware messages, applies the resolved decoding mode,
    invokes (with the schema-validation retry when constrained), and funnels
    every raw response through budget.track once.
    """
    resolved = resolve_tier(cfg, req.tier, model_override=req.model_override)
    # An explicit per-request mode wins; otherwise fall back to the tier's
    # configured default_decoding_mode (carried on resolved) before AUTO.
    requested_mode = req.decoding_mode
    if requested_mode == DecodingMode.AUTO and resolved.decoding_mode != DecodingMode.AUTO:
        requested_mode = resolved.decoding_mode
    mode = resolve_decoding_mode(
        requested_mode, engine=resolved.engine, provider=resolved.provider,
        has_schema=req.output_schema is not None, has_grammar=req.grammar is not None,
    )
    # Guided decoding needs the served-engine request shaping that only lands
    # with #13; until then refuse loudly rather than silently degrade a guided
    # request to unconstrained (a schema-less grammar request would otherwise
    # slip through the "output_schema is None" unconstrained branch below).
    if mode in (DecodingMode.GUIDED_JSON, DecodingMode.GUIDED_GRAMMAR):
        raise NotImplementedError(
            f"{mode.value} decoding requires the served-engine request shaping "
            "from issue #13 (vLLM/SGLang guided decoding is not yet wired through)."
        )

    llm = create_chat_model(
        resolved.llm_config,
        model=resolved.model,
        temperature=req.sampling.temperature,
        max_tokens=req.sampling.max_tokens,
    )
    for t in req.tools:
        llm = llm.bind_tools([t.tool])

    # REASON_THEN_EXTRACT: unconstrained reasoning, then constrained extraction.
    if req.extraction_policy == ExtractionPolicy.REASON_THEN_EXTRACT and req.output_schema:
        reason_msgs = _build_messages(req, resolved)
        reasoning = await llm.ainvoke(reason_msgs)
        _track(req, reasoning)
        extract_msgs = list(reason_msgs)
        extract_msgs.append(reasoning)
        extract_msgs.append(HumanMessage(content=(
            "Now extract the structured result from your reasoning above, "
            f"conforming exactly to the {getattr(req.output_schema, '__name__', 'schema')}."
        )))
        parsed, raw, err, attempts = await _invoke_structured(
            llm, req.output_schema, extract_msgs, req,
        )
        # usage covers BOTH calls (budget.track already saw each); the returned
        # field must not undercount the reasoning tokens.
        ru, eu = _usage_of(reasoning), _usage_of(raw)
        return InferenceResult(
            parsed=parsed, raw_message=raw,
            text=getattr(reasoning, "content", None),
            tool_calls=getattr(raw, "tool_calls", []) or [],
            usage=UsageDelta(ru.input_tokens + eu.input_tokens,
                             ru.output_tokens + eu.output_tokens),
            resolved=replace(resolved, decoding_mode=mode), attempts=attempts + 1,
            parsing_error=err,
        )

    messages = _build_messages(req, resolved)

    # Unconstrained.
    if mode == DecodingMode.NONE or req.output_schema is None:
        raw = await llm.ainvoke(messages)
        _track(req, raw)
        return InferenceResult(
            parsed=None, raw_message=raw,
            text=(raw.content if isinstance(getattr(raw, "content", None), str) else None),
            tool_calls=getattr(raw, "tool_calls", []) or [],
            usage=_usage_of(raw),
            resolved=replace(resolved, decoding_mode=mode), attempts=1,
        )

    # Constrained frontier decoding (tool_use / json_schema_strict) — both go
    # through with_structured_output, which selects the provider mechanism.
    # The resolved mode is recorded on ``resolved`` for observability; guided
    # served-engine modes are rejected above until #13 wires their shaping.
    parsed, raw, err, attempts = await _invoke_structured(
        llm, req.output_schema, messages, req,
    )
    return InferenceResult(
        parsed=parsed, raw_message=raw,
        text=None, tool_calls=getattr(raw, "tool_calls", []) or [],
        usage=_usage_of(raw),
        resolved=replace(resolved, decoding_mode=mode),
        attempts=attempts,
    )


__all__ = [
    "InferenceTier", "ProviderEngine", "DecodingMode", "ExtractionPolicy",
    "SamplingParams", "ToolSpec", "InferenceAccounting", "InferenceRequest",
    "ResolvedModel", "UsageDelta", "InferenceResult",
    "resolve_tier", "resolve_decoding_mode", "ainvoke_request",
]
