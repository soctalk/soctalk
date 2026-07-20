"""DeliveryProfile classification and the backend seam (#63).

The model-consumption abstraction keeps InferenceRequest uniform and derives a
per-backend DeliveryProfile from the resolved tier, so the cost and scheduling
layers can reason about readiness/billing/capabilities. Frontier, Modal served
endpoints, RunPod pods, Ollama, and generic OpenAI-compatible gateways must
classify distinctly from provider + engine + base URL.
"""

from __future__ import annotations

from soctalk.config import LLMConfig
from soctalk.inference import (
    BackendKind,
    DecodingMode,
    DeliveryProfile,
    InferenceResult,
    InferenceTier,
    ProviderEngine,
    ResolvedModel,
    SyncChatBackend,
    UsageDelta,
    UsageRecord,
    delivery_profile_for,
    resolve_backend,
    select_backend,
)


def _resolved(engine, *, provider="openai", base_url=None, model="m") -> ResolvedModel:
    data: dict = {"provider": provider}
    if provider == "openai":
        data["openai_base_url"] = base_url
    else:
        data["anthropic_base_url"] = base_url
    cfg = LLMConfig(**data)
    return ResolvedModel(
        tier=InferenceTier.ROUTER, provider=provider, engine=engine, model=model,
        decoding_mode=DecodingMode.AUTO, llm_config=cfg,
    )


def test_frontier_profile():
    p = delivery_profile_for(_resolved(ProviderEngine.FRONTIER, provider="anthropic"))
    assert p.kind is BackendKind.FRONTIER
    assert p.readiness == "warm" and p.billing == "per_token"
    assert p.capabilities.prompt_cache is True   # anthropic
    assert p.capabilities.batch_api is True
    assert p.capabilities.guided_json is False   # not a served engine


def test_default_frontier_engine_with_self_host_base_url_classifies_by_url():
    # The common self-host wiring: provider=openai + OPENAI_BASE_URL, which leaves
    # the engine at the default FRONTIER. It must classify by the URL, not as the
    # real frontier API (this is exactly how the bench eval reaches Modal/RunPod).
    modal = delivery_profile_for(_resolved(
        ProviderEngine.FRONTIER, base_url="https://u--app-serve.modal.run/v1"))
    assert modal.kind is BackendKind.MODAL
    runpod = delivery_profile_for(_resolved(
        ProviderEngine.FRONTIER, base_url="https://p-8000.proxy.runpod.net/v1"))
    assert runpod.kind is BackendKind.RUNPOD_POD
    # No override and no custom host is the real frontier API.
    real = delivery_profile_for(_resolved(ProviderEngine.FRONTIER, provider="openai"))
    assert real.kind is BackendKind.FRONTIER


def test_runpod_pod_from_proxy_url():
    p = delivery_profile_for(_resolved(
        ProviderEngine.VLLM, base_url="https://abc123-8000.proxy.runpod.net/v1"))
    assert p.kind is BackendKind.RUNPOD_POD
    assert p.billing == "per_gpu_second"
    assert p.readiness == "warm"          # a pod is an always-on VM
    assert p.capabilities.guided_json is True
    assert p.capabilities.prompt_cache is False


def test_modal_from_serve_url():
    p = delivery_profile_for(_resolved(
        ProviderEngine.SGLANG, base_url="https://user--app-serve.modal.run/v1"))
    assert p.kind is BackendKind.MODAL
    assert p.readiness == "scale_to_zero" and p.billing == "per_gpu_second"


def test_ollama_from_local_url():
    p = delivery_profile_for(_resolved(
        ProviderEngine.OPENAI_COMPATIBLE, base_url="http://localhost:11434/v1"))
    assert p.kind is BackendKind.OLLAMA
    assert p.billing == "free" and p.lifecycle == "local"


def test_generic_openai_compatible():
    p = delivery_profile_for(_resolved(
        ProviderEngine.OPENAI_COMPATIBLE, base_url="https://api.example.com/v1"))
    assert p.kind is BackendKind.OPENAI_COMPAT
    assert p.billing == "per_token"       # unknown gateway priced per-token


def test_runpod_serverless_is_job_not_pod():
    # api.runpod.ai is the serverless async-job endpoint (#64), which is
    # scale-to-zero, not the always-on pod behind proxy.runpod.net.
    p = delivery_profile_for(_resolved(
        ProviderEngine.OPENAI_COMPATIBLE,
        base_url="https://api.runpod.ai/v2/abc/openai/v1"))
    assert p.kind is BackendKind.RUNPOD_JOB
    assert p.readiness == "scale_to_zero" and p.billing == "per_gpu_second"


def test_generic_openai_compat_does_not_advertise_guided():
    # Guided decoding is only wired for vLLM/SGLang; a generic gateway must not
    # claim it, or a capability consumer would pick a mode that then fails.
    p = delivery_profile_for(_resolved(
        ProviderEngine.OPENAI_COMPATIBLE, base_url="https://api.example.com/v1"))
    assert p.capabilities.guided_json is False
    assert p.capabilities.grammar is False


def test_lookalike_host_is_not_frontier():
    # Substring matching would read api.openai.com.evil as the real frontier.
    p = delivery_profile_for(_resolved(
        ProviderEngine.FRONTIER, provider="openai",
        base_url="https://api.openai.com.evil.example/v1"))
    assert p.kind is BackendKind.OPENAI_COMPAT


def test_resolve_backend_carries_profile():
    cfg = LLMConfig(provider="anthropic", anthropic_api_key="ak")
    rb = resolve_backend(cfg, InferenceTier.REASONING)
    assert isinstance(rb.profile, DeliveryProfile)
    assert rb.resolved.tier is InferenceTier.REASONING
    assert isinstance(select_backend(rb), SyncChatBackend)


def test_usage_record_tags_backend():
    from soctalk.inference import _usage_record
    profile = delivery_profile_for(
        _resolved(ProviderEngine.VLLM, base_url="https://x-8000.proxy.runpod.net/v1"))
    result = InferenceResult(
        parsed=None, raw_message=None, text=None, tool_calls=[],
        usage=UsageDelta(input_tokens=100, output_tokens=20),
        resolved=_resolved(ProviderEngine.VLLM), attempts=1,
    )
    rec = _usage_record(result, profile)
    assert isinstance(rec, UsageRecord)
    assert rec.input_tokens == 100 and rec.output_tokens == 20
    assert rec.backend_kind == "runpod_pod"
    assert rec.backend_id.startswith("runpod_pod:")
