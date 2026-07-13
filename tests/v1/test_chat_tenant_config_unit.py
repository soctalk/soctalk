"""Per-tenant chat LLM config overlay (issue #10/#4).

The chat agent runs in the shared API process, so it can't read per-tenant
``SOCTALK_*`` env like each single-tenant worker does. ``_tenant_chat_llm_config``
loads the tenant's ``IntegrationConfig`` and overlays provider/base_url/model/key
onto the process-global chat config so a BYOK / custom-model tenant's chat runs
on THEIR backend. These tests exercise the overlay against a fake session.
"""

from __future__ import annotations

from uuid import uuid4

import pytest

from soctalk.chat.agent import _tenant_chat_llm_config
from soctalk.config import LLMConfig
from soctalk.core.tenancy.models import IntegrationConfig


class _Result:
    def __init__(self, row):
        self._row = row

    def scalar_one_or_none(self):
        return self._row


class _FakeDb:
    """Minimal async session stub: returns a preset IntegrationConfig row."""

    def __init__(self, row):
        self._row = row

    async def execute(self, *_a, **_k):
        return _Result(self._row)


def _base():
    return LLMConfig(
        provider="anthropic", anthropic_api_key="mssp-shared-key",
        anthropic_base_url="https://api.anthropic.com",
        fast_model="claude-sonnet-4-6", chat_model="", openai_api_key="",
    )


def _integration(**over):
    base = dict(tenant_id=uuid4(), llm_provider="anthropic",
                llm_base_url="https://api.anthropic.com", llm_model="claude-opus-4")
    base.update(over)
    return IntegrationConfig(**base)


async def test_no_integration_returns_base_unchanged():
    base = _base()
    cfg, model = await _tenant_chat_llm_config(_FakeDb(None), uuid4(), base, "req-model")
    assert cfg is base
    assert model == "req-model"


async def test_openai_byok_tenant_overlays_and_swaps_model():
    # Cross-provider BYOK: overlay provider/base/key AND swap the effective model
    # (the stored conversation model was chosen for the old anthropic provider).
    integ = _integration(
        llm_provider="openai-compatible", llm_base_url="http://sglang.internal/v1",
        llm_model="qwen3-32b", llm_api_key_plain="sk-tenant-own",
    )
    cfg, model = await _tenant_chat_llm_config(
        _FakeDb(integ), integ.tenant_id, _base(), "claude-sonnet-4-6"
    )
    assert cfg.provider == "openai"  # openai-compatible → openai
    assert cfg.openai_base_url == "http://sglang.internal/v1"
    assert cfg.openai_api_key == "sk-tenant-own"
    assert cfg.chat_model == "qwen3-32b"
    assert cfg.fast_model == "qwen3-32b"
    # Cross-provider → the tenant model wins over the stale conversation model.
    assert model == "qwen3-32b"
    # The MSSP anthropic key is NOT leaked onto the openai path.
    assert cfg.anthropic_api_key == "mssp-shared-key"  # base retained, unused


async def test_cross_provider_without_own_key_falls_back_to_base():
    # A default/unconfigured openai-compatible row with NO own key on an
    # anthropic install can't authenticate — must fall back to base (Codex #3).
    integ = _integration(
        llm_provider="openai-compatible", llm_base_url="https://api.openai.com/v1",
        llm_model="gpt-4o", llm_api_key_plain=None,
    )
    base = _base()
    cfg, model = await _tenant_chat_llm_config(
        _FakeDb(integ), integ.tenant_id, base, "claude-sonnet-4-6"
    )
    assert cfg is base
    assert model == "claude-sonnet-4-6"


async def test_same_provider_respects_conversation_model():
    # Same provider (anthropic install + anthropic tenant), no own key: overlay
    # the model but keep the shared key, and the per-conversation model wins.
    integ = _integration(llm_model="claude-opus-4", llm_api_key_plain=None)
    cfg, model = await _tenant_chat_llm_config(
        _FakeDb(integ), integ.tenant_id, _base(), "claude-sonnet-4-6"
    )
    assert cfg.provider == "anthropic"
    assert cfg.anthropic_api_key == "mssp-shared-key"  # base retained (shared key)
    # Same provider → the conversation's model choice is respected.
    assert model == "claude-sonnet-4-6"


async def test_overlay_drops_shared_chat_tier():
    # The process-global 'chat' tier must not override the overlaid backend.
    base = _base().model_copy(update={"tiers": {"chat": {"provider": "openai",
                                                         "base_url": "http://shared/v1"}}})
    integ = _integration(
        llm_provider="openai-compatible", llm_base_url="http://tenant/v1",
        llm_model="qwen", llm_api_key_plain="sk-own",
    )
    cfg, _ = await _tenant_chat_llm_config(_FakeDb(integ), integ.tenant_id, base, "m")
    assert "chat" not in cfg.tiers


async def test_default_chat_model_prefers_tenant_model(monkeypatch):
    # A new tenant conversation opens on the tenant's model (consistent with the
    # per-tenant provider the agent resolves), not the global Anthropic default.
    from soctalk.core.api import chat as chat_api

    class _ModelResult:
        def scalar_one_or_none(self):
            return "qwen3-32b"

    class _Db:
        async def execute(self, *_a, **_k):
            return _ModelResult()

    monkeypatch.setenv("SOCTALK_CHAT_MODEL", "claude-sonnet-4-6")
    out = await chat_api._default_chat_model_for_tenant(_Db(), uuid4())
    assert out == "qwen3-32b"


async def test_default_chat_model_fleet_uses_global(monkeypatch):
    from soctalk.core.api import chat as chat_api

    monkeypatch.setenv("SOCTALK_CHAT_MODEL", "claude-sonnet-4-6")
    # tenant_id None (fleet scope) → global default, no db lookup.
    out = await chat_api._default_chat_model_for_tenant(None, None)
    assert out == "claude-sonnet-4-6"


if __name__ == "__main__":  # pragma: no cover
    pytest.main([__file__, "-q"])
