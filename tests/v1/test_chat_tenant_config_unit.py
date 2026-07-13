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
    out = await _tenant_chat_llm_config(_FakeDb(None), uuid4(), base)
    assert out is base


async def test_openai_tenant_overlays_provider_key_model():
    integ = _integration(
        llm_provider="openai-compatible", llm_base_url="http://sglang.internal/v1",
        llm_model="qwen3-32b", llm_api_key_plain="sk-tenant-own",
    )
    out = await _tenant_chat_llm_config(_FakeDb(integ), integ.tenant_id, _base())
    assert out.provider == "openai"  # openai-compatible → openai
    assert out.openai_base_url == "http://sglang.internal/v1"
    assert out.openai_api_key == "sk-tenant-own"
    # Model applied to both chat_model and fast_model (resolve_tier CHAT fallback).
    assert out.chat_model == "qwen3-32b"
    assert out.fast_model == "qwen3-32b"
    # The MSSP anthropic key is NOT leaked onto the openai path.
    assert out.anthropic_api_key == "mssp-shared-key"  # base retained, unused


async def test_anthropic_tenant_without_own_key_keeps_shared_key():
    # A tenant using the MSSP shared install key (no own key) still uses its own
    # provider/model, but the primary credential falls back to the base config.
    integ = _integration(llm_model="claude-opus-4", llm_api_key_plain=None)
    out = await _tenant_chat_llm_config(_FakeDb(integ), integ.tenant_id, _base())
    assert out.provider == "anthropic"
    assert out.anthropic_api_key == "mssp-shared-key"  # base retained (shared key)
    assert out.chat_model == "claude-opus-4"


async def test_missing_model_falls_back_to_base():
    integ = _integration(llm_model="", llm_api_key_plain="sk-own")
    base = _base()
    out = await _tenant_chat_llm_config(_FakeDb(integ), integ.tenant_id, base)
    # No tenant model → base chat_model ('' here) or fast_model.
    assert out.chat_model == base.fast_model


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
