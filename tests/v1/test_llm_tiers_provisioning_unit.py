"""Per-tier LLM provisioning: schema validation + render (issue #12).

The deployment half of #4. A hybrid tenant stores per-tier LLM backends in
``IntegrationConfig.llm_tiers``; render turns them into ``values.llm.tiers`` +
per-tier Secret keys + a port-union egress. Single-provider tenants (llm_tiers
NULL) must render byte-identically — asserted here at the values-dict level.
"""

from __future__ import annotations

from uuid import uuid4

import pytest

from soctalk.core.provisioning.render import render_tenant_values
from soctalk.core.tenancy.models import (
    BrandingConfig,
    IntegrationConfig,
    Tenant,
    TenantState,
    validate_llm_tiers,
)


def _tenant():
    return Tenant(id=uuid4(), slug="acme", display_name="Acme", profile="poc",
                  state=TenantState.PROVISIONING.value, organization_id=uuid4())


def _integration(tid, **over):
    base = dict(tenant_id=tid, llm_provider="anthropic",
                llm_base_url="https://api.anthropic.com", llm_model="claude-sonnet-4-6",
                llm_api_key_plain="ak-primary")
    base.update(over)
    return IntegrationConfig(**base)


def _render(integration, *, include_llm_api_key=True):
    t = _tenant()
    return render_tenant_values(
        tenant=t, integration=integration,
        branding=BrandingConfig(tenant_id=t.id, app_name="Acme SOC"),
        mssp_id=str(uuid4()), install_id=str(uuid4()),
        llm_secret_name="tenant-llm-key", include_llm_api_key=include_llm_api_key,
        profile="poc",
    )


_FAST = {"provider": "openai-compatible", "base_url": "http://sglang.internal:8000/v1",
         "model": "qwen3-32b", "engine": "sglang", "api_key_plain": "sk-served"}


# ---------------------------------------------------------------- validation


def test_validate_llm_tiers_ok_normalizes():
    out = validate_llm_tiers({"fast": _FAST})
    assert out["fast"]["provider"] == "openai-compatible"
    assert out["fast"]["engine"] == "sglang"
    # exclude_none: an omitted engine isn't stored as null.
    out2 = validate_llm_tiers({"reasoning": {"provider": "anthropic",
                                             "base_url": "https://api.anthropic.com",
                                             "model": "claude-sonnet-4-6"}})
    assert "engine" not in out2["reasoning"]


def test_validate_llm_tiers_none_and_empty():
    assert validate_llm_tiers(None) is None
    assert validate_llm_tiers({}) is None


def test_validate_llm_tiers_unknown_tier_rejected():
    with pytest.raises(ValueError, match="unknown llm_tiers"):
        validate_llm_tiers({"chat": _FAST})


def test_validate_llm_tiers_bad_block_rejected():
    with pytest.raises(ValueError):
        validate_llm_tiers({"fast": {"provider": "bedrock", "base_url": "x", "model": "m"}})
    with pytest.raises(ValueError):  # extra field (extra=forbid)
        validate_llm_tiers({"fast": {**_FAST, "surprise": 1}})


# -------------------------------------------------------- byte-identical guard


def test_single_provider_render_has_no_tier_keys():
    v = _render(_integration(uuid4()))
    assert "tiers" not in v["llm"]
    assert "tierKeys" not in v["llm"]
    assert "extraLlmEgressPorts" not in v["networkPolicies"]


# --------------------------------------------------------------- tier render


def test_hybrid_render_tiers_and_ports():
    integ = _integration(uuid4(), llm_tiers=validate_llm_tiers({"fast": _FAST}))
    v = _render(integ)
    fast = v["llm"]["tiers"]["fast"]
    assert fast["provider"] == "openai"  # canonicalized from openai-compatible
    assert fast["baseUrl"] == "http://sglang.internal:8000/v1"
    assert fast["model"] == "qwen3-32b"
    assert fast["engine"] == "sglang"
    # Own key materialized into tenant-llm-key on the L2 (chart-owned) path.
    assert v["llm"]["tierKeys"]["fast"] == "sk-served"
    # sglang :8000 is distinct from the primary anthropic :443 → port union.
    assert v["networkPolicies"]["extraLlmEgressPorts"] == [8000]


def test_hybrid_render_l1_controller_path_omits_plaintext():
    integ = _integration(uuid4(), llm_tiers=validate_llm_tiers({"fast": _FAST}))
    v = _render(integ, include_llm_api_key=False)
    # Tier key present (so the worker env references it) but plaintext withheld
    # — the controller mirrors the real key into the Secret.
    assert v["llm"]["tierKeys"]["fast"] == ""


def test_hybrid_same_port_no_extra_egress():
    # A tier whose backend shares the primary port (443) adds no extra port.
    integ = _integration(uuid4(), llm_tiers=validate_llm_tiers({
        "reasoning": {"provider": "anthropic", "base_url": "https://api.anthropic.com",
                      "model": "claude-opus-4"},
    }))
    v = _render(integ)
    assert "extraLlmEgressPorts" not in v["networkPolicies"]
    # No own key → not in tierKeys (reuses the primary credential).
    assert "tierKeys" not in v["llm"] or "reasoning" not in v["llm"].get("tierKeys", {})
