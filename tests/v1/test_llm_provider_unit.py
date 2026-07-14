"""Pure-function unit tests for the shared LLM provider helpers.

No DB, no fixtures — these guard the provider↔model↔base_url reconciliation
rules that both the onboard endpoint and the provisioning controller rely on
so a tenant's stored config stays internally consistent (and, crucially, so
the runs-worker egress NetworkPolicy opens the host the client actually calls).
"""

from soctalk.core.llm_provider import (
    ANTHROPIC_DEFAULT_BASE_URL,
    OPENAI_SENTINEL_BASE_URL,
    infer_provider_from_key,
    reconcile_provider_base_url,
    reconcile_provider_model,
)


def test_base_url_sentinel_swapped_to_anthropic_when_provider_is_anthropic():
    # The wizard's untouched OpenAI base_url on an anthropic tenant would make
    # render.py open runs-worker egress for api.openai.com while the Anthropic
    # client calls api.anthropic.com — the call is dropped. Reconcile flips it.
    assert (
        reconcile_provider_base_url("anthropic", OPENAI_SENTINEL_BASE_URL)
        == ANTHROPIC_DEFAULT_BASE_URL
    )


def test_base_url_custom_endpoint_preserved_for_anthropic():
    # Only the exact unset sentinel is flipped; a real proxy/gateway is kept.
    proxy = "https://claude-proxy.internal.example/v1"
    assert reconcile_provider_base_url("anthropic", proxy) == proxy


def test_base_url_sentinel_preserved_for_openai_compatible():
    # openai-compatible + the OpenAI endpoint is already consistent — no swap.
    assert (
        reconcile_provider_base_url("openai-compatible", OPENAI_SENTINEL_BASE_URL)
        == OPENAI_SENTINEL_BASE_URL
    )


def test_key_inferred_anthropic_then_base_url_reconciled():
    # End-to-end of the risky path: sk-ant key → provider=anthropic → the
    # base_url that was still the OpenAI sentinel is reconciled to Anthropic.
    provider = infer_provider_from_key("sk-ant-abc123")
    assert provider == "anthropic"
    assert (
        reconcile_provider_base_url(provider, OPENAI_SENTINEL_BASE_URL)
        == ANTHROPIC_DEFAULT_BASE_URL
    )
    # ...and the mismatched default model is flipped alongside it.
    assert reconcile_provider_model(provider, "gpt-4o") == "claude-sonnet-4-6"


def test_non_ant_key_keeps_openai_compatible_and_endpoint():
    provider = infer_provider_from_key("sk-proj-xyz")
    assert provider == "openai-compatible"
    assert (
        reconcile_provider_base_url(provider, OPENAI_SENTINEL_BASE_URL)
        == OPENAI_SENTINEL_BASE_URL
    )
