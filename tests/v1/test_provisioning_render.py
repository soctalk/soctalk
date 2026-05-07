"""Unit tests for profile-driven chart values rendering.

No DB, no kube, no helm. Pure functions only.
"""

from __future__ import annotations

from uuid import uuid4

import pytest

from soctalk.core.provisioning.render import (
    render_tenant_values,
    render_wazuh_values,
)
from soctalk.core.tenancy.models import (
    BrandingConfig,
    IntegrationConfig,
    Tenant,
    TenantState,
)


def _make_tenant(profile: str = "poc") -> Tenant:
    return Tenant(
        id=uuid4(),
        slug="acme",
        display_name="Acme Corp",
        state=TenantState.PROVISIONING.value,
        profile=profile,
        organization_id=uuid4(),
    )


def _make_integration(tid) -> IntegrationConfig:
    return IntegrationConfig(
        tenant_id=tid,
        llm_base_url="https://api.openai.com/v1",
        llm_model="gpt-4o",
    )


def _make_branding(tid) -> BrandingConfig:
    return BrandingConfig(
        tenant_id=tid,
        app_name="Acme SOC",
        primary_color="#112233",
    )


# ---------------------------------------------------------------------------
# render_tenant_values: profile layering
# ---------------------------------------------------------------------------


def test_poc_profile_emits_tight_resource_quota():
    t = _make_tenant("poc")
    v = render_tenant_values(
        tenant=t,
        integration=_make_integration(t.id),
        branding=_make_branding(t.id),
        mssp_id=str(uuid4()),
        install_id=str(uuid4()),
        llm_secret_name="tenant-x-llm",
        profile="poc",
    )
    # Chart schema disallows unknown top-level fields, so no "profile"
    # key ends up in values; the overrides land in resourceQuota etc.
    assert "profile" not in v
    assert v["resourceQuota"]["requests"]["memory"] == "2Gi"
    assert v["resourceQuota"]["pods"] == "20"


def test_persistent_profile_emits_larger_quota():
    t = _make_tenant("persistent")
    v = render_tenant_values(
        tenant=t,
        integration=_make_integration(t.id),
        branding=_make_branding(t.id),
        mssp_id=str(uuid4()),
        install_id=str(uuid4()),
        llm_secret_name="tenant-x-llm",
        profile="persistent",
    )
    assert "profile" not in v
    assert v["resourceQuota"]["requests"]["memory"] == "6Gi"
    # Persistent leaves limitRange at the base (no override).


def test_tenant_identity_always_rendered():
    """Regardless of profile, tenant / branding / llm blocks are filled."""
    t = _make_tenant("poc")
    v = render_tenant_values(
        tenant=t,
        integration=_make_integration(t.id),
        branding=_make_branding(t.id),
        mssp_id="11111111-1111-1111-1111-111111111111",
        install_id="22222222-2222-2222-2222-222222222222",
        llm_secret_name="tenant-x-llm",
        profile="poc",
    )
    assert v["tenant"]["slug"] == "acme"
    assert v["tenant"]["msspId"] == "11111111-1111-1111-1111-111111111111"
    assert v["branding"]["appName"] == "Acme SOC"
    assert v["branding"]["primaryColor"] == "#112233"
    assert v["llm"]["apiKeyRef"]["name"] == "tenant-x-llm"


def test_llm_api_key_propagated_to_chart_values():
    """When the integration row holds a plaintext key, the rendered
    values pass it through as ``llm.apiKey`` so the chart's secret
    template materializes ``tenant-llm-key`` with the actual key.

    Regression: previously the renderer dropped ``llm_api_key_plain``
    on the floor, the chart's ``{{- if .Values.llm.apiKey }}`` guard
    skipped the Secret, and the runs-worker mounted an empty
    ``secretKeyRef`` — triage would fail with "No LLM API key
    configured" on every alert until an admin PATCHed the LLM endpoint
    post-install.
    """
    t = _make_tenant("poc")
    integration = _make_integration(t.id)
    integration.llm_api_key_plain = "sk-test-llm-key-deadbeef"
    v = render_tenant_values(
        tenant=t,
        integration=integration,
        branding=_make_branding(t.id),
        mssp_id=str(uuid4()),
        install_id=str(uuid4()),
        llm_secret_name="tenant-x-llm",
        profile="poc",
    )
    assert v["llm"]["apiKey"] == "sk-test-llm-key-deadbeef"


def test_llm_api_key_empty_when_unset():
    """Empty plaintext renders as empty string, not absent. The chart
    treats empty + present as "operator pre-provisions the Secret",
    matching the legacy collapsed-tier contract."""
    t = _make_tenant("poc")
    v = render_tenant_values(
        tenant=t,
        integration=_make_integration(t.id),  # no llm_api_key_plain
        branding=_make_branding(t.id),
        mssp_id=str(uuid4()),
        install_id=str(uuid4()),
        llm_secret_name="tenant-x-llm",
        profile="poc",
    )
    assert v["llm"]["apiKey"] == ""


# ---------------------------------------------------------------------------
# render_wazuh_values: per-tenant layer
# ---------------------------------------------------------------------------


def test_wazuh_values_carry_minted_creds():
    t = _make_tenant("poc")
    v = render_wazuh_values(
        tenant=t,
        profile="poc",
        admin_password="a-random-admin-pw",
        authd_password="a-random-authd-pw",
    )
    # Api password is the minted one; indexer stays at demo `admin`
    # until internal_users.yml override lands (documented in render.py).
    assert v["credentials"]["apiPassword"] == "a-random-admin-pw"
    assert v["credentials"]["authdPassword"] == "a-random-authd-pw"
    assert v["credentials"]["indexerPassword"] == "admin"
    assert v["tenant"]["slug"] == "acme"
    assert v["tenant"]["profile"] == "poc"


def test_wazuh_values_storage_override_only_for_persistent():
    t = _make_tenant("persistent")
    v = render_wazuh_values(
        tenant=t,
        profile="persistent",
        admin_password="pw",
        authd_password="pw",
        storage_class_override="standard",
    )
    assert v["storage"]["storageClass"] == "standard"


def test_wazuh_values_no_storage_override_for_poc():
    """PoC profile relies on the chart's values.poc.yaml for storage."""
    t = _make_tenant("poc")
    v = render_wazuh_values(
        tenant=t,
        profile="poc",
        admin_password="pw",
        authd_password="pw",
        storage_class_override=None,
    )
    # Per-tenant layer should NOT push a storageClass; the profile values
    # file owns that default.
    assert "storage" not in v
