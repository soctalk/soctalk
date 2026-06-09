"""Unit tests for profile-driven chart values rendering.

No DB, no kube, no helm. Pure functions only.
"""

from __future__ import annotations

import json
from pathlib import Path
from uuid import uuid4

import pytest

from soctalk.core.provisioning.render import (
    _profile_tenant_overrides,
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
    # 4Gi covers adapter + wazuh-{manager,indexer,dashboard} at PoC limits
    # with restart headroom; bumped from 2Gi when Wazuh joined the bundle.
    assert v["resourceQuota"]["requests"]["memory"] == "4Gi"
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


# ---------------------------------------------------------------------------
# render_tenant_values: 'provided' profile (tenant brings their own Wazuh)
# ---------------------------------------------------------------------------


def _tenant_values_schema() -> dict:
    """Load the soctalk-tenant chart values schema from the repo."""
    schema_path = (
        Path(__file__).resolve().parents[2]
        / "charts"
        / "soctalk-tenant"
        / "values.schema.json"
    )
    return json.loads(schema_path.read_text())


def _assert_validates_against_tenant_schema(values: dict) -> None:
    """The rendered values must satisfy the tenant chart's JSON Schema."""
    jsonschema = pytest.importorskip("jsonschema")
    jsonschema.validate(instance=values, schema=_tenant_values_schema())


def test_render_provided_profile():
    """The 'provided' profile: the tenant brings their OWN external Wazuh stack.

    SocTalk must NOT deploy in-cluster Wazuh/TheHive/Cortex; it points the
    per-tenant adapter at the EXTERNAL indexer using the controller-managed
    ``tenant-external-siem-creds`` Secret, drops the agent ingress, sizes the
    ResourceQuota for just the adapter + runs-worker, and emits the external
    SIEM egress allow-list (both indexer + API hosts) with FQDN egress on.

    Asserts every acceptance bullet of ``tenant.profile.provided.render``.
    """
    t = _make_tenant("provided")
    integration = _make_integration(t.id)
    # The integration row claims the in-cluster components are "enabled"; the
    # 'provided' profile must override them OFF regardless of these flags.
    integration.wazuh_enabled = True
    integration.thehive_enabled = True
    integration.cortex_enabled = True
    # External Wazuh — indexer + API on DISTINCT hosts; BOTH credential pairs.
    integration.wazuh_indexer_url = "https://indexer.siem.acme.example:9200"
    integration.wazuh_indexer_username = "ext-indexer"
    integration.wazuh_indexer_password_plain = "indexer-pw"
    integration.wazuh_url = "https://manager.siem.acme.example"
    integration.wazuh_api_url = "https://manager.siem.acme.example:55000"
    integration.wazuh_username = "ext-api"
    integration.wazuh_password_plain = "api-pw"
    # Set FALSE here (non-default) so the poc check below — which uses True —
    # proves verifySsl is wired to the integration row, not hardcoded.
    integration.wazuh_verify_ssl = False

    v = render_tenant_values(
        tenant=t,
        integration=integration,
        branding=_make_branding(t.id),
        mssp_id=str(uuid4()),
        install_id=str(uuid4()),
        llm_secret_name="tenant-x-llm",
        profile="provided",
    )

    # (1) in-cluster SOC stack disabled for 'provided'
    assert v["components"]["wazuh"]["enabled"] is False
    assert v["components"]["thehive"]["enabled"] is False
    assert v["components"]["cortex"]["enabled"] is False

    # (2) adapter points at the EXTERNAL indexer via the controller-managed Secret
    idx = v["adapter"]["wazuhIndexer"]
    assert idx["url"] == integration.wazuh_indexer_url
    assert idx["credsSecret"] == "tenant-external-siem-creds"
    assert idx["usernameKey"] == "INDEXER_USERNAME"
    assert idx["passwordKey"] == "INDEXER_PASSWORD"

    # (3) verifySsl mirrors the integration row (rendered for 'provided')
    assert idx["verifySsl"] == integration.wazuh_verify_ssl  # False here

    # (4) no agent ingress — the tenant's own Wazuh fronts its agents
    assert "agentIngress" not in v or v["agentIngress"].get("enabled") is False

    # (5) ResourceQuota sized for adapter + runs-worker only — assert both the
    #     rendered dict AND the override helper directly (acceptance names it).
    rq = v["resourceQuota"]
    assert rq["requests"] == {"cpu": "1", "memory": "2Gi"}
    assert rq["limits"] == {"cpu": "2", "memory": "4Gi"}
    assert rq["pods"] == "10"
    assert rq["persistentVolumeClaims"] == "2"
    override_rq = _profile_tenant_overrides("provided")["resourceQuota"]
    assert override_rq["requests"] == {"cpu": "1", "memory": "2Gi"}
    assert override_rq["limits"] == {"cpu": "2", "memory": "4Gi"}
    assert override_rq["pods"] == "10"
    assert override_rq["persistentVolumeClaims"] == "2"

    # (6) external SIEM egress allow-list: both hosts, deduped; FQDN egress on
    hosts = v["networkPolicies"]["externalSiemHosts"]
    assert "indexer.siem.acme.example" in hosts
    assert "manager.siem.acme.example" in hosts
    assert len(hosts) == len(set(hosts)) == 2  # deduped, no stray entries
    assert v["networkPolicies"]["fqdnEgress"]["enabled"] is True

    # (4, schema) the rendered 'provided' shape validates against the chart schema
    _assert_validates_against_tenant_schema(v)

    # (3 + 6, other profiles) verifySsl is rendered for poc too, and
    # externalSiemHosts is empty for non-provided profiles. poc still validates.
    poc_integration = _make_integration(t.id)
    poc_integration.wazuh_verify_ssl = True
    v_poc = render_tenant_values(
        tenant=_make_tenant("poc"),
        integration=poc_integration,
        branding=_make_branding(t.id),
        mssp_id=str(uuid4()),
        install_id=str(uuid4()),
        llm_secret_name="tenant-x-llm",
        profile="poc",
    )
    assert (
        v_poc["adapter"]["wazuhIndexer"]["verifySsl"]
        == poc_integration.wazuh_verify_ssl  # True here
    )
    assert v_poc["networkPolicies"]["externalSiemHosts"] == []
    _assert_validates_against_tenant_schema(v_poc)


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
    # apiKeyRef points at the tenant-namespace Secret (always
    # ``tenant-llm-key``); ``llm_secret_name`` names the Secret in
    # ``soctalk-system`` that the controller mirrors from.
    assert v["llm"]["apiKeyRef"]["name"] == "tenant-llm-key"


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
