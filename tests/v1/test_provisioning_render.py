"""Unit tests for profile-driven chart values rendering.

Pure functions only — no DB, no kube. The ``adapter-fqdn-egress`` chart
assertions shell out to ``helm template`` (the only place that touches a
binary); they self-skip where ``helm`` is not on PATH so the rest of the
suite stays a pure-python run.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
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
    # 6Gi covers adapter + wazuh-{manager,indexer,dashboard} + linux-ep
    # at PoC limits with restart headroom; bumped from 4Gi when linux-ep
    # joined the poc bundle (attack simulator + Wazuh agent side-by-side).
    assert v["resourceQuota"]["requests"]["memory"] == "6Gi"
    assert v["resourceQuota"]["pods"] == "20"


def test_poc_profile_wires_linuxep_wazuh_manager():
    # The poc profile enables the linux-ep subchart, whose statefulset hard-fails
    # helm install unless wazuh.managerHost + credsSecret are set — the cause of
    # the demo 'degraded' provisioning failure. Assert the passthrough block is
    # emitted with the wazuh-<slug> release convention.
    t = _make_tenant("poc")
    v = render_tenant_values(
        tenant=t, integration=_make_integration(t.id), branding=_make_branding(t.id),
        mssp_id=str(uuid4()), install_id=str(uuid4()),
        llm_secret_name="tenant-x-llm", profile="poc",
    )
    lep = v["linuxep"]
    assert lep["wazuh"]["managerHost"] == f"wazuh-{t.slug}-wazuh-manager"
    assert lep["wazuh"]["credsSecret"]["name"] == f"wazuh-{t.slug}-wazuh-creds"
    # Must match the key the wazuh chart's creds Secret actually uses (AUTHD_PASS),
    # not render_linux_ep_values' default — else the linuxep pod can't start.
    assert lep["wazuh"]["credsSecret"]["authdPasswordKey"] == "AUTHD_PASS"
    assert v["components"]["linuxep"]["enabled"] is True
    # Non-poc profiles don't enable linux-ep → no passthrough block.
    v2 = render_tenant_values(
        tenant=_make_tenant("persistent"), integration=_make_integration(t.id),
        branding=_make_branding(t.id), mssp_id=str(uuid4()), install_id=str(uuid4()),
        llm_secret_name="tenant-x-llm", profile="persistent",
    )
    assert "linuxep" not in v2


def test_moving_latest_tag_pulls_always():
    # A moving `latest` image tag MUST render pullPolicy=Always or the node caches
    # stale code (the demo runs-worker/adapter ran weeks-old triage code).
    t = _make_tenant("poc")
    v = render_tenant_values(
        tenant=t, integration=_make_integration(t.id), branding=_make_branding(t.id),
        mssp_id=str(uuid4()), install_id=str(uuid4()),
        llm_secret_name="tenant-x-llm", profile="poc",
    )
    assert v["runsWorker"]["image"]["tag"] == "latest"
    assert v["runsWorker"]["image"]["pullPolicy"] == "Always"
    assert v["adapter"]["image"]["pullPolicy"] == "Always"


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

    # (3 + 6, other profiles) verifySsl is FORCED false for poc regardless
    # of the integration row — poc ships in-cluster Wazuh with self-signed
    # certs, so the adapter can never verify them. externalSiemHosts stays
    # empty for non-provided profiles. poc still validates.
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
    assert v_poc["adapter"]["wazuhIndexer"]["verifySsl"] is False
    assert v_poc["networkPolicies"]["externalSiemHosts"] == []
    _assert_validates_against_tenant_schema(v_poc)


# ---------------------------------------------------------------------------
# Chart render: adapter-fqdn-egress CiliumNetworkPolicy (helm template)
#
# These exercise the *chart* side of the FQDN-egress feature. The values from
# render_tenant_values are fed through ``helm template`` and the emitted
# CiliumNetworkPolicy is asserted on. ``helm`` also validates against
# values.schema.json while templating, so a schema violation surfaces as a
# non-zero exit here too. Skipped (not failed) where ``helm`` is absent.
# ---------------------------------------------------------------------------

_TENANT_CHART_DIR = Path(__file__).resolve().parents[2] / "charts" / "soctalk-tenant"


def _helm_template(values: dict) -> list[dict]:
    """Render the soctalk-tenant chart with ``values`` → list of manifests."""
    helm = shutil.which("helm")
    if helm is None:
        pytest.skip("helm binary not on PATH")
    yaml = pytest.importorskip("yaml")

    with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as fh:
        yaml.safe_dump(values, fh)
        values_path = fh.name
    try:
        proc = subprocess.run(
            [helm, "template", "t", str(_TENANT_CHART_DIR), "-f", values_path],
            capture_output=True,
            text=True,
        )
    finally:
        os.unlink(values_path)
    assert proc.returncode == 0, f"helm template failed:\n{proc.stderr}"
    return [d for d in yaml.safe_load_all(proc.stdout) if d]


def _fqdn_egress_match_names(manifests: list[dict]) -> list[str] | None:
    """toFQDNs matchName values from adapter-fqdn-egress, or None if absent."""
    for doc in manifests:
        if (
            doc.get("kind") == "CiliumNetworkPolicy"
            and doc.get("metadata", {}).get("name") == "adapter-fqdn-egress"
        ):
            names: list[str] = []
            for rule in doc.get("spec", {}).get("egress", []):
                for fqdn in rule.get("toFQDNs", []) or []:
                    if "matchName" in fqdn:
                        names.append(fqdn["matchName"])
            return names
    return None


def _provided_values_for_chart(
    *,
    indexer_url: str | None,
    api_url: str | None,
    soctalk_url: str,
) -> dict:
    """render_tenant_values for a 'provided' tenant, plus a soctalkSystem.url.

    render populates externalSiemHosts + fqdnEgress.enabled; soctalkSystem.url
    is injected here because the L1 :issue-agent path sets it, not the renderer.
    """
    t = _make_tenant("provided")
    integration = _make_integration(t.id)
    integration.wazuh_indexer_url = indexer_url
    integration.wazuh_api_url = api_url
    v = render_tenant_values(
        tenant=t,
        integration=integration,
        branding=_make_branding(t.id),
        mssp_id=str(uuid4()),
        install_id=str(uuid4()),
        llm_secret_name="tenant-x-llm",
        profile="provided",
    )
    v["soctalkSystem"] = {"url": soctalk_url, "adapterToken": ""}
    return v


def test_chart_fqdn_egress_includes_l1_and_external_siem_hosts():
    """Acceptance 1 + 6: the rendered adapter-fqdn-egress CiliumNetworkPolicy
    carries the L1 host (from soctalkSystem.url) AND every external SIEM host
    (from networkPolicies.externalSiemHosts) under toFQDNs."""
    values = _provided_values_for_chart(
        indexer_url="https://indexer.siem.acme.example:9200",
        api_url="https://manager.siem.acme.example:55000",
        soctalk_url="https://l1.mssp.example",
    )
    # Precondition: render produced the external host list the chart consumes.
    assert set(values["networkPolicies"]["externalSiemHosts"]) == {
        "indexer.siem.acme.example",
        "manager.siem.acme.example",
    }

    names = _fqdn_egress_match_names(_helm_template(values))
    assert names is not None, "adapter-fqdn-egress was not emitted"
    assert "l1.mssp.example" in names  # L1 host
    assert "indexer.siem.acme.example" in names  # external SIEM indexer
    assert "manager.siem.acme.example" in names  # external SIEM API


def test_chart_fqdn_egress_emitted_for_external_hosts_without_l1_url():
    """Acceptance 1 + 2 boundary: external SIEM hosts alone (soctalkSystem.url
    empty) still emit the policy — the skip only triggers when BOTH are empty."""
    values = _provided_values_for_chart(
        indexer_url="https://indexer.siem.acme.example:9200",
        api_url="https://manager.siem.acme.example:55000",
        soctalk_url="",
    )
    names = _fqdn_egress_match_names(_helm_template(values))
    assert names is not None, "adapter-fqdn-egress should emit for SIEM hosts"
    assert "indexer.siem.acme.example" in names
    assert "manager.siem.acme.example" in names
    assert "l1.mssp.example" not in names  # no L1 url ⇒ no L1 entry


def test_chart_fqdn_egress_skipped_when_no_hosts():
    """Acceptance 2: with externalSiemHosts empty AND soctalkSystem.url empty,
    the CiliumNetworkPolicy is not emitted (existing skip behavior preserved)
    even though the 'provided' profile forces fqdnEgress.enabled=true."""
    values = _provided_values_for_chart(
        indexer_url="https://indexer.siem.acme.example:9200",
        api_url="https://manager.siem.acme.example:55000",
        soctalk_url="",
    )
    # Force the exact skip precondition: no external hosts, no L1 url, while
    # leaving fqdnEgress enabled — proves the gate skips on host-emptiness,
    # not just on the toggle. (A real 'provided' tenant always has hosts, so
    # the adapter indexer URL is kept valid for the schema check.)
    values["networkPolicies"]["externalSiemHosts"] = []
    values["soctalkSystem"]["url"] = ""
    assert values["networkPolicies"]["fqdnEgress"]["enabled"] is True

    names = _fqdn_egress_match_names(_helm_template(values))
    assert names is None, "adapter-fqdn-egress must be skipped when no hosts"


@pytest.mark.parametrize("profile", ["poc", "persistent", "provided"])
@pytest.mark.parametrize("verify", [True, False])
def test_verify_ssl_flows_from_integration_for_all_profiles(profile, verify):
    """``adapter.wazuhIndexer.verifySsl`` mirrors ``integration.wazuh_verify_ssl``
    only for the ``provided`` profile — the two in-cluster profiles (``poc``,
    ``persistent``) always emit ``verifySsl: false`` because the bundled Wazuh
    subchart ships a self-signed indexer cert with no operator-facing way to
    swap it. The adapter would fail every ingest if verify were True.
    """
    t = _make_tenant(profile)
    integration = _make_integration(t.id)
    integration.wazuh_verify_ssl = verify
    # 'provided' derives its external-SIEM shape from the indexer URL.
    integration.wazuh_indexer_url = "https://indexer.siem.example:9200"
    v = render_tenant_values(
        tenant=t,
        integration=integration,
        branding=_make_branding(t.id),
        mssp_id=str(uuid4()),
        install_id=str(uuid4()),
        llm_secret_name="tenant-x-llm",
        profile=profile,
    )
    expected = verify if profile == "provided" else False
    assert v["adapter"]["wazuhIndexer"]["verifySsl"] is expected


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


def test_llm_api_key_suppressed_on_controller_path():
    """``include_llm_api_key=False`` (the L1 controller path) renders
    ``llm.apiKey`` as "" even when the integration row holds a key.

    Regression: the controller writes ``Secret/tenant-llm-key`` directly
    in apply_secrets (no Helm ownership metadata). When a per-tenant key
    was set at onboard, the renderer passed the plaintext through,
    the chart's ``{{- if .Values.llm.apiKey }}`` guard fired, and helm
    refused to install: 'Secret "tenant-llm-key" ... exists and cannot
    be imported into the current release: invalid ownership metadata'.
    The controller path must keep a single Secret owner (the controller);
    the plaintext-through-values path is reserved for the cross-cluster
    L2 install-spec where no controller pre-writes Secrets.
    """
    t = _make_tenant("provided")
    integration = _make_integration(t.id)
    integration.llm_api_key_plain = "sk-test-llm-key-deadbeef"
    v = render_tenant_values(
        tenant=t,
        integration=integration,
        branding=_make_branding(t.id),
        mssp_id=str(uuid4()),
        install_id=str(uuid4()),
        llm_secret_name="tenant-x-llm",
        profile="provided",
        include_llm_api_key=False,
    )
    assert v["llm"]["apiKey"] == ""
    # The mount reference is untouched — the runs-worker still reads the
    # controller-written Secret.
    assert v["llm"]["apiKeyRef"]["name"] == "tenant-llm-key"


# ---------------------------------------------------------------------------
# runsWorker model overrides (tenant.llm.models.render)
# ---------------------------------------------------------------------------


def test_runs_worker_model_overrides_rendered_when_set():
    """Per-tenant ``llm_fast_model`` / ``llm_reasoning_model`` overrides flow
    into ``runsWorker.fastModel`` / ``runsWorker.reasoningModel`` — the chart
    maps those to SOCTALK_FAST_MODEL / SOCTALK_REASONING_MODEL on the
    runs-worker (35-runs-worker.yaml), so no chart edit is needed."""
    t = _make_tenant("poc")
    integration = _make_integration(t.id)
    integration.llm_fast_model = "gpt-4o-mini"
    integration.llm_reasoning_model = "o3"
    v = render_tenant_values(
        tenant=t,
        integration=integration,
        branding=_make_branding(t.id),
        mssp_id=str(uuid4()),
        install_id=str(uuid4()),
        llm_secret_name="tenant-x-llm",
        profile="poc",
    )
    assert v["runsWorker"]["fastModel"] == "gpt-4o-mini"
    assert v["runsWorker"]["reasoningModel"] == "o3"
    # llm.model itself is untouched by the overrides.
    assert v["llm"]["model"] == "gpt-4o"
    _assert_validates_against_tenant_schema(v)


def test_runs_worker_models_fall_back_to_llm_model_when_null():
    """NULL overrides preserve today's behavior: both runsWorker models
    render as ``integration.llm_model`` for every existing tenant row."""
    t = _make_tenant("poc")
    integration = _make_integration(t.id)  # llm_fast/reasoning_model both NULL
    assert integration.llm_fast_model is None
    assert integration.llm_reasoning_model is None
    v = render_tenant_values(
        tenant=t,
        integration=integration,
        branding=_make_branding(t.id),
        mssp_id=str(uuid4()),
        install_id=str(uuid4()),
        llm_secret_name="tenant-x-llm",
        profile="poc",
    )
    assert v["runsWorker"]["fastModel"] == "gpt-4o"
    assert v["runsWorker"]["reasoningModel"] == "gpt-4o"


def test_runs_worker_models_treat_empty_string_as_unset():
    """A cleared override may be stored as '' instead of NULL; render time
    must treat both identically and fall back to llm_model."""
    t = _make_tenant("poc")
    integration = _make_integration(t.id)
    integration.llm_fast_model = ""
    integration.llm_reasoning_model = ""
    v = render_tenant_values(
        tenant=t,
        integration=integration,
        branding=_make_branding(t.id),
        mssp_id=str(uuid4()),
        install_id=str(uuid4()),
        llm_secret_name="tenant-x-llm",
        profile="poc",
    )
    assert v["runsWorker"]["fastModel"] == "gpt-4o"
    assert v["runsWorker"]["reasoningModel"] == "gpt-4o"


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
