"""Render a Tenant row into ``soctalk-tenant`` and ``wazuh`` chart values.

Pure functions: given a Tenant + associated config + deployment profile,
produce dicts matching the respective chart's values schema. Output is
written to a temp file and passed to ``helm install -f`` by the caller.

Profiles (see ``docs/multi-tenant/wazuh-profiles.md``):

- ``poc`` — ephemeral / cheapest viable. Single-node, node-local storage,
  no ingress, tight resource quotas. Intended for demo tenants.
- ``persistent`` — single-node but durable. PVC-backed indexer and
  manager. No HA (deferred).
- ``legacy`` — tenants provisioned before the profile concept existed.
  The controller refuses to re-render for ``legacy`` tenants on the MVP
  path: their topology is whatever was applied at install time, and we
  do not assume.
"""

from __future__ import annotations

import os
from typing import Any, Literal

from soctalk.core.tenancy.models import BrandingConfig, IntegrationConfig, Tenant


Profile = Literal["poc", "persistent", "legacy"]


def _profile_tenant_overrides(profile: Profile) -> dict[str, Any]:
    """Layer profile-specific defaults over the shared base values.

    Only the fields that actually differ between profiles. Values merged
    shallowly by key at the top level, so section dicts overwrite —
    re-specify the full section when overriding.
    """

    if profile == "poc":
        return {
            "resourceQuota": {
                "enabled": True,
                # Sized for adapter + wazuh-manager + wazuh-indexer +
                # wazuh-dashboard at PoC limits, with headroom for one
                # restart and the indexer's init containers.
                "requests": {"cpu": "2", "memory": "4Gi"},
                "limits": {"cpu": "4", "memory": "8Gi"},
                "persistentVolumeClaims": "4",
                "pods": "20",
            },
            "limitRange": {
                "enabled": True,
                "defaults": {"memory": "512Mi", "cpu": "250m"},
                "defaultRequests": {"memory": "128Mi", "cpu": "50m"},
                "max": {"memory": "2Gi", "cpu": "1"},
            },
        }

    if profile == "persistent":
        return {
            "resourceQuota": {
                "enabled": True,
                "requests": {"cpu": "2", "memory": "6Gi"},
                "limits": {"cpu": "5", "memory": "12Gi"},
                "persistentVolumeClaims": "6",
                "pods": "30",
            },
        }

    # legacy: no overrides. Caller should not normally re-render legacy
    # tenants; if they do, hand back the base values unchanged.
    return {}


def render_tenant_values(
    tenant: Tenant,
    integration: IntegrationConfig,
    branding: BrandingConfig,
    *,
    mssp_id: str,
    install_id: str,
    llm_secret_name: str,
    adapter_token_secret: str = "adapter-token",
    api_service_host: str = "soctalk-system-api.soctalk-system.svc.cluster.local",
    api_service_port: int = 8000,
    allowed_llm_hosts: list[str] | None = None,
    agent_hostname: str | None = None,
    cert_issuer: str | None = None,
    profile: Profile = "poc",
    network_policies_enabled: bool = True,
) -> dict[str, Any]:
    """Produce a values dict for the tenant chart.

    Args:
        tenant: the ``Tenant`` DB row.
        integration: per-tenant integration config (LLM, Wazuh/TheHive/Cortex URLs).
        branding: per-tenant branding config.
        mssp_id: install's MSSP UUID (from ``Organization``).
        install_id: install's UUID.
        llm_secret_name: name of the K8s Secret in ``soctalk-system`` holding
            this tenant's LLM API key.
        allowed_llm_hosts: FQDNs permitted in Cilium egress policy.
            Defaults to the host portion of ``integration.llm_base_url``.
        agent_hostname: public hostname used by Wazuh agents (see wazuh-ingress).
        cert_issuer: cert-manager ClusterIssuer for per-tenant TLS.

    Returns:
        A dict matching ``soctalk-tenant/values.schema.json``.
    """
    from urllib.parse import urlparse

    if allowed_llm_hosts is None:
        host = urlparse(integration.llm_base_url).hostname
        allowed_llm_hosts = [host] if host else []

    values: dict[str, Any] = {
        "tenant": {
            "id": str(tenant.id),
            "slug": tenant.slug,
            "msspId": mssp_id,
            "installId": install_id,
            "displayName": tenant.display_name,
        },
        "branding": {
            "appName": branding.app_name,
            "logoUrl": branding.logo_url or "",
            "primaryColor": branding.primary_color or "#1a73e8",
            "secondaryColor": branding.secondary_color or "#fbbc04",
            "favicon": branding.favicon_url or "",
        },
        "llm": {
            "provider": integration.llm_provider,
            "baseUrl": integration.llm_base_url,
            "model": integration.llm_model,
            # Pass the plaintext through so the chart's 25-secrets.yaml
            # materializes ``tenant-llm-key`` on install. Without this
            # the chart's ``{{- if .Values.llm.apiKey }}`` guard skips
            # the Secret, the runs-worker mounts an empty secretKeyRef,
            # and triage fails with "No LLM API key configured" until
            # an admin PATCHes /api/mssp/tenants/{id}/llm post-install.
            # Empty string when the MSSP hasn't seeded a key yet — the
            # chart treats that as "operator will pre-provision",
            # matching the original collapsed-tier contract.
            "apiKey": integration.llm_api_key_plain or "",
            "apiKeyRef": {
                # Tenant-local Secret. The controller mirrors the
                # install's shared LLM key into the tenant ns under
                # ``tenant-llm-key`` at provisioning so secretKeyRef
                # resolves same-namespace from the worker + adapter
                # pods. ``namespace`` is informational only — k8s
                # secretKeyRef ignores cross-namespace.
                "namespace": "",
                "name": "tenant-llm-key",
                "key": "api_key",
            },
        },
        "components": {
            "wazuh": {"enabled": integration.wazuh_enabled},
            "thehive": {"enabled": integration.thehive_enabled},
            "cortex": {"enabled": integration.cortex_enabled},
            "misp": {"enabled": False},  # V1: MISP deferred regardless of config
        },
        "networkPolicies": {
            "enabled": network_policies_enabled,
            "allowedLlmHosts": allowed_llm_hosts,
        },
        "resourceQuota": {
            "enabled": True,
            "requests": {"cpu": "3", "memory": "8Gi"},
            "limits": {"cpu": "7", "memory": "16Gi"},
            "persistentVolumeClaims": "10",
            "pods": "50",
        },
        "limitRange": {
            "enabled": True,
            "defaults": {"memory": "2Gi", "cpu": "500m"},
            "defaultRequests": {"memory": "256Mi", "cpu": "100m"},
            "max": {"memory": "6Gi", "cpu": "2"},
        },
        "agentIngress": {
            "hostname": agent_hostname or f"{tenant.slug}.soc.mssp.local",
            "tls": {
                "issuerRef": cert_issuer or "letsencrypt-prod",
                "secretName": "wazuh-tls",
            },
        },
        "adapter": {
            "image": {
                "repository": os.getenv(
                    "SOCTALK_TENANT_ADAPTER_IMAGE_REPO",
                    "ghcr.io/soctalk/soctalk-adapter",
                ),
                "tag": os.getenv("SOCTALK_TENANT_ADAPTER_IMAGE_TAG", "0.1.13-fixes"),
                "pullPolicy": "IfNotPresent",
            },
            "resources": {
                "requests": {"cpu": "50m", "memory": "128Mi"},
                "limits": {"cpu": "200m", "memory": "256Mi"},
            },
            "api": {
                "serviceHost": api_service_host,
                "servicePort": api_service_port,
            },
            "tokenSecretRef": {
                "name": adapter_token_secret,
                "key": "token",
            },
            "wazuhIndexer": {
                "url": f"https://wazuh-{tenant.slug}-wazuh-indexer:9200",
                "credsSecret": f"wazuh-{tenant.slug}-wazuh-creds",
                "usernameKey": "INDEXER_USERNAME",
                "passwordKey": "INDEXER_PASSWORD",
                "minSeverity": int(
                    os.getenv("SOCTALK_ADAPTER_MIN_SEVERITY", "10")
                ),
            },
        },
        "runsWorker": {
            "enabled": True,
            "replicas": 1,
            "image": {
                "repository": os.getenv(
                    "SOCTALK_TENANT_RUNS_WORKER_IMAGE_REPO",
                    "ghcr.io/soctalk/soctalk-orchestrator",
                ),
                "tag": os.getenv(
                    "SOCTALK_TENANT_RUNS_WORKER_IMAGE_TAG", "0.1.13-fixes"
                ),
                "pullPolicy": "IfNotPresent",
            },
            "resources": {
                # Lab tenants share a 4-CPU ResourceQuota with the
                # wazuh stack + adapter (~3 CPU together). Original
                # 1-CPU limit was unschedulable in fresh tenants;
                # 500m fits with headroom for one restart.
                "requests": {"cpu": "100m", "memory": "256Mi"},
                "limits": {"cpu": "500m", "memory": "512Mi"},
            },
            "tokenSecretRef": {
                "name": "runs-worker-token",
                "key": "token",
            },
            "fastModel": integration.llm_model,
            "reasoningModel": integration.llm_model,
        },
        "namespaceLabels": {
            "tenant": "true",
            "managed-by": "soctalk",
        },
    }

    # Layer profile overrides on top. Shallow-merge at the top level.
    # (No top-level "profile" key: the chart's values.schema.json rejects
    # unknown root fields, and the profile is already visible via
    # namespaceLabels.soctalk.io/profile emitted during ensure_namespace.)
    for k, v in _profile_tenant_overrides(profile).items():
        values[k] = v
    return values


def render_wazuh_values(
    tenant: Tenant,
    *,
    profile: Profile,
    admin_password: str,
    authd_password: str,
    storage_class_override: str | None = None,
) -> dict[str, Any]:
    """Produce per-tenant values for ``charts/wazuh``.

    The base chart has ``values.yaml`` (defaults) plus ``values.poc.yaml``
    and ``values.persistent.yaml`` on disk. Helm layers those first (via
    ``-f``), and this dict is the **last** layer — per-tenant overrides
    on top: minted credentials, tenant-scoped cluster name, optional
    storage-class pin from controller settings (for ``persistent``).
    """

    values: dict[str, Any] = {
        "credentials": {
            "apiUsername": "wazuh-wui",
            "apiPassword": admin_password,
            "indexerUsername": "admin",
            # The demo-security init in the upstream indexer image still
            # expects admin:admin; until we override internal_users.yml
            # at install time, filebeat on the manager will 401 if this
            # changes. See k3d setup notes.
            "indexerPassword": "admin",
            "authdPassword": authd_password,
        },
        "tenant": {
            "id": str(tenant.id),
            "slug": tenant.slug,
            "profile": profile,
        },
    }

    base_domain = os.getenv("SOCTALK_TENANT_BASE_DOMAIN", "").strip()
    if base_domain:
        values["dashboard"] = {
            "ingress": {
                "enabled": True,
                "className": os.getenv("SOCTALK_INGRESS_CLASS_NAME", "nginx"),
                "hostname": f"wazuh-{tenant.slug}.{base_domain}",
            },
        }

    if storage_class_override:
        values["storage"] = {"storageClass": storage_class_override}

    return values
