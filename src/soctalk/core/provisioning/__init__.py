"""Tenant provisioning and lifecycle control plane.

``docs/v1/P0-8-two-chart-contract.md`` §6 (render → apply flow).

The :class:`TenantController` orchestrates:

1. Secret generation per P0-5 §5.
2. Namespace creation with required labels (no Kyverno in V1; application code
   enforces naming).
3. Per-tenant K8s Secret provisioning in both ``soctalk-system`` (for
   orchestrator-accessed secrets like LLM keys) and the tenant namespace
   (for data-plane bootstrap creds).
4. Rendering ``charts/soctalk-tenant`` values from the tenant config row.
5. Invoking Helm install/upgrade/uninstall.
6. Emitting :class:`TenantLifecycleEvent` rows on every transition.

V1 uses the Helm SDK via subprocess (``helm install`` CLI) as the fallback
most friendly to async Python. V1.5 can swap to embedded Go Helm SDK or
``pyhelm``.
"""

from soctalk.core.provisioning.controller import (  # noqa: F401
    ProvisionError,
    TenantController,
    TenantLifecycleError,
)
from soctalk.core.provisioning.render import (  # noqa: F401
    Profile,
    render_tenant_values,
    render_wazuh_values,
)
from soctalk.core.provisioning.worker import ProvisioningWorker  # noqa: F401

__all__ = [
    "ProvisionError",
    "Profile",
    "ProvisioningWorker",
    "TenantController",
    "TenantLifecycleError",
    "render_tenant_values",
    "render_wazuh_values",
]
