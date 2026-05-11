"""V1 multi-tenancy primitives.

See docs/multi-tenant/security-model.md and docs/multi-tenant/postgres-rls.md for the
authoritative design. This package implements the runtime:

- :mod:`~soctalk.core.tenancy.models`. Organization, Tenant, User (4-role),
  IntegrationConfig, BrandingConfig, TenantSecret, AuditLog, TenantLifecycleEvent
- :mod:`~soctalk.core.tenancy.context`: tenant_context middleware +
  ``system_context()`` context manager
- :mod:`~soctalk.core.tenancy.decorators`. ``@tenant_scoped_worker``,
  ``@require_role``, ``@require_tenant_role``
- :mod:`~soctalk.core.tenancy.auth`: ingress-handoff OIDC adapter +
  JWT minting

All DB access from tenant-scoped code paths must happen inside a transaction
with ``app.current_tenant_id`` set. Postgres RLS is the guardrail; application
code is the first line.
"""

from soctalk.core.tenancy.context import (  # noqa: F401
    MissingTenantContext,
    SystemContext,
    TenantContext,
    set_current_tenant,
    system_context,
)
from soctalk.core.tenancy.decorators import (  # noqa: F401
    require_role,
    require_tenant_role,
    tenant_scoped_worker,
)
from soctalk.core.tenancy.models import (  # noqa: F401
    AuditLog,
    BrandingConfig,
    IntegrationConfig,
    Organization,
    Role,
    Tenant,
    TenantLifecycleEvent,
    TenantSecret,
    User,
    UserType,
)

__all__ = [
    "AuditLog",
    "BrandingConfig",
    "IntegrationConfig",
    "MissingTenantContext",
    "Organization",
    "Role",
    "SystemContext",
    "Tenant",
    "TenantContext",
    "TenantLifecycleEvent",
    "TenantSecret",
    "User",
    "UserType",
    "require_role",
    "require_tenant_role",
    "set_current_tenant",
    "system_context",
    "tenant_scoped_worker",
]
