"""Capability (permission) layer over the role model.

Roles name *who someone is*; permissions name *what they may do*. Endpoint guards check
capabilities (``require_permission``), and roles are just named bundles of them. This gives real
separation of duties across three functional tiers, applied per audience:

    Admin (configure)  ⊇  SOC Manager (authorize risk)  ⊇  SOC Analyst (operate)

The bundles are hierarchical (a higher tier holds every lower-tier capability), but every
capability is listed explicitly per role below so a strict-SoD deployment can later split a
sensitive capability (e.g. AUTHORIZE_ENGAGEMENT) out of admin without touching call sites.

``ROLE_PERMISSIONS`` is the single source of truth; nothing else should hardcode which role may
do what. Audience (MSSP vs tenant) is orthogonal and enforced separately at the route
(``require_permission(..., audience=...)``).
"""

from __future__ import annotations

from enum import Enum

from soctalk.core.tenancy.models import Role


class Permission(str, Enum):
    # --- operate (SOC analyst) ---
    VIEW_INVESTIGATIONS = "view_investigations"
    TRIAGE_INVESTIGATION = "triage_investigation"      # post messages, cancel, edit case facts
    REVIEW_DECIDE = "review_decide"                    # approve/reject/expire a pending review
    APPROVE_PROPOSAL = "approve_proposal"              # approve/reject standard-blast proposals
    VIEW_ALERTS = "view_alerts"
    VIEW_DASHBOARD = "view_dashboard"
    VIEW_ANALYTICS = "view_analytics"
    VIEW_AUDIT = "view_audit"
    USE_CHAT = "use_chat"
    VIEW_TRIAGE_POLICIES = "view_triage_policies"
    VIEW_ENGAGEMENTS = "view_engagements"
    VIEW_AUTHORIZATION_FACTS = "view_authorization_facts"
    VIEW_TENANTS = "view_tenants"

    # --- authorize risk (SOC manager, + analyst) ---
    AUTHORIZE_ENGAGEMENT = "authorize_engagement"      # declare/revoke engagements
    MANAGE_AUTHORIZATION_FACTS = "manage_authorization_facts"  # create/revoke authz facts
    APPROVE_PRIVILEGED_PROPOSAL = "approve_privileged_proposal"  # high-blast (WRITE_EXTERNAL)

    # --- configure the system (admin, + manager) ---
    CONFIGURE_INTEGRATIONS = "configure_integrations"
    MANAGE_EXTERNAL_SIEM = "manage_external_siem"
    CONFIGURE_LLM = "configure_llm"
    MANAGE_BRANDING = "manage_branding"
    MANAGE_USERS = "manage_users"
    MANAGE_TRIAGE_POLICIES = "manage_triage_policies"  # author/activate custom policies
    MANAGE_TENANT_LIFECYCLE = "manage_tenant_lifecycle"

    # --- tenant self-service (tenant audience) ---
    TENANT_VIEW_INVESTIGATIONS = "tenant_view_investigations"
    TENANT_VIEW_BRANDING = "tenant_view_branding"
    TENANT_MANAGE_LLM = "tenant_manage_llm"
    TENANT_VIEW_ENGAGEMENTS = "tenant_view_engagements"
    TENANT_AUTHORIZE_ENGAGEMENT = "tenant_authorize_engagement"  # declare/revoke own engagements
    TENANT_VIEW_AUTHORIZATION_FACTS = "tenant_view_authorization_facts"
    TENANT_ASSERT_AUTHORIZATION_FACTS = "tenant_assert_authorization_facts"  # assert (→ pending review)


# ---------------------------------------------------------------------------
# Tier bundles (MSSP audience) — built additively so the hierarchy is explicit.
# ---------------------------------------------------------------------------

_ANALYST: frozenset[Permission] = frozenset(
    {
        Permission.VIEW_INVESTIGATIONS,
        Permission.TRIAGE_INVESTIGATION,
        Permission.REVIEW_DECIDE,
        Permission.APPROVE_PROPOSAL,
        Permission.VIEW_ALERTS,
        Permission.VIEW_DASHBOARD,
        Permission.VIEW_ANALYTICS,
        Permission.VIEW_AUDIT,
        Permission.USE_CHAT,
        Permission.VIEW_TRIAGE_POLICIES,
        Permission.VIEW_ENGAGEMENTS,
        Permission.VIEW_AUTHORIZATION_FACTS,
        Permission.VIEW_TENANTS,
    }
)

# SOC manager adds the "authorize risk" capabilities.
_MANAGER: frozenset[Permission] = _ANALYST | {
    Permission.AUTHORIZE_ENGAGEMENT,
    Permission.MANAGE_AUTHORIZATION_FACTS,
    Permission.APPROVE_PRIVILEGED_PROPOSAL,
}

# Admin adds "configure the system".
_ADMIN: frozenset[Permission] = _MANAGER | {
    Permission.CONFIGURE_INTEGRATIONS,
    Permission.MANAGE_EXTERNAL_SIEM,
    Permission.CONFIGURE_LLM,
    Permission.MANAGE_BRANDING,
    Permission.MANAGE_USERS,
    Permission.MANAGE_TRIAGE_POLICIES,
    Permission.MANAGE_TENANT_LIFECYCLE,
}

# --- tenant audience bundles (viewer ⊆ manager ⊆ admin) ---
_TENANT_VIEWER: frozenset[Permission] = frozenset(
    {
        Permission.TENANT_VIEW_INVESTIGATIONS,
        Permission.TENANT_VIEW_BRANDING,
        Permission.TENANT_VIEW_ENGAGEMENTS,
        Permission.TENANT_VIEW_AUTHORIZATION_FACTS,
    }
)
# tenant SOC manager authorizes their own risk: declares pentest engagements and asserts
# authorization facts (which land 'pending' for MSSP review before they can influence triage).
_TENANT_MANAGER: frozenset[Permission] = _TENANT_VIEWER | {
    Permission.TENANT_AUTHORIZE_ENGAGEMENT,
    Permission.TENANT_ASSERT_AUTHORIZATION_FACTS,
}
# tenant admin adds self-service config
_TENANT_ADMIN: frozenset[Permission] = _TENANT_MANAGER | {Permission.TENANT_MANAGE_LLM}


ROLE_PERMISSIONS: dict[str, frozenset[Permission]] = {
    Role.PLATFORM_ADMIN.value: _ADMIN,   # cross-install super-admin: every MSSP capability
    Role.MSSP_ADMIN.value: _ADMIN,
    Role.MSSP_MANAGER.value: _MANAGER,
    Role.ANALYST.value: _ANALYST,
    Role.TENANT_ADMIN.value: _TENANT_ADMIN,
    Role.TENANT_MANAGER.value: _TENANT_MANAGER,
    Role.CUSTOMER_VIEWER.value: _TENANT_VIEWER,
}


def permissions_for(role: str | Role | None) -> frozenset[Permission]:
    """Every capability a role holds (empty for unknown / token-only principals
    like ``adapter``/``worker``)."""
    key = role.value if isinstance(role, Role) else role
    return ROLE_PERMISSIONS.get(key or "", frozenset())


def has_permission(role: str | Role | None, perm: Permission) -> bool:
    return perm in permissions_for(role)


# Capability classes whose proposal approval is a privileged (manager-tier) action:
# anything that writes to an external system. Reads and sandbox writes stay analyst-tier.
PRIVILEGED_CAPABILITY_CLASSES: frozenset[str] = frozenset({"write_external"})
