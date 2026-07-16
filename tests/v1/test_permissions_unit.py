"""The capability layer: tier hierarchy, separation of duties, and matrix integrity.

These are the invariants the RBAC redesign rests on — if a future edit accidentally hands an
analyst a manager/admin capability, or leaves a permission unheld by any role, this fails.
"""

from __future__ import annotations

import pytest

from soctalk.core.tenancy.decorators import MSSP_ROLES, require_permission
from soctalk.core.tenancy.models import Role
from soctalk.core.tenancy.permissions import (
    ROLE_PERMISSIONS,
    Permission,
    has_permission,
    permissions_for,
)

_MANAGER_CAPS = {
    Permission.AUTHORIZE_ENGAGEMENT,
    Permission.MANAGE_AUTHORIZATION_FACTS,
    Permission.APPROVE_PRIVILEGED_PROPOSAL,
}
_ADMIN_CAPS = {
    Permission.CONFIGURE_INTEGRATIONS,
    Permission.MANAGE_EXTERNAL_SIEM,
    Permission.CONFIGURE_LLM,
    Permission.MANAGE_BRANDING,
    Permission.MANAGE_USERS,
    Permission.MANAGE_TRIAGE_POLICIES,
    Permission.MANAGE_TENANT_LIFECYCLE,
}


def test_tiers_are_strictly_hierarchical():
    analyst = permissions_for(Role.ANALYST)
    manager = permissions_for(Role.MSSP_MANAGER)
    admin = permissions_for(Role.MSSP_ADMIN)
    assert analyst < manager < admin
    assert permissions_for(Role.PLATFORM_ADMIN) == admin  # super-admin == full admin bundle


def test_separation_of_duties():
    # analyst operates but cannot authorize risk or configure the system
    for cap in _MANAGER_CAPS | _ADMIN_CAPS:
        assert not has_permission(Role.ANALYST, cap), f"analyst must not hold {cap}"
    # manager authorizes risk but cannot configure the system
    for cap in _MANAGER_CAPS:
        assert has_permission(Role.MSSP_MANAGER, cap)
    for cap in _ADMIN_CAPS:
        assert not has_permission(Role.MSSP_MANAGER, cap), f"manager must not hold {cap}"
    # admin configures (and, by hierarchy, holds the manager caps)
    for cap in _ADMIN_CAPS | _MANAGER_CAPS:
        assert has_permission(Role.MSSP_ADMIN, cap)


def test_analyst_keeps_core_operations():
    for cap in (
        Permission.VIEW_INVESTIGATIONS,
        Permission.TRIAGE_INVESTIGATION,
        Permission.REVIEW_DECIDE,
        Permission.APPROVE_PROPOSAL,
        Permission.USE_CHAT,
        Permission.VIEW_ENGAGEMENTS,
        Permission.VIEW_AUTHORIZATION_FACTS,
    ):
        assert has_permission(Role.ANALYST, cap)


def test_tenant_roles_are_audience_isolated():
    # tenant roles hold only TENANT_* capabilities, never an MSSP capability
    for role in (Role.TENANT_ADMIN, Role.CUSTOMER_VIEWER):
        for cap in permissions_for(role):
            assert cap.value.startswith("tenant_"), f"{role} holds non-tenant cap {cap}"
    # and no MSSP role holds a tenant capability
    for role in (Role.PLATFORM_ADMIN, Role.MSSP_ADMIN, Role.MSSP_MANAGER, Role.ANALYST):
        for cap in permissions_for(role):
            assert not cap.value.startswith("tenant_"), f"{role} holds tenant cap {cap}"


def test_matrix_parity_no_orphan_permissions():
    """Every declared Permission is granted to at least one role (no dead capability)."""
    granted = set().union(*ROLE_PERMISSIONS.values())
    orphans = set(Permission) - granted
    assert not orphans, f"permissions held by no role: {sorted(p.value for p in orphans)}"


def test_token_only_principals_have_no_permissions():
    for role in (None, "", "adapter", "worker"):
        assert permissions_for(role) == frozenset()


def test_mssp_manager_is_a_recognised_mssp_role():
    assert Role.MSSP_MANAGER.value in MSSP_ROLES


def test_require_permission_audience_is_mandatory_and_validated():
    with pytest.raises(ValueError):
        require_permission(Permission.VIEW_ALERTS, audience="everyone")
    # both valid audiences build a checker
    assert require_permission(Permission.VIEW_ALERTS, audience="mssp") is not None
    assert require_permission(Permission.TENANT_VIEW_INVESTIGATIONS, audience="tenant") is not None
