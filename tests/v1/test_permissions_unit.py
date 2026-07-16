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
    for role in (Role.TENANT_ADMIN, Role.TENANT_MANAGER, Role.TENANT_ANALYST, Role.CUSTOMER_VIEWER):
        for cap in permissions_for(role):
            assert cap.value.startswith("tenant_"), f"{role} holds non-tenant cap {cap}"
    # and no MSSP role holds a tenant capability
    for role in (Role.PLATFORM_ADMIN, Role.MSSP_ADMIN, Role.MSSP_MANAGER, Role.ANALYST):
        for cap in permissions_for(role):
            assert not cap.value.startswith("tenant_"), f"{role} holds tenant cap {cap}"


# --- tenant ladder: viewer ⊆ analyst ⊆ manager ⊆ admin, mirroring the MSSP side ---

_TENANT_OPERATE_CAPS = {
    Permission.TENANT_TRIAGE_INVESTIGATION,
    Permission.TENANT_REVIEW_DECIDE,
    Permission.TENANT_APPROVE_PROPOSAL,
    Permission.TENANT_USE_CHAT,
}
_TENANT_MANAGER_CAPS = {
    Permission.TENANT_AUTHORIZE_ENGAGEMENT,
    Permission.TENANT_ASSERT_AUTHORIZATION_FACTS,
    Permission.TENANT_APPROVE_PRIVILEGED_PROPOSAL,
}
_TENANT_ADMIN_CAPS = {Permission.TENANT_MANAGE_LLM}


def test_tenant_tiers_are_strictly_hierarchical():
    viewer = permissions_for(Role.CUSTOMER_VIEWER)
    analyst = permissions_for(Role.TENANT_ANALYST)
    manager = permissions_for(Role.TENANT_MANAGER)
    admin = permissions_for(Role.TENANT_ADMIN)
    assert viewer < analyst < manager < admin


def test_tenant_analyst_operates_own_soc():
    # the co-managed-SOC tier holds full operate authority (mirror of the MSSP analyst)
    for cap in _TENANT_OPERATE_CAPS | {Permission.TENANT_VIEW_INVESTIGATIONS}:
        assert has_permission(Role.TENANT_ANALYST, cap), f"tenant_analyst must hold {cap}"


def test_tenant_analyst_separation_of_duties():
    # the analyst operates but cannot authorize risk, sign off high-blast writes, or configure
    for cap in _TENANT_MANAGER_CAPS | _TENANT_ADMIN_CAPS:
        assert not has_permission(Role.TENANT_ANALYST, cap), f"tenant_analyst must not hold {cap}"
    # customer_viewer is read-only: no operate/authorize/configure capability
    for cap in _TENANT_OPERATE_CAPS | _TENANT_MANAGER_CAPS | _TENANT_ADMIN_CAPS:
        assert not has_permission(Role.CUSTOMER_VIEWER, cap), f"customer_viewer must not hold {cap}"
    # manager authorizes risk (and, by hierarchy, operates) but does not configure
    for cap in _TENANT_MANAGER_CAPS | _TENANT_OPERATE_CAPS:
        assert has_permission(Role.TENANT_MANAGER, cap)
    for cap in _TENANT_ADMIN_CAPS:
        assert not has_permission(Role.TENANT_MANAGER, cap), f"tenant_manager must not hold {cap}"


def test_tenant_privileged_proposal_stays_manager_tier_on_both_audiences():
    # WRITE_EXTERNAL proposal sign-off is a manager decision for MSSP and tenant alike
    assert not has_permission(Role.ANALYST, Permission.APPROVE_PRIVILEGED_PROPOSAL)
    assert has_permission(Role.MSSP_MANAGER, Permission.APPROVE_PRIVILEGED_PROPOSAL)
    assert not has_permission(Role.TENANT_ANALYST, Permission.TENANT_APPROVE_PRIVILEGED_PROPOSAL)
    assert has_permission(Role.TENANT_MANAGER, Permission.TENANT_APPROVE_PRIVILEGED_PROPOSAL)


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


# --- require_permission_any: the dual-audience OR-guard for co-managed operate endpoints ---


class _FakeRequest:
    def __init__(self, identity):
        self.state = type("S", (), {"user_identity": identity})()


def _id(user_type, role, tenant_id="t1"):
    return {"user_type": user_type, "role": role, "tenant_id": tenant_id}


async def _run(guard, identity):
    from fastapi import HTTPException

    try:
        await guard(_FakeRequest(identity))
        return None
    except HTTPException as e:
        return e.status_code


@pytest.mark.asyncio
async def test_require_permission_any_admits_either_audience():
    from soctalk.core.tenancy.decorators import require_permission_any

    guard = require_permission_any(
        (Permission.REVIEW_DECIDE, "mssp"),
        (Permission.TENANT_REVIEW_DECIDE, "tenant"),
    )
    # MSSP analyst (holds REVIEW_DECIDE) passes
    assert await _run(guard, _id("mssp", Role.ANALYST.value, tenant_id=None)) is None
    # tenant_analyst (holds TENANT_REVIEW_DECIDE) passes
    assert await _run(guard, _id("tenant", Role.TENANT_ANALYST.value)) is None
    # customer_viewer (holds neither) is denied
    assert await _run(guard, _id("tenant", Role.CUSTOMER_VIEWER.value)) == 403
    # a tenant principal without a tenant_id claim never matches the tenant alternative
    assert await _run(guard, _id("tenant", Role.TENANT_ANALYST.value, tenant_id=None)) == 403
    # unauthenticated → 401
    assert await _run(guard, None) == 401


@pytest.mark.asyncio
async def test_require_permission_any_does_not_cross_audience():
    from soctalk.core.tenancy.decorators import require_permission_any

    # A guard that only admits the MSSP alternative must reject a tenant caller even if the
    # tenant role happens to hold a same-named-ish capability — audience is a hard wall.
    guard = require_permission_any((Permission.REVIEW_DECIDE, "mssp"))
    assert await _run(guard, _id("tenant", Role.TENANT_ANALYST.value)) == 403
    assert await _run(guard, _id("mssp", Role.ANALYST.value, tenant_id=None)) is None


def test_no_tenant_role_is_ever_a_fleet_bypassrls_role():
    """The load-bearing isolation invariant: the role-sets that select a BYPASSRLS / fleet
    session must never contain a tenant role, or a tenant caller could read cross-tenant."""
    from soctalk.core.api.chat import MSSP_LEVEL_ROLES as CHAT_FLEET
    from soctalk.core.api.legacy_stubs import _MSSP_LEVEL_ROLES as REVIEW_FLEET

    tenant_roles = {
        Role.TENANT_ADMIN.value,
        Role.TENANT_MANAGER.value,
        Role.TENANT_ANALYST.value,
        Role.CUSTOMER_VIEWER.value,
    }
    for fleet_set in (CHAT_FLEET, REVIEW_FLEET, MSSP_ROLES):
        assert not (tenant_roles & set(fleet_set)), (
            f"tenant role leaked into a fleet/BYPASSRLS set: {tenant_roles & set(fleet_set)}"
        )
