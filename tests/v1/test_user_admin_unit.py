"""Deterministic guards for user administration: role assignability, platform-admin protection,
audience wall, and the endpoint capability gates. No DB."""

from __future__ import annotations

import os
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

os.environ.setdefault("SOCTALK_JWT_SIGNING_KEY", "test-signing-key-32-bytes-plaintext")

from soctalk.core.api.user_admin import (  # noqa: E402
    assert_role_assignable,
    assert_target_not_protected,
    validate_email,
)
from soctalk.core.tenancy.models import Role, UserType  # noqa: E402


def _id(role):
    return SimpleNamespace(role=role)


def _raises(fn, *a):
    with pytest.raises(HTTPException) as exc:
        fn(*a)
    return exc.value.status_code


# --- role assignability + audience wall ---


def test_mssp_roles_assignable_only_on_mssp_side():
    caller = _id(Role.MSSP_ADMIN.value)
    for r in (Role.ANALYST.value, Role.MSSP_MANAGER.value, Role.MSSP_ADMIN.value):
        assert_role_assignable(caller, r, "mssp")  # no raise
    # a tenant role cannot be assigned through the MSSP endpoint
    for r in (Role.TENANT_ANALYST.value, Role.CUSTOMER_VIEWER.value):
        assert _raises(assert_role_assignable, caller, r, "mssp") == 422


def test_tenant_roles_assignable_only_on_tenant_side():
    caller = _id(Role.TENANT_ADMIN.value)
    for r in (Role.CUSTOMER_VIEWER.value, Role.TENANT_ANALYST.value, Role.TENANT_MANAGER.value, Role.TENANT_ADMIN.value):
        assert_role_assignable(caller, r, "tenant")
    for r in (Role.ANALYST.value, Role.MSSP_ADMIN.value, Role.PLATFORM_ADMIN.value):
        assert _raises(assert_role_assignable, caller, r, "tenant") == 422


def test_only_platform_admin_may_assign_platform_admin():
    assert _raises(assert_role_assignable, _id(Role.MSSP_ADMIN.value), Role.PLATFORM_ADMIN.value, "mssp") == 403
    # a platform_admin can
    assert_role_assignable(_id(Role.PLATFORM_ADMIN.value), Role.PLATFORM_ADMIN.value, "mssp")


# --- platform-admin target protection ---


def test_existing_platform_admin_only_mutable_by_platform_admin():
    # mssp_admin cannot touch a platform_admin target
    assert _raises(assert_target_not_protected, _id(Role.MSSP_ADMIN.value), Role.PLATFORM_ADMIN.value) == 403
    # platform_admin can
    assert_target_not_protected(_id(Role.PLATFORM_ADMIN.value), Role.PLATFORM_ADMIN.value)
    # a non-platform target is unprotected
    assert_target_not_protected(_id(Role.MSSP_ADMIN.value), Role.MSSP_MANAGER.value)


# --- email validation ---


def test_email_validation():
    assert validate_email("  Ana@Acme.COM ") == "ana@acme.com"
    for bad in ("nope", "a@b", "@x.com", "x@.com", "x@com.", "a b@x.com", "a@b@c.com"):
        with pytest.raises(ValueError):
            validate_email(bad)


# --- endpoint capability gates ---


class _Req:
    def __init__(self, identity):
        self.state = type("S", (), {"user_identity": identity})()


async def _status(guard, ut, role):
    try:
        await guard(_Req({"user_type": ut, "role": role, "tenant_id": "t1"}))
        return None
    except HTTPException as e:
        return e.status_code


@pytest.mark.asyncio
async def test_mssp_user_mgmt_is_admin_tier_only():
    from soctalk.core.api.mssp_users import _MANAGE

    assert await _status(_MANAGE, UserType.MSSP.value, Role.MSSP_ADMIN.value) is None
    assert await _status(_MANAGE, UserType.MSSP.value, Role.PLATFORM_ADMIN.value) is None
    assert await _status(_MANAGE, UserType.MSSP.value, Role.MSSP_MANAGER.value) == 403
    assert await _status(_MANAGE, UserType.MSSP.value, Role.ANALYST.value) == 403
    # a tenant user can never reach the MSSP endpoint
    assert await _status(_MANAGE, UserType.TENANT.value, Role.TENANT_ADMIN.value) == 403


@pytest.mark.asyncio
async def test_tenant_user_mgmt_is_tenant_admin_only():
    from soctalk.core.api.users import _MANAGE

    assert await _status(_MANAGE, UserType.TENANT.value, Role.TENANT_ADMIN.value) is None
    assert await _status(_MANAGE, UserType.TENANT.value, Role.TENANT_MANAGER.value) == 403
    assert await _status(_MANAGE, UserType.TENANT.value, Role.TENANT_ANALYST.value) == 403
    assert await _status(_MANAGE, UserType.TENANT.value, Role.CUSTOMER_VIEWER.value) == 403
    # an MSSP user can never reach the tenant endpoint
    assert await _status(_MANAGE, UserType.MSSP.value, Role.MSSP_ADMIN.value) == 403
