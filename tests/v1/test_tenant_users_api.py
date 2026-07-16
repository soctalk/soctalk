"""Tenant self-service user management: gating, role validation, and own-tenant creation."""

from __future__ import annotations

import os
from types import SimpleNamespace
from uuid import uuid4

import pytest
from fastapi import HTTPException

os.environ.setdefault("SOCTALK_JWT_SIGNING_KEY", "test-signing-key-32-bytes-plaintext")

from soctalk.core.tenancy.models import Role, UserType  # noqa: E402


# --------------------------------------------------------------------------- #
# Guard gating + role validation (deterministic, no DB)
# --------------------------------------------------------------------------- #


class _FakeRequest:
    def __init__(self, identity, db=None):
        self.state = type("S", (), {"user_identity": identity, "db": db})()


def _id(role, tenant_id="t1"):
    return {"user_type": UserType.TENANT.value, "role": role, "tenant_id": tenant_id}


async def _status(guard, identity):
    try:
        await guard(_FakeRequest(identity))
        return None
    except HTTPException as e:
        return e.status_code


@pytest.mark.asyncio
async def test_only_tenant_admin_may_manage_users():
    from soctalk.core.api.users import _MANAGE_USERS

    assert await _status(_MANAGE_USERS, _id(Role.TENANT_ADMIN.value)) is None
    assert await _status(_MANAGE_USERS, _id(Role.TENANT_MANAGER.value)) == 403
    assert await _status(_MANAGE_USERS, _id(Role.TENANT_ANALYST.value)) == 403
    assert await _status(_MANAGE_USERS, _id(Role.CUSTOMER_VIEWER.value)) == 403
    # MSSP audience is walled off from this tenant endpoint
    assert (
        await _status(
            _MANAGE_USERS,
            {"user_type": UserType.MSSP.value, "role": Role.MSSP_ADMIN.value, "tenant_id": None},
        )
        == 403
    )


@pytest.mark.asyncio
async def test_cannot_assign_a_non_tenant_or_unknown_role():
    from soctalk.core.api.users import TenantUserCreate, create_tenant_user

    ident = SimpleNamespace(
        user_id=uuid4(), email="admin@acme.example", role=Role.TENANT_ADMIN.value, tenant_id=uuid4()
    )
    req = _FakeRequest(ident)
    # an MSSP role is rejected 422 BEFORE any DB access (the audience wall for role assignment)
    for bad in (Role.MSSP_ADMIN.value, Role.ANALYST.value, "root", ""):
        with pytest.raises(HTTPException) as exc:
            await create_tenant_user(TenantUserCreate(email="new@acme.example", role=bad), req)
        assert exc.value.status_code == 422


def test_email_is_shape_validated():
    from soctalk.core.api.users import TenantUserCreate

    from pydantic import ValidationError

    for bad in ("nope", "a@b", "@acme.com", "x@.com", "x@com."):
        with pytest.raises(ValidationError):
            TenantUserCreate(email=bad, role=Role.TENANT_ANALYST.value)
    # good one normalises to lowercase
    assert TenantUserCreate(email="Ana@Acme.COM", role=Role.TENANT_ANALYST.value).email == "ana@acme.com"


# --------------------------------------------------------------------------- #
# Own-tenant creation (Postgres) — tenant_admin provisions a tenant_analyst
# --------------------------------------------------------------------------- #

SKIP_INTEGRATION = os.getenv("SKIP_INTEGRATION", "0") == "1"


@pytest.mark.integration
@pytest.mark.skipif(SKIP_INTEGRATION, reason="needs Postgres")
async def test_tenant_admin_creates_and_lists_a_tenant_analyst(app_session, mssp_session, seed_two_tenants):
    from soctalk.core.api.users import (
        TenantUserCreate,
        create_tenant_user,
        deactivate_tenant_user,
        list_tenant_users,
    )

    a, _ = seed_two_tenants
    await mssp_session.commit()  # make the seeded tenants visible to the app-role session

    # current_identity() rebuilds a UserIdentity from this dict, so pass the full claim shape.
    admin = {
        "user_id": str(a.admin_user_id),
        "email": "admin-a@acme.example",
        "user_type": UserType.TENANT.value,
        "role": Role.TENANT_ADMIN.value,
        "tenant_id": str(a.tenant_id),
        "current_tenant": None,
    }
    req = _FakeRequest(admin, db=app_session)
    email = f"analyst-{uuid4().hex[:8]}@acme.example"
    try:
        created = await create_tenant_user(
            TenantUserCreate(email=email, role=Role.TENANT_ANALYST.value), req
        )
        await app_session.commit()
        assert created.role == Role.TENANT_ANALYST.value
        assert created.temporary_password  # surfaced once
        assert created.email == email

        listed = await list_tenant_users(req)
        assert any(u.email == email and u.role == Role.TENANT_ANALYST.value for u in listed)

        # deactivate it (audits + revokes sessions; no-op revoke for a fresh user) → active=false
        from uuid import UUID as _UUID

        await deactivate_tenant_user(_UUID(created.id), req)
        await app_session.commit()
        after = await list_tenant_users(req)
        row = next(u for u in after if u.id == created.id)
        assert row.active is False

        # cannot deactivate self (parsed-UUID compare)
        with pytest.raises(HTTPException) as exc:
            await deactivate_tenant_user(a.admin_user_id, req)
        assert exc.value.status_code == 400
    finally:
        from sqlalchemy import text

        await mssp_session.execute(text("DELETE FROM users WHERE email = :e"), {"e": email})
        await mssp_session.commit()
