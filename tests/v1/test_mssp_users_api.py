"""MSSP-side user management (Postgres): CRUD happy path plus the escalation, platform-admin
protection, self-modify, and audience/tenant-scope guards."""

from __future__ import annotations

import os
from types import SimpleNamespace
from uuid import uuid4

import pytest
from fastapi import HTTPException

os.environ.setdefault("SOCTALK_JWT_SIGNING_KEY", "test-signing-key-32-bytes-plaintext")

from soctalk.core.tenancy.models import Role, UserType  # noqa: E402

SKIP_INTEGRATION = os.getenv("SKIP_INTEGRATION", "0") == "1"
pytestmark = [pytest.mark.integration, pytest.mark.skipif(SKIP_INTEGRATION, reason="needs Postgres")]


@pytest.fixture(autouse=True)
async def _fresh_cached_engines():
    # The handlers open their own sessions via the module-cached get_mssp_sessionmaker engine.
    # Dispose it after each test so the next function-scoped event loop gets a fresh engine
    # (asyncpg pools are bound to the loop that created them).
    yield
    from soctalk.core.tenancy.db import dispose_engines

    await dispose_engines()


class _Req:
    def __init__(self, identity):
        self.state = type("S", (), {"user_identity": identity})()


def _mssp(role, user_id):
    return _Req(
        {
            "user_id": str(user_id),
            "email": f"{role}@mssp.example",
            "user_type": UserType.MSSP.value,
            "role": role,
            "tenant_id": None,
            "current_tenant": None,
        }
    )


async def test_create_list_and_role_change(mssp_session):
    from uuid import UUID

    from sqlalchemy import text

    from soctalk.core.api.mssp_users import (
        MsspUserCreate,
        MsspUserUpdate,
        create_mssp_user,
        list_mssp_users,
        update_mssp_user,
    )

    admin = _mssp(Role.MSSP_ADMIN.value, uuid4())
    email = f"analyst-{uuid4().hex[:8]}@mssp.example"
    try:
        created = await create_mssp_user(
            MsspUserCreate(email=email, role=Role.ANALYST.value), admin
        )
        assert created.role == Role.ANALYST.value
        assert created.temporary_password

        listed = await list_mssp_users(admin)
        assert any(u.email == email and u.role == Role.ANALYST.value for u in listed)

        # promote analyst -> mssp_manager
        updated = await update_mssp_user(
            UUID(created.id), MsspUserUpdate(role=Role.MSSP_MANAGER.value), admin
        )
        assert updated.role == Role.MSSP_MANAGER.value
    finally:
        await mssp_session.execute(text("DELETE FROM users WHERE email = :e"), {"e": email})
        await mssp_session.commit()


async def test_audience_and_escalation_guards():
    from soctalk.core.api.mssp_users import MsspUserCreate, create_mssp_user

    admin = _mssp(Role.MSSP_ADMIN.value, uuid4())
    # a tenant role cannot be created through the MSSP endpoint
    with pytest.raises(HTTPException) as e1:
        await create_mssp_user(
            MsspUserCreate(email="x@mssp.example", role=Role.TENANT_ANALYST.value), admin
        )
    assert e1.value.status_code == 422
    # an mssp_admin cannot mint a platform_admin
    with pytest.raises(HTTPException) as e2:
        await create_mssp_user(
            MsspUserCreate(email="y@mssp.example", role=Role.PLATFORM_ADMIN.value), admin
        )
    assert e2.value.status_code == 403


async def test_platform_admin_target_is_protected(mssp_session):
    from sqlalchemy import text

    from soctalk.core.api.mssp_users import MsspUserUpdate, deactivate_mssp_user, update_mssp_user

    pa_id = uuid4()
    email = f"pa-{uuid4().hex[:8]}@mssp.example"
    await mssp_session.execute(
        text(
            "INSERT INTO users (id, email, display_name, user_type, role, tenant_id, active, created_at) "
            "VALUES (:id, :e, 'pa', 'mssp', 'platform_admin', NULL, true, now())"
        ),
        {"id": str(pa_id), "e": email},
    )
    await mssp_session.commit()
    admin = _mssp(Role.MSSP_ADMIN.value, uuid4())
    try:
        # an mssp_admin may not demote or deactivate an existing platform_admin
        with pytest.raises(HTTPException) as e1:
            await update_mssp_user(pa_id, MsspUserUpdate(role=Role.ANALYST.value), admin)
        assert e1.value.status_code == 403
        with pytest.raises(HTTPException) as e2:
            await deactivate_mssp_user(pa_id, admin)
        assert e2.value.status_code == 403
    finally:
        await mssp_session.execute(text("DELETE FROM users WHERE id = :id"), {"id": str(pa_id)})
        await mssp_session.commit()


async def test_self_modify_blocked():
    from soctalk.core.api.mssp_users import MsspUserUpdate, deactivate_mssp_user, update_mssp_user

    me = uuid4()
    admin = _mssp(Role.MSSP_ADMIN.value, me)
    with pytest.raises(HTTPException) as e1:
        await update_mssp_user(me, MsspUserUpdate(role=Role.ANALYST.value), admin)
    assert e1.value.status_code == 400
    with pytest.raises(HTTPException) as e2:
        await deactivate_mssp_user(me, admin)
    assert e2.value.status_code == 400


async def test_mssp_endpoint_cannot_touch_a_tenant_user(seed_two_tenants):
    from soctalk.core.api.mssp_users import MsspUserUpdate, update_mssp_user

    a, _ = seed_two_tenants
    admin = _mssp(Role.MSSP_ADMIN.value, uuid4())
    # a.viewer_user_id is a tenant customer_viewer; the MSSP endpoint must not see it
    with pytest.raises(HTTPException) as exc:
        await update_mssp_user(a.viewer_user_id, MsspUserUpdate(active=False), admin)
    assert exc.value.status_code == 404
