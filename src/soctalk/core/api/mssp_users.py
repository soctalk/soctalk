"""MSSP-side staff user management.

Create, list, update, and deactivate MSSP staff logins (``user_type='mssp'``, null tenant).
Gated on ``MANAGE_USERS`` (admin tier). Uses the BYPASSRLS MSSP session AND an explicit
``user_type='mssp' AND tenant_id IS NULL`` predicate on every query, so these endpoints can never
reach a tenant user even when the caller is pinned to a tenant (the users RLS policy would otherwise
expose ``tenant_id IS NULL`` rows inside a tenant context). Tenant users are managed only via the
tenant self-service endpoints in ``users.py``.
"""

from __future__ import annotations

from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, field_validator
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from soctalk.core.api.user_admin import (
    assert_role_assignable,
    assert_target_not_protected,
    guard_admin_floor,
    new_temp_password,
    revoke_sessions_if_needed,
    validate_email,
)
from soctalk.core.auth.models import PasswordCredential
from soctalk.core.auth.passwords import hash_password
from soctalk.core.observability.audit import log_audit
from soctalk.core.tenancy.auth import current_identity
from soctalk.core.tenancy.db import get_mssp_sessionmaker
from soctalk.core.tenancy.decorators import require_permission
from soctalk.core.tenancy.models import AuditAction, User, UserType
from soctalk.core.tenancy.permissions import Permission

mssp_users_router = APIRouter(prefix="/api/mssp/users", tags=["mssp-users"])

_MANAGE = require_permission(Permission.MANAGE_USERS, audience="mssp")

# Every query is additionally constrained to MSSP staff rows, defence-in-depth over the session.
_MSSP_ONLY = "user_type = 'mssp' AND tenant_id IS NULL"


class MsspUserCreate(BaseModel):
    email: str
    role: str
    display_name: str | None = None

    @field_validator("email")
    @classmethod
    def _email(cls, v: str) -> str:
        return validate_email(v)


class MsspUserUpdate(BaseModel):
    role: str | None = None
    display_name: str | None = None
    active: bool | None = None


class MsspUserOut(BaseModel):
    id: str
    email: str
    display_name: str | None
    role: str
    active: bool


class MsspUserCreated(MsspUserOut):
    temporary_password: str


@mssp_users_router.get("", response_model=list[MsspUserOut], dependencies=[Depends(_MANAGE)])
async def list_mssp_users(request: Request) -> list[MsspUserOut]:
    sm = get_mssp_sessionmaker()
    async with sm() as s:
        rows = (
            await s.execute(
                text(
                    f"SELECT id::text, email, display_name, role, active "
                    f"FROM users WHERE {_MSSP_ONLY} ORDER BY created_at ASC"
                )
            )
        ).mappings().all()
    return [MsspUserOut(**dict(r)) for r in rows]


@mssp_users_router.post("", response_model=MsspUserCreated, dependencies=[Depends(_MANAGE)])
async def create_mssp_user(payload: MsspUserCreate, request: Request) -> MsspUserCreated:
    identity = current_identity(request)
    assert_role_assignable(identity, payload.role, "mssp")
    temp_password = new_temp_password()
    sm = get_mssp_sessionmaker()
    async with sm() as s:
        user = User(
            email=payload.email,
            display_name=payload.display_name or payload.email.split("@")[0],
            user_type=UserType.MSSP.value,
            role=payload.role,
            tenant_id=None,
            active=True,
        )
        s.add(user)
        try:
            await s.flush()
        except IntegrityError as exc:
            await s.rollback()
            raise HTTPException(409, "a user with that email already exists") from exc
        s.add(
            PasswordCredential(
                user_id=user.id, password_hash=hash_password(temp_password), must_change=True
            )
        )
        await log_audit(
            s,
            action=AuditAction.USER_CREATE,
            actor_principal=identity.role,
            actor_id=str(identity.user_id),
            resource_type="user",
            resource_id=str(user.id),
            after={"email": user.email, "role": user.role},
            notes="mssp staff user creation",
        )
        await s.commit()
        return MsspUserCreated(
            id=str(user.id),
            email=user.email,
            display_name=user.display_name,
            role=user.role,
            active=user.active,
            temporary_password=temp_password,
        )


async def _load_mssp_target(s: AsyncSession, user_id: UUID) -> dict[str, Any]:
    # FOR UPDATE: hold the target row for the transaction so read + guard + write are consistent.
    row = (
        await s.execute(
            text(
                f"SELECT role, active, email, display_name FROM users "
                f"WHERE id = :id AND {_MSSP_ONLY} FOR UPDATE"
            ),
            {"id": str(user_id)},
        )
    ).mappings().first()
    if row is None:
        raise HTTPException(404, "user not found")
    return dict(row)


@mssp_users_router.patch(
    "/{user_id}", response_model=MsspUserOut, dependencies=[Depends(_MANAGE)]
)
async def update_mssp_user(
    user_id: UUID, payload: MsspUserUpdate, request: Request
) -> MsspUserOut:
    identity = current_identity(request)
    if identity.user_id == user_id:
        raise HTTPException(400, "you cannot modify your own account")
    if payload.role is None and payload.display_name is None and payload.active is None:
        raise HTTPException(400, "nothing to update")
    if payload.role is not None:
        assert_role_assignable(identity, payload.role, "mssp")

    sm = get_mssp_sessionmaker()
    async with sm() as s:
        target = await _load_mssp_target(s, user_id)
        # An existing platform_admin may only be mutated by a platform_admin.
        assert_target_not_protected(identity, target["role"])
        old_role, old_active = target["role"], target["active"]
        new_role = payload.role if payload.role is not None else old_role
        new_active = payload.active if payload.active is not None else old_active

        await guard_admin_floor(
            s,
            audience="mssp",
            tenant_id=None,
            target_id=user_id,
            final_role=new_role,
            final_active=new_active,
        )

        # Write only the fields the caller supplied (a display_name-only patch must not clobber a
        # concurrent role/active change).
        sets: list[str] = []
        params: dict[str, Any] = {"id": str(user_id)}
        if payload.role is not None:
            sets.append("role = :role")
            params["role"] = payload.role
        if payload.active is not None:
            sets.append("active = :active")
            params["active"] = payload.active
        if payload.display_name is not None:
            sets.append("display_name = :dn")
            params["dn"] = payload.display_name
        if sets:
            await s.execute(
                text(f"UPDATE users SET {', '.join(sets)} WHERE id = :id AND {_MSSP_ONLY}"), params
            )
        role_changed = payload.role is not None and new_role != old_role
        deactivated = new_active is False and old_active is True
        await revoke_sessions_if_needed(
            s, user_id=user_id, role_changed=role_changed, deactivated=deactivated
        )
        await log_audit(
            s,
            action=AuditAction.USER_UPDATE,
            actor_principal=identity.role,
            actor_id=str(identity.user_id),
            resource_type="user",
            resource_id=str(user_id),
            before={"role": old_role, "active": old_active},
            after={"role": new_role, "active": new_active},
        )
        await s.commit()
        return MsspUserOut(
            id=str(user_id),
            email=target["email"],
            display_name=params.get("dn", target["display_name"]),
            role=new_role,
            active=new_active,
        )


class DeactivateResult(BaseModel):
    deactivated: str


@mssp_users_router.post(
    "/{user_id}/deactivate", response_model=DeactivateResult, dependencies=[Depends(_MANAGE)]
)
async def deactivate_mssp_user(user_id: UUID, request: Request) -> DeactivateResult:
    identity = current_identity(request)
    if identity.user_id == user_id:
        raise HTTPException(400, "you cannot deactivate your own account")
    sm = get_mssp_sessionmaker()
    async with sm() as s:
        target = await _load_mssp_target(s, user_id)
        assert_target_not_protected(identity, target["role"])
        await guard_admin_floor(
            s,
            audience="mssp",
            tenant_id=None,
            target_id=user_id,
            final_role=target["role"],
            final_active=False,
        )
        await s.execute(
            text(f"UPDATE users SET active = false WHERE id = :id AND {_MSSP_ONLY}"),
            {"id": str(user_id)},
        )
        await revoke_sessions_if_needed(s, user_id=user_id, role_changed=False, deactivated=True)
        await log_audit(
            s,
            action=AuditAction.USER_DELETE,
            actor_principal=identity.role,
            actor_id=str(identity.user_id),
            resource_type="user",
            resource_id=str(user_id),
            notes="mssp staff deactivation",
        )
        await s.commit()
    return DeactivateResult(deactivated=str(user_id))


__all__ = ["mssp_users_router"]
