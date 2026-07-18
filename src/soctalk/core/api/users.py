"""Tenant self-service user management.

Lets a ``tenant_admin`` create, list, update, and deactivate its own org's logins. Every write is
pinned to the caller's own tenant from the token and runs inside ``tenant_context`` so RLS (WITH
CHECK on ``app.current_tenant_id``) guarantees a tenant admin can only ever touch users in its own
tenant. Cross-cutting invariants (role assignability, the admin floor, session revocation) live in
``user_admin`` and are shared with the MSSP-side endpoints.
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
    guard_admin_floor,
    new_temp_password,
    revoke_sessions_if_needed,
    validate_email,
)
from soctalk.core.auth.models import PasswordCredential
from soctalk.core.auth.passwords import hash_password
from soctalk.core.observability.audit import log_audit
from soctalk.core.tenancy.auth import current_identity
from soctalk.core.tenancy.context import tenant_context
from soctalk.core.tenancy.decorators import require_permission
from soctalk.core.tenancy.models import AuditAction, User, UserType
from soctalk.core.tenancy.permissions import Permission

tenant_users_router = APIRouter(prefix="/api/tenant", tags=["tenant-users"])

_MANAGE = require_permission(Permission.TENANT_MANAGE_USERS, audience="tenant")


def _db(request: Request) -> AsyncSession:
    sess: AsyncSession | None = getattr(request.state, "db", None)
    if sess is None:
        raise HTTPException(500, "db session not attached")
    return sess


def _caller_tenant(request: Request) -> UUID:
    tid = current_identity(request).tenant_id
    if not tid:
        raise HTTPException(400, "tenant_id missing from token")
    return tid if isinstance(tid, UUID) else UUID(str(tid))


class TenantUserCreate(BaseModel):
    email: str
    role: str
    display_name: str | None = None

    @field_validator("email")
    @classmethod
    def _email(cls, v: str) -> str:
        return validate_email(v)


class TenantUserUpdate(BaseModel):
    # Email is immutable here; it is the login identity. Change one by deactivating and recreating.
    role: str | None = None
    display_name: str | None = None
    active: bool | None = None


class TenantUserOut(BaseModel):
    id: str
    email: str
    display_name: str | None
    role: str
    active: bool


class TenantUserCreated(TenantUserOut):
    # The one-time temporary password. Surfaced ONCE at creation; the user must change it on first
    # login (must_change=True). Never stored or re-fetchable in plaintext.
    temporary_password: str


@tenant_users_router.get(
    "/users", response_model=list[TenantUserOut], dependencies=[Depends(_MANAGE)]
)
async def list_tenant_users(request: Request) -> list[TenantUserOut]:
    db = _db(request)
    tid = _caller_tenant(request)
    async with tenant_context(db, tid):
        rows = (
            await db.execute(
                text(
                    "SELECT id::text, email, display_name, role, active "
                    "FROM users WHERE user_type = 'tenant' ORDER BY created_at ASC"
                )
            )
        ).mappings().all()
    return [TenantUserOut(**dict(r)) for r in rows]


@tenant_users_router.post(
    "/users", response_model=TenantUserCreated, dependencies=[Depends(_MANAGE)]
)
async def create_tenant_user(payload: TenantUserCreate, request: Request) -> TenantUserCreated:
    identity = current_identity(request)
    assert_role_assignable(identity, payload.role, "tenant")
    db = _db(request)
    tid = _caller_tenant(request)
    temp_password = new_temp_password()
    email = payload.email

    async with tenant_context(db, tid):
        user = User(
            email=email,
            display_name=payload.display_name or email.split("@")[0],
            user_type=UserType.TENANT.value,
            role=payload.role,
            tenant_id=tid,  # pinned from the token; RLS WITH CHECK rejects any other tenant
            active=True,
        )
        db.add(user)
        try:
            await db.flush()
        except IntegrityError as exc:
            await db.rollback()
            raise HTTPException(409, "a user with that email already exists") from exc
        db.add(
            PasswordCredential(
                user_id=user.id, password_hash=hash_password(temp_password), must_change=True
            )
        )
        await db.flush()
        await log_audit(
            db,
            action=AuditAction.USER_CREATE,
            actor_principal="tenant_admin",
            actor_id=str(identity.user_id),
            tenant_id=tid,
            resource_type="user",
            resource_id=str(user.id),
            after={"email": user.email, "role": user.role},
            notes="tenant self-service user creation",
        )

    return TenantUserCreated(
        id=str(user.id),
        email=user.email,
        display_name=user.display_name,
        role=user.role,
        active=user.active,
        temporary_password=temp_password,
    )


@tenant_users_router.patch(
    "/users/{user_id}", response_model=TenantUserOut, dependencies=[Depends(_MANAGE)]
)
async def update_tenant_user(
    user_id: UUID, payload: TenantUserUpdate, request: Request
) -> TenantUserOut:
    identity = current_identity(request)
    if identity.user_id == user_id:
        raise HTTPException(400, "you cannot modify your own account")
    if payload.role is None and payload.display_name is None and payload.active is None:
        raise HTTPException(400, "nothing to update")
    if payload.role is not None:
        assert_role_assignable(identity, payload.role, "tenant")

    db = _db(request)
    tid = _caller_tenant(request)
    role_changed = False
    deactivated = False
    async with tenant_context(db, tid):
        # Lock the target row for the life of the transaction so the read, the guard, and the
        # write are consistent (no concurrent role/active change can slip between them).
        row = (
            await db.execute(
                text(
                    "SELECT role, active, email, display_name FROM users "
                    "WHERE id = :id AND user_type = 'tenant' FOR UPDATE"
                ),
                {"id": str(user_id)},
            )
        ).mappings().first()
        if row is None:
            raise HTTPException(404, "user not found")
        old_role, old_active = row["role"], row["active"]
        new_role = payload.role if payload.role is not None else old_role
        new_active = payload.active if payload.active is not None else old_active

        # If this would demote or deactivate a tenant_admin, make sure it is not the last one.
        await guard_admin_floor(
            db,
            audience="tenant",
            tenant_id=tid,
            target_id=user_id,
            final_role=new_role,
            final_active=new_active,
        )

        # Write only the fields the caller actually supplied, so a display_name-only patch never
        # clobbers a concurrent role or active change.
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
            await db.execute(text(f"UPDATE users SET {', '.join(sets)} WHERE id = :id"), params)
        role_changed = payload.role is not None and new_role != old_role
        deactivated = new_active is False and old_active is True
        await log_audit(
            db,
            action=AuditAction.USER_UPDATE,
            actor_principal="tenant_admin",
            actor_id=str(identity.user_id),
            tenant_id=tid,
            resource_type="user",
            resource_id=str(user_id),
            before={"role": old_role, "active": old_active},
            after={"role": new_role, "active": new_active},
        )
        out = TenantUserOut(
            id=str(user_id),
            email=row["email"],
            display_name=params.get("dn", row["display_name"]),
            role=new_role,
            active=new_active,
        )

    await revoke_sessions_if_needed(
        db, user_id=user_id, role_changed=role_changed, deactivated=deactivated
    )
    return out


class DeactivateResult(BaseModel):
    deactivated: str


@tenant_users_router.post(
    "/users/{user_id}/deactivate",
    response_model=DeactivateResult,
    dependencies=[Depends(_MANAGE)],
)
async def deactivate_tenant_user(user_id: UUID, request: Request) -> DeactivateResult:
    identity = current_identity(request)
    if identity.user_id == user_id:
        raise HTTPException(400, "you cannot deactivate your own account")
    db = _db(request)
    tid = _caller_tenant(request)
    async with tenant_context(db, tid):
        row = (
            await db.execute(
                text("SELECT role FROM users WHERE id = :id AND user_type = 'tenant' FOR UPDATE"),
                {"id": str(user_id)},
            )
        ).mappings().first()
        if row is None:
            raise HTTPException(404, "user not found")
        await guard_admin_floor(
            db,
            audience="tenant",
            tenant_id=tid,
            target_id=user_id,
            final_role=row["role"],
            final_active=False,
        )
        await db.execute(
            text("UPDATE users SET active = false WHERE id = :id"), {"id": str(user_id)}
        )
        await log_audit(
            db,
            action=AuditAction.USER_DELETE,
            actor_principal="tenant_admin",
            actor_id=str(identity.user_id),
            tenant_id=tid,
            resource_type="user",
            resource_id=str(user_id),
            notes="tenant self-service deactivation",
        )
    await revoke_sessions_if_needed(db, user_id=user_id, role_changed=False, deactivated=True)
    return DeactivateResult(deactivated=str(user_id))


__all__ = ["tenant_users_router"]
