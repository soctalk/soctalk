"""Tenant self-service user management.

Lets a ``tenant_admin`` provision its own org's logins — the piece that makes the tenant RBAC
real: without this, no ``tenant_analyst`` / ``tenant_manager`` / ``customer_viewer`` user can be
created (users otherwise only come from the CLI and tenant-onboarding, which mint a single
``tenant_admin``). Every write is pinned to the caller's own tenant from the token and runs inside
``tenant_context`` so RLS (WITH CHECK on ``app.current_tenant_id``) guarantees a tenant admin can
only ever create/list/deactivate users in its own tenant.
"""

from __future__ import annotations

import secrets
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, field_validator
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from soctalk.core.auth.models import PasswordCredential
from soctalk.core.auth.passwords import hash_password
from soctalk.core.tenancy.auth import current_identity
from soctalk.core.tenancy.context import tenant_context
from soctalk.core.tenancy.decorators import require_permission
from soctalk.core.tenancy.models import Role, User, UserType
from soctalk.core.tenancy.permissions import Permission

tenant_users_router = APIRouter(prefix="/api/tenant", tags=["tenant-users"])

# The tenant roles a tenant_admin may assign. MSSP roles are never assignable here (audience wall).
_ASSIGNABLE_TENANT_ROLES = frozenset(
    {
        Role.CUSTOMER_VIEWER.value,
        Role.TENANT_ANALYST.value,
        Role.TENANT_MANAGER.value,
        Role.TENANT_ADMIN.value,
    }
)

_MANAGE_USERS = require_permission(Permission.TENANT_MANAGE_USERS, audience="tenant")


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
    def _valid_email(cls, v: str) -> str:
        v = v.strip().lower()
        # Minimal shape check (no email-validator dependency): one '@', non-empty local+domain,
        # a dot in the domain. Deliverability isn't verified — this is a login identifier.
        local, sep, domain = v.partition("@")
        dotted = "." in domain and not domain.startswith(".") and not domain.endswith(".")
        if not sep or not local or not dotted:
            raise ValueError("invalid email address")
        return v


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
    "/users",
    response_model=list[TenantUserOut],
    dependencies=[Depends(_MANAGE_USERS)],
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
    "/users",
    response_model=TenantUserCreated,
    dependencies=[Depends(_MANAGE_USERS)],
)
async def create_tenant_user(payload: TenantUserCreate, request: Request) -> TenantUserCreated:
    if payload.role not in _ASSIGNABLE_TENANT_ROLES:
        raise HTTPException(
            422,
            f"role must be one of {sorted(_ASSIGNABLE_TENANT_ROLES)} "
            "(MSSP roles cannot be assigned to a tenant user)",
        )
    db = _db(request)
    tid = _caller_tenant(request)
    temp_password = secrets.token_urlsafe(12)
    email = payload.email  # already normalised (lowercased + shape-checked) by the validator

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
            # global-unique email index → a login already exists (in this or any tenant)
            raise HTTPException(409, "a user with that email already exists") from exc
        db.add(
            PasswordCredential(
                user_id=user.id,
                password_hash=hash_password(temp_password),
                must_change=True,
            )
        )
        await db.flush()

    return TenantUserCreated(
        id=str(user.id),
        email=user.email,
        display_name=user.display_name,
        role=user.role,
        active=user.active,
        temporary_password=temp_password,
    )


class DeactivateResult(BaseModel):
    deactivated: str


@tenant_users_router.post(
    "/users/{user_id}/deactivate",
    response_model=DeactivateResult,
    dependencies=[Depends(_MANAGE_USERS)],
)
async def deactivate_tenant_user(user_id: str, request: Request) -> DeactivateResult:
    identity = current_identity(request)
    if str(identity.user_id) == user_id:
        raise HTTPException(400, "you cannot deactivate your own account")
    db = _db(request)
    tid = _caller_tenant(request)
    async with tenant_context(db, tid):
        # RLS scopes the UPDATE to the caller's tenant; a foreign/absent id matches zero rows.
        res = await db.execute(
            text(
                "UPDATE users SET active = false "
                "WHERE id = :id AND user_type = 'tenant' RETURNING id"
            ),
            {"id": user_id},
        )
        if res.first() is None:
            raise HTTPException(404, "user not found")
    return DeactivateResult(deactivated=user_id)


__all__ = ["tenant_users_router"]
