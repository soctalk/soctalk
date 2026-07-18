"""Shared guards for user administration (tenant self-service and MSSP-side).

These enforce the invariants Codex flagged for the user CRUD, in one place so the tenant and MSSP
endpoints cannot drift:

- role assignability per audience (no cross-audience role; only a platform_admin may mint or touch a
  platform_admin);
- protection of existing platform_admin rows from mutation by a non-platform_admin;
- a race-safe "admin floor" so a change can never remove the last active admin (or the last active
  platform_admin, when one exists);
- session revocation after a demotion or deactivation.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any
from uuid import UUID

from fastapi import HTTPException
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from soctalk.core.auth.passwords import generate_admin_reset_password
from soctalk.core.auth.sessions import revoke_all_user_sessions
from soctalk.core.tenancy.models import Role

if TYPE_CHECKING:
    from soctalk.core.tenancy.auth import UserIdentity

# Roles a caller may assign, by audience. platform_admin is in the MSSP set but is additionally
# gated (see ``assert_role_assignable``): only a platform_admin may assign it.
TENANT_ASSIGNABLE_ROLES = frozenset(
    {
        Role.CUSTOMER_VIEWER.value,
        Role.TENANT_ANALYST.value,
        Role.TENANT_MANAGER.value,
        Role.TENANT_ADMIN.value,
    }
)
MSSP_ASSIGNABLE_ROLES = frozenset(
    {
        Role.ANALYST.value,
        Role.MSSP_MANAGER.value,
        Role.MSSP_ADMIN.value,
        Role.PLATFORM_ADMIN.value,
    }
)

# The roles that count toward "an admin can still administer the install/tenant".
_MSSP_ADMIN_ROLES = (Role.PLATFORM_ADMIN.value, Role.MSSP_ADMIN.value)
_TENANT_ADMIN_ROLES = (Role.TENANT_ADMIN.value,)


def new_temp_password() -> str:
    """A one-time temporary password (CSPRNG, 24 bytes). Caller hashes it and returns it once."""
    return generate_admin_reset_password()


def validate_email(v: str) -> str:
    """Normalise and shape-check an email login identifier (no deliverability check)."""
    v = v.strip().lower()
    if any(c.isspace() or ord(c) < 0x20 for c in v):
        raise ValueError("invalid email address")
    local, sep, domain = v.partition("@")
    dotted = "." in domain and not domain.startswith(".") and not domain.endswith(".")
    if not sep or not local or not dotted or "@" in domain:
        raise ValueError("invalid email address")
    return v


def _is_platform_admin(identity: "UserIdentity") -> bool:
    return getattr(identity, "role", None) == Role.PLATFORM_ADMIN.value


def assert_role_assignable(identity: "UserIdentity", new_role: str, audience: str) -> None:
    """The role must be assignable in this audience, and platform_admin only by a platform_admin."""
    allowed = MSSP_ASSIGNABLE_ROLES if audience == "mssp" else TENANT_ASSIGNABLE_ROLES
    if new_role not in allowed:
        raise HTTPException(
            422,
            f"role must be one of {sorted(allowed)} for this endpoint",
        )
    if new_role == Role.PLATFORM_ADMIN.value and not _is_platform_admin(identity):
        raise HTTPException(403, "only a platform_admin may assign the platform_admin role")


def assert_target_not_protected(identity: "UserIdentity", target_current_role: str) -> None:
    """An existing platform_admin may only be mutated (role change, deactivate, reset) by a
    platform_admin. Reactivating or resetting one is effectively restoring superuser power."""
    if target_current_role == Role.PLATFORM_ADMIN.value and not _is_platform_admin(identity):
        raise HTTPException(403, "only a platform_admin may modify a platform_admin account")


async def guard_admin_floor(
    db: AsyncSession,
    *,
    audience: str,
    tenant_id: UUID | None,
    target_id: UUID,
    final_role: str,
    final_active: bool,
) -> None:
    """Block a change that would remove the last active admin. Locks the candidate admin rows
    ``FOR UPDATE`` inside the caller's transaction so concurrent demotes/deactivations serialise and
    cannot both pass the guard. ``final_role`` / ``final_active`` are the target's state AFTER the
    pending change, so combined role+active patches are evaluated by their end state."""
    if audience == "mssp":
        admin_roles: tuple[str, ...] = _MSSP_ADMIN_ROLES
        where = "user_type = 'mssp' AND tenant_id IS NULL"
        params: dict[str, Any] = {}
    else:
        admin_roles = _TENANT_ADMIN_ROLES
        where = "user_type = 'tenant' AND tenant_id = :tid"
        params = {"tid": str(tenant_id)}

    rows = (
        await db.execute(
            text(
                f"SELECT id::text AS id, role FROM users "
                f"WHERE active AND role = ANY(:roles) AND {where} FOR UPDATE"
            ),
            {"roles": list(admin_roles), **params},
        )
    ).mappings().all()
    current = {r["id"]: r["role"] for r in rows}

    post = dict(current)
    tid = str(target_id)
    if final_active and final_role in admin_roles:
        post[tid] = final_role
    else:
        post.pop(tid, None)

    # Only block if THIS change drops a non-empty admin set to empty. If the target is not a
    # counted admin, or there were no admins to begin with, the floor is untouched.
    if current and not post:
        raise HTTPException(409, "cannot remove the last active administrator")

    if audience == "mssp":
        had_platform = any(r == Role.PLATFORM_ADMIN.value for r in current.values())
        has_platform = any(r == Role.PLATFORM_ADMIN.value for r in post.values())
        if had_platform and not has_platform:
            raise HTTPException(409, "cannot remove the last active platform_admin")


async def revoke_sessions_if_needed(
    db: AsyncSession, *, user_id: UUID, role_changed: bool, deactivated: bool
) -> None:
    """After a demotion or a deactivation, end the target's live sessions. Deactivation must
    (``active`` is enforced in middleware, but revoking closes the window now); a role change
    is reloaded from the row each request under internal auth, but revoke anyway so proxy tokens
    do not keep a stale role until expiry."""
    if role_changed or deactivated:
        await revoke_all_user_sessions(db, user_id=user_id)


__all__ = [
    "MSSP_ASSIGNABLE_ROLES",
    "TENANT_ASSIGNABLE_ROLES",
    "assert_role_assignable",
    "assert_target_not_protected",
    "guard_admin_floor",
    "new_temp_password",
    "revoke_sessions_if_needed",
    "validate_email",
]
