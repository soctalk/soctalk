"""Auth business logic.

Endpoints call into this module. Keeping the flow here (rather than in
the router) means the backend tests can exercise it directly with a
session fixture, no HTTP harness required.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from uuid import UUID

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from soctalk.core.auth.models import PasswordCredential, Session
from soctalk.core.auth.passwords import (
    MIN_PASSWORD_LENGTH,
    PasswordPolicyError,
    generate_admin_reset_password,
    hash_password,
    validate_password,
    verify_password,
)
from soctalk.core.auth.sessions import (
    create_session,
    revoke_all_user_sessions,
    revoke_session,
)
from soctalk.core.observability.audit import log_audit
from soctalk.core.tenancy.models import User, UserType


LOCKOUT_THRESHOLD = 10
LOCKOUT_DURATION = timedelta(minutes=15)


class AuthError(Exception):
    """Base class for authentication errors surfaced to the client."""


class InvalidCredentials(AuthError):
    pass


class AccountLocked(AuthError):
    def __init__(self, locked_until: datetime) -> None:
        super().__init__("account temporarily locked")
        self.locked_until = locked_until


class PasswordChangeRequired(AuthError):
    """Raised by authenticate() when the credential's must_change flag is set.

    The login flow still proceeds — a session is established — but the
    caller signals must_change in the response body so the UI can route
    the user to the change-password page.
    """


@dataclass
class LoginResult:
    session: Session
    user: User
    must_change: bool


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _ensure_aware(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


async def _get_user_by_email(db: AsyncSession, email: str) -> User | None:
    """Lookup the User row at login time.

    Tenant users are hidden from the app-role session by RLS until a
    tenant context is set. At login we don't know the tenant yet — the
    user IS the source of that information — so we route the lookup
    through the MSSP DB role (same workaround as the proxy-handoff
    middleware in ``core/tenancy/auth.py:_lookup_user_for_auth``).
    Falls back to the request session if the MSSP sessionmaker isn't
    configured (test environments).
    """
    from soctalk.core.tenancy.auth import _lookup_user_for_auth

    return await _lookup_user_for_auth(email, db)


async def _get_credential(
    db: AsyncSession, user_id: UUID
) -> PasswordCredential | None:
    return (
        await db.execute(
            select(PasswordCredential).where(PasswordCredential.user_id == user_id)
        )
    ).scalar_one_or_none()


async def authenticate(
    db: AsyncSession,
    email: str,
    password: str,
    ip: str | None,
    user_agent: str | None,
) -> LoginResult:
    """Validate credentials and open a new session.

    On success, emits ``auth.login.success`` and returns a LoginResult
    with ``must_change`` set from the credential. On failure, emits
    ``auth.login.failure`` or ``auth.lockout.triggered`` and raises the
    appropriate ``AuthError`` subclass. The caller is responsible for
    setting the session cookie on the response.
    """

    user = await _get_user_by_email(db, email)
    if user is None:
        await log_audit(
            db,
            action="auth.login.failure",
            actor_principal="anonymous",
            actor_id="anonymous",
            tenant_id=None,
            notes="reason=unknown_email",
        )
        raise InvalidCredentials()

    # Tenant users were resolved through the MSSP-role bypass, but the
    # rest of this function (credential read, audit_log writes) runs on
    # the request's app-role session. Without ``app.current_tenant_id``
    # set, audit_log RLS rejects writes that carry ``tenant_id=user.
    # tenant_id`` (the model has a tenant_id-NOT-NULL CHECK on tenant
    # rows), so a bad-password attempt for a tenant user would 500
    # instead of returning 401. Stamp the context BEFORE any audit
    # write that carries the tenant_id (including the inactive-user
    # rejection below) so the whole flow stays inside policy.
    from soctalk.core.tenancy.context import set_request_db_context
    from soctalk.core.tenancy.models import UserType as _UserType

    if user.user_type == _UserType.TENANT.value and user.tenant_id is not None:
        await set_request_db_context(
            db,
            tenant_id=user.tenant_id,
            audience="customer",
            user_role=user.role,
        )

    # Deactivated users (``active=false``) must not authenticate even
    # if their password credential row still exists. The MSSP-role
    # lookup path bypasses RLS and would otherwise return rows
    # regardless of the active flag; gate them here before any
    # credential verification.
    if not user.active:
        await log_audit(
            db,
            action="auth.login.failure",
            actor_principal="user",
            actor_id=str(user.id),
            tenant_id=user.tenant_id,
            notes="reason=inactive_user",
        )
        raise InvalidCredentials()

    cred = await _get_credential(db, user.id)
    if cred is None:
        # Users authenticated via proxy handoff may not have a local
        # credential. They cannot log in here.
        await log_audit(
            db,
            action="auth.login.failure",
            actor_principal="user",
            actor_id=str(user.id),
            tenant_id=user.tenant_id,
            notes="reason=no_credential",
        )
        raise InvalidCredentials()

    now = _now()
    locked_until = _ensure_aware(cred.locked_until)
    if locked_until is not None and now < locked_until:
        await log_audit(
            db,
            action="auth.login.failure",
            actor_principal="user",
            actor_id=str(user.id),
            tenant_id=user.tenant_id,
            notes="reason=locked",
        )
        raise AccountLocked(locked_until)

    matched, maybe_new_hash = verify_password(password, cred.password_hash)
    if not matched:
        cred.consecutive_failures += 1
        if cred.consecutive_failures >= LOCKOUT_THRESHOLD:
            cred.locked_until = now + LOCKOUT_DURATION
            await log_audit(
                db,
                action="auth.lockout.triggered",
                actor_principal="system",
                actor_id="system:auth",
                tenant_id=user.tenant_id,
                notes=f"user_id={user.id} failures={cred.consecutive_failures}",
            )
        db.add(cred)
        await db.flush()
        await log_audit(
            db,
            action="auth.login.failure",
            actor_principal="user",
            actor_id=str(user.id),
            tenant_id=user.tenant_id,
            notes="reason=bad_password",
        )
        raise InvalidCredentials()

    # Success.
    if maybe_new_hash is not None:
        cred.password_hash = maybe_new_hash
    cred.consecutive_failures = 0
    cred.last_used_at = now
    cred.locked_until = None
    db.add(cred)
    await db.flush()

    tenant_context = user.tenant_id if user.user_type == UserType.TENANT.value else None
    session_row = await create_session(
        db,
        user_id=user.id,
        tenant_context=tenant_context,
        ip=ip,
        user_agent=user_agent,
    )

    await log_audit(
        db,
        action="auth.login.success",
        actor_principal="user",
        actor_id=str(user.id),
        tenant_id=user.tenant_id,
    )
    return LoginResult(session=session_row, user=user, must_change=cred.must_change)


async def change_password(
    db: AsyncSession,
    user_id: UUID,
    current_session_id: UUID,
    old_password: str,
    new_password: str,
) -> None:
    """Change the password for the authenticated user.

    On success, revokes all other sessions for the user (preserves the
    current one), clears ``must_change``, emits ``auth.password.changed``.
    Raises ``InvalidCredentials`` on wrong old password,
    ``PasswordPolicyError`` if the new password fails policy.
    """

    validate_password(new_password)

    cred = await _get_credential(db, user_id)
    if cred is None:
        raise InvalidCredentials()

    matched, _ = verify_password(old_password, cred.password_hash)
    if not matched:
        raise InvalidCredentials()

    cred.password_hash = hash_password(new_password)
    cred.must_change = False
    cred.updated_at = _now()
    cred.consecutive_failures = 0
    cred.locked_until = None
    db.add(cred)
    await db.flush()

    await revoke_all_user_sessions(
        db, user_id=user_id, except_session_id=current_session_id
    )

    user = (
        await db.execute(select(User).where(User.id == user_id))
    ).scalar_one_or_none()
    await log_audit(
        db,
        action="auth.password.changed",
        actor_principal="user",
        actor_id=str(user_id),
        tenant_id=user.tenant_id if user else None,
    )


async def admin_reset_password(
    db: AsyncSession,
    actor_user: User,
    target_user_id: UUID,
) -> str:
    """Generate a new random password for ``target_user_id`` and set
    ``must_change``. Returns the plaintext password (shown once).

    Revokes all sessions for the target user. Emits
    ``auth.password.reset.admin``.
    """

    target = (
        await db.execute(select(User).where(User.id == target_user_id))
    ).scalar_one_or_none()
    if target is None:
        raise AuthError("target user not found")

    new_plain = generate_admin_reset_password()

    cred = await _get_credential(db, target_user_id)
    if cred is None:
        cred = PasswordCredential(
            user_id=target_user_id,
            password_hash=hash_password(new_plain),
            must_change=True,
            updated_at=_now(),
            consecutive_failures=0,
            locked_until=None,
        )
        db.add(cred)
    else:
        cred.password_hash = hash_password(new_plain)
        cred.must_change = True
        cred.updated_at = _now()
        cred.consecutive_failures = 0
        cred.locked_until = None
        db.add(cred)
    await db.flush()

    await revoke_all_user_sessions(db, user_id=target_user_id)

    await log_audit(
        db,
        action="auth.password.reset.admin",
        actor_principal="user",
        actor_id=str(actor_user.id),
        tenant_id=target.tenant_id,
        resource_type="user",
        resource_id=str(target_user_id),
    )
    return new_plain


async def logout(
    db: AsyncSession, session_id: UUID, user_id: UUID, tenant_id: UUID | None
) -> None:
    await revoke_session(db, session_id)
    await log_audit(
        db,
        action="auth.logout",
        actor_principal="user",
        actor_id=str(user_id),
        tenant_id=tenant_id,
    )


# Re-export constants needed by the routes.
__all__ = [
    "AccountLocked",
    "AuthError",
    "InvalidCredentials",
    "LoginResult",
    "LOCKOUT_THRESHOLD",
    "MIN_PASSWORD_LENGTH",
    "PasswordPolicyError",
    "admin_reset_password",
    "authenticate",
    "change_password",
    "logout",
]
