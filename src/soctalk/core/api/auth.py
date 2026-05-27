"""Internal authentication endpoints.

Only mounted when ``SOCTALK_AUTH_MODE=internal`` (see app factory). In
``proxy`` mode these paths 404 because the router is not registered.
"""

from __future__ import annotations

from uuid import UUID

import structlog
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from soctalk.core.auth.rate_limit import default_limiter
from soctalk.core.auth.service import (
    AccountLocked,
    InvalidCredentials,
    PasswordPolicyError,
    admin_reset_password,
    authenticate,
    change_password,
    logout as logout_service,
)
from soctalk.core.tenancy.auth import (
    SESSION_COOKIE_NAME,
    current_identity,
)
from soctalk.core.tenancy.decorators import require_role
from soctalk.core.tenancy.models import Role, User

logger = structlog.get_logger()


auth_router = APIRouter(prefix="/api/auth", tags=["auth"])
auth_admin_router = APIRouter(prefix="/api/mssp/users", tags=["auth-admin"])


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------


class LoginRequest(BaseModel):
    email: str = Field(..., max_length=320)
    password: str = Field(..., min_length=1, max_length=4096)
    # Optional slug-driven tenant pin. Set when the login form is on a
    # ``<slug>.customer.<base>`` host so the session lands already
    # scoped to that tenant. For tenant-bound users this MUST match
    # their ``users.tenant_id`` or login fails. For mssp users it
    # populates ``sessions.current_tenant`` (audited impersonation).
    tenant_slug: str | None = Field(default=None, max_length=64)


class UserPayload(BaseModel):
    user_id: str
    email: str
    user_type: str
    role: str
    tenant_id: str | None
    current_tenant: str | None
    # Display fields for the scope-chip in the UI: when ``current_tenant``
    # is pinned, ``current_tenant_slug`` + ``current_tenant_display_name``
    # name the tenant so the chip can render "Tenant: <name>" without a
    # round-trip. Both null when scope is cross-tenant (MSSP audience).
    current_tenant_slug: str | None = None
    current_tenant_display_name: str | None = None


class LoginResponse(BaseModel):
    user: UserPayload
    must_change: bool


class PasswordChangeRequest(BaseModel):
    old_password: str = Field(..., min_length=1, max_length=4096)
    new_password: str = Field(..., min_length=1, max_length=4096)


class AdminResetResponse(BaseModel):
    user_id: str
    temporary_password: str
    must_change: bool = True


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _db(request: Request) -> AsyncSession:
    session = getattr(request.state, "db", None)
    if session is None:
        raise HTTPException(500, "db session not attached to request")
    return session


def _client_ip(request: Request) -> str | None:
    return request.client.host if request.client else None


def _user_agent(request: Request) -> str | None:
    return request.headers.get("user-agent")


async def _resolve_tenant_label(
    db: AsyncSession, tenant_id: UUID | str | None
) -> tuple[str | None, str | None]:
    """Look up the slug + display_name for a tenant id (or None,None).

    Used to populate the scope-chip fields on UserPayload — keeps the
    UI a single round-trip on /auth/me + /assume-tenant.
    """
    if tenant_id is None:
        return None, None
    from sqlalchemy import select as _select
    from soctalk.core.tenancy.models import Tenant as _Tenant

    tid = tenant_id if isinstance(tenant_id, UUID) else UUID(str(tenant_id))
    row = (
        await db.execute(_select(_Tenant.slug, _Tenant.display_name).where(_Tenant.id == tid))
    ).first()
    if row is None:
        return None, None
    return row[0], row[1]


def _cookie_secure_default() -> bool:
    """Default Secure flag. Production HTTPS keeps it True; dev/lab
    installs over plain HTTP set ``SOCTALK_AUTH_COOKIE_SECURE=0`` so the
    browser actually returns the cookie on subsequent requests."""
    import os

    return os.getenv("SOCTALK_AUTH_COOKIE_SECURE", "1").strip().lower() not in {"0", "false", "no"}


def _set_session_cookie(response: Response, session_id: UUID) -> None:
    from soctalk.core.auth.sessions import ABSOLUTE_TTL

    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=str(session_id),
        max_age=int(ABSOLUTE_TTL.total_seconds()),
        httponly=True,
        secure=_cookie_secure_default(),
        samesite="lax",
        path="/",
    )


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@auth_router.post("/login", response_model=LoginResponse)
async def login(
    payload: LoginRequest, request: Request, response: Response
) -> LoginResponse:
    ip = _client_ip(request)
    # Rate-limit by IP + email.
    limiter = default_limiter()
    rl_key = f"{ip or 'unknown'}:{payload.email.lower()}"
    if not limiter.hit(rl_key):
        raise HTTPException(
            status_code=429, detail="Too many attempts. Try again later."
        )

    db = _db(request)
    try:
        result = await authenticate(
            db,
            email=payload.email,
            password=payload.password,
            ip=ip,
            user_agent=_user_agent(request),
        )
    except AccountLocked as exc:
        # Reveal the lockout time so the UI can render a helpful message.
        raise HTTPException(
            status_code=423,
            detail={
                "reason": "locked",
                "locked_until": exc.locked_until.isoformat(),
            },
        )
    except InvalidCredentials:
        # Generic error — never reveal which side was wrong.
        raise HTTPException(status_code=401, detail="Invalid credentials.")

    user = result.user

    # Slug-driven tenant pin. The frontend sends ``tenant_slug`` when
    # the login page is loaded under ``<slug>.customer.<base>`` so the
    # session lands already scoped to that tenant.
    if payload.tenant_slug:
        from sqlalchemy import select as _select

        from soctalk.core.tenancy.models import Tenant as _Tenant

        slug_row = (
            await db.execute(
                _select(_Tenant.id).where(_Tenant.slug == payload.tenant_slug)
            )
        ).scalar_one_or_none()
        if slug_row is None:
            raise HTTPException(404, "tenant slug not found")
        if user.user_type == "tenant":
            # Tenant users must match the URL slug — otherwise the
            # session would float between tenants on the same browser.
            if user.tenant_id != slug_row:
                raise HTTPException(403, "tenant slug does not match user")
        # MSSP users land scoped to the URL's tenant (audited
        # impersonation, same row mssp_admin would set via the
        # tenant switcher post-login).
        result.session.tenant_context = slug_row
        await db.flush()

    # Commit before returning so the session row is durable by the time
    # the client receives the cookie. The DB middleware commits after
    # the response is sent, which races with the client's immediate
    # follow-up request: the next call's middleware looks up the session
    # by id, finds nothing yet, and evicts the freshly-minted cookie.
    await db.commit()

    _set_session_cookie(response, result.session.id)
    limiter.reset(rl_key)
    cur_slug, cur_name = await _resolve_tenant_label(db, result.session.tenant_context)
    return LoginResponse(
        user=UserPayload(
            user_id=str(user.id),
            email=user.email,
            user_type=user.user_type,
            role=user.role,
            tenant_id=str(user.tenant_id) if user.tenant_id else None,
            current_tenant=(
                str(result.session.tenant_context)
                if result.session.tenant_context
                else None
            ),
            current_tenant_slug=cur_slug,
            current_tenant_display_name=cur_name,
        ),
        must_change=result.must_change,
    )


@auth_router.post("/logout")
async def logout(request: Request, response: Response) -> dict[str, bool]:
    session_id_raw = getattr(request.state, "session_id", None)
    if session_id_raw:
        identity = getattr(request.state, "user_identity", None) or {}
        db = _db(request)
        # Audit row needs to land within the request's RLS context. For
        # an MSSP user with a tenant pin (``current_tenant``), the
        # session middleware already set ``app.current_tenant_id`` to
        # that tenant, and the audit_log policy rejects null-tenant
        # writes while a tenant context is set. Prefer current_tenant
        # → tenant_id → None so the audit insert always carries a
        # value compatible with the active context.
        ct = identity.get("current_tenant") or identity.get("tenant_id")
        await logout_service(
            db,
            session_id=UUID(session_id_raw),
            user_id=UUID(identity["user_id"]),
            tenant_id=UUID(ct) if ct else None,
        )
    # ``delete_cookie`` must match every attribute used by
    # ``_set_session_cookie`` (path / secure / samesite / httponly)
    # or some browsers — Safari and recent Chrome with strict
    # SameSite/Secure matching — treat the Set-Cookie line as a
    # *new* cookie and the original sticks around. Symptom: the
    # next ``GET /api/auth/me`` returns the still-logged-in user,
    # the login page sees ``session.user`` populated and
    # ``goto('/')`` bounces the user straight back to the
    # dashboard. Repro requires a real browser; headless Chromium
    # in Playwright is lenient about this.
    response.delete_cookie(
        SESSION_COOKIE_NAME,
        path="/",
        secure=_cookie_secure_default(),
        httponly=True,
        samesite="lax",
    )
    return {"ok": True}


@auth_router.get("/me", response_model=UserPayload)
async def me(request: Request) -> UserPayload:
    identity = getattr(request.state, "user_identity", None)
    if identity is None:
        raise HTTPException(status_code=401, detail="Not authenticated.")
    db = _db(request)
    cur_slug, cur_name = await _resolve_tenant_label(db, identity.get("current_tenant"))
    return UserPayload(
        **identity,
        current_tenant_slug=cur_slug,
        current_tenant_display_name=cur_name,
    )


class AssumeTenantRequest(BaseModel):
    slug: str | None = None
    tenant_id: str | None = None


@auth_router.post("/assume-tenant", response_model=UserPayload)
async def assume_tenant(
    payload: AssumeTenantRequest, request: Request
) -> UserPayload:
    """MSSP impersonation: pin ``sessions.current_tenant`` to a slug or id.

    Tenant-bound users cannot call this; they're already scoped. MSSP
    users use this to switch which tenant they're viewing without
    re-logging-in. ``slug=null + tenant_id=null`` clears the pin and
    returns to cross-tenant view.
    """
    identity = getattr(request.state, "user_identity", None)
    if identity is None:
        raise HTTPException(401, "Not authenticated.")
    if identity.get("user_type") != "mssp":
        raise HTTPException(403, "tenant users cannot assume tenants")

    db = _db(request)
    target_tid: UUID | None = None
    if payload.slug:
        from sqlalchemy import select as _select

        from soctalk.core.tenancy.models import Tenant as _Tenant

        target_tid = (
            await db.execute(
                _select(_Tenant.id).where(_Tenant.slug == payload.slug)
            )
        ).scalar_one_or_none()
        if target_tid is None:
            raise HTTPException(404, "slug not found")
    elif payload.tenant_id:
        try:
            target_tid = UUID(payload.tenant_id)
        except ValueError:
            raise HTTPException(400, "invalid tenant_id")

    session_id_raw = getattr(request.state, "session_id", None)
    if session_id_raw is None:
        raise HTTPException(500, "session not attached")
    from soctalk.core.auth.models import Session as _Session
    from sqlalchemy import select as _select2

    session_row = (
        await db.execute(
            _select2(_Session).where(_Session.id == UUID(session_id_raw))
        )
    ).scalar_one_or_none()
    if session_row is None:
        raise HTTPException(401, "session not found")
    session_row.tenant_context = target_tid
    await db.flush()

    cur_slug, cur_name = await _resolve_tenant_label(db, target_tid)
    return UserPayload(
        user_id=identity["user_id"],
        email=identity["email"],
        user_type=identity["user_type"],
        role=identity["role"],
        tenant_id=identity.get("tenant_id"),
        current_tenant=str(target_tid) if target_tid else None,
        current_tenant_slug=cur_slug,
        current_tenant_display_name=cur_name,
    )


@auth_router.post("/password/change")
async def password_change(
    payload: PasswordChangeRequest, request: Request
) -> dict[str, bool]:
    identity = getattr(request.state, "user_identity", None)
    if identity is None:
        raise HTTPException(status_code=401, detail="Not authenticated.")
    session_id_raw = getattr(request.state, "session_id", None)
    if not session_id_raw:
        raise HTTPException(status_code=401, detail="No active session.")

    db = _db(request)
    try:
        await change_password(
            db,
            user_id=UUID(identity["user_id"]),
            current_session_id=UUID(session_id_raw),
            old_password=payload.old_password,
            new_password=payload.new_password,
        )
    except InvalidCredentials:
        raise HTTPException(
            status_code=400, detail="Current password is incorrect."
        )
    except PasswordPolicyError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return {"ok": True}


# ---------------------------------------------------------------------------
# Admin reset
# ---------------------------------------------------------------------------


@auth_admin_router.post(
    "/{user_id}/password/reset",
    response_model=AdminResetResponse,
    dependencies=[
        Depends(require_role(Role.PLATFORM_ADMIN, Role.MSSP_ADMIN))
    ],
)
async def admin_reset(
    user_id: UUID, request: Request
) -> AdminResetResponse:
    identity = current_identity(request)
    db = _db(request)

    # Load the acting user row to pass into the service.
    from sqlalchemy import select

    actor = (
        await db.execute(select(User).where(User.id == identity.user_id))
    ).scalar_one_or_none()
    if actor is None:
        raise HTTPException(500, "acting user not resolvable")

    new_password = await admin_reset_password(
        db, actor_user=actor, target_user_id=user_id
    )
    return AdminResetResponse(
        user_id=str(user_id), temporary_password=new_password, must_change=True
    )
