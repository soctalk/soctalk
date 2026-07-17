"""Request middleware that resolves the internal session cookie to a
``UserIdentity`` and attaches it to ``request.state``.

Mirrors the contract of the V1 ``ingress_handoff_middleware`` so that
decorators, RLS context helpers, and endpoint dependencies do not care
which path authenticated the user.
"""

from __future__ import annotations

from typing import Callable
from uuid import UUID

import structlog
from fastapi import Request
from fastapi.responses import JSONResponse, Response
from sqlalchemy import select

from soctalk.core.auth.csrf import request_origin_is_trusted
from soctalk.core.auth.models import PasswordCredential
from soctalk.core.auth.sessions import resolve_session
from soctalk.core.tenancy.auth import SESSION_COOKIE_NAME, UserIdentity
from soctalk.core.tenancy.context import set_request_db_context
from soctalk.core.tenancy.models import User, UserType


# Paths reachable while ``must_change=true``. Everything else 403s so the
# SPA redirects the user to /account/password.
_MUST_CHANGE_WHITELIST: frozenset[tuple[str, str]] = frozenset(
    {
        ("GET", "/api/auth/me"),
        ("POST", "/api/auth/password/change"),
        ("POST", "/api/auth/logout"),
    }
)


def _is_must_change_whitelisted(method: str, path: str) -> bool:
    return (method.upper(), path) in _MUST_CHANGE_WHITELIST

logger = structlog.get_logger()


async def internal_session_middleware(
    request: Request, call_next: Callable
) -> Response:
    """Resolve the session cookie and stamp ``request.state.user_identity``.

    Unauthenticated requests are allowed through; role decorators enforce
    the real requirements at the handler level.
    """

    # CSRF: state-changing requests must carry a matching Origin/Referer.
    # Applied here so it fires before any handler runs.
    if not request_origin_is_trusted(request):
        return JSONResponse(
            status_code=403,
            content={"detail": "CSRF validation failed"},
        )

    raw = request.cookies.get(SESSION_COOKIE_NAME)
    if not raw:
        return await call_next(request)

    try:
        session_id = UUID(raw)
    except (ValueError, TypeError):
        logger.info("session_cookie_invalid_format")
        response = await call_next(request)
        response.delete_cookie(SESSION_COOKIE_NAME)
        return response

    db = request.state.db
    session_row = await resolve_session(db, session_id)
    if session_row is None:
        response = await call_next(request)
        response.delete_cookie(SESSION_COOKIE_NAME)
        return response

    # If the session has a tenant_context (tenant user, or MSSP user
    # impersonating), stamp RLS BEFORE the User lookup. The users
    # policy hides tenant rows when ``app.current_tenant_id`` is unset,
    # so a tenant user's User row would resolve to None on the
    # app-role session and we'd evict their cookie on every request.
    # Setting context up front lets the lookup succeed; if the lookup
    # later fails we still fall through to the cookie-evict branch.
    if session_row.tenant_context is not None:
        await set_request_db_context(
            db,
            tenant_id=session_row.tenant_context,
            audience="customer",
            user_role=None,  # role unknown until we read the User
        )

    user = (
        await db.execute(select(User).where(User.id == session_row.user_id))
    ).scalar_one_or_none()
    if user is None:
        # Stale session for a user that no longer exists.
        response = await call_next(request)
        response.delete_cookie(SESSION_COOKIE_NAME)
        return response
    if not user.active:
        # Deactivated after the session was minted. The role is reloaded from the row every
        # request, but ``active`` must be enforced here too: deactivation revokes sessions, and
        # this check closes the race where a session is created concurrently with a deactivate.
        response = await call_next(request)
        response.delete_cookie(SESSION_COOKIE_NAME)
        return response

    # For tenant users, current_tenant defaults to their home tenant.
    # For MSSP users, current_tenant is whatever was captured at login
    # (normally None; impersonation is a deferred feature).
    current_tenant = session_row.tenant_context
    if current_tenant is None and user.user_type == UserType.TENANT.value:
        current_tenant = user.tenant_id

    identity = UserIdentity(
        user_id=user.id,
        email=user.email,
        user_type=user.user_type,
        role=user.role,
        tenant_id=user.tenant_id,
        current_tenant=current_tenant,
    )
    request.state.user_identity = identity.as_dict()
    request.state.session_id = str(session_row.id)

    # Stamp RLS session vars so policies can see audience + tenant.
    audience = "customer" if user.user_type == UserType.TENANT.value else "mssp"
    await set_request_db_context(
        db,
        tenant_id=current_tenant,
        audience=audience,
        user_role=user.role,
    )

    cred = (
        await db.execute(
            select(PasswordCredential).where(
                PasswordCredential.user_id == user.id
            )
        )
    ).scalar_one_or_none()
    must_change = cred is not None and cred.must_change
    request.state.must_change = must_change

    if must_change and not _is_must_change_whitelisted(
        request.method, request.url.path
    ):
        return JSONResponse(
            status_code=403,
            content={"detail": "password_change_required"},
        )

    return await call_next(request)
