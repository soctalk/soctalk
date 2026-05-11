"""Decorators enforcing tenant context and role checks.

``docs/multi-tenant/security-model.md`` §§1.2, 5.

Three decorators:

- ``@tenant_scoped_worker``: worker entrypoint MUST carry ``tenant_id`` in its
  payload and set DB session var before any access. Missing context raises
  :class:`~soctalk.core.tenancy.context.MissingTenantContext`.
- ``@require_role``: endpoint guard: reject if authenticated user's role is
  not in the allowed set (MSSP-side roles).
- ``@require_tenant_role``: endpoint guard for ``/api/tenant/*``: require
  ``customer_viewer`` role AND a tenant binding.
"""

from __future__ import annotations

import functools
import inspect
from collections.abc import Callable, Iterable
from typing import Any

import structlog
from fastapi import HTTPException, Request

from soctalk.core.tenancy.context import (
    MissingTenantContext,
    TenantContext,
    set_current_tenant,
)
from soctalk.core.tenancy.models import Role, UserType

logger = structlog.get_logger()


# ----------------------------------------------------------------------------
# Worker decorator
# ----------------------------------------------------------------------------


def tenant_scoped_worker(func: Callable[..., Any]) -> Callable[..., Any]:
    """Decorate a worker entrypoint so it runs inside a tenant context.

    The decorated function must accept as its first positional argument either:

    - a dict containing ``tenant_id`` (LangGraph-style state), OR
    - a tuple / dataclass exposing ``tenant_id``.

    If the function also declares ``db_session`` keyword parameter, the
    decorator opens a :class:`TenantContext` on it; otherwise it only sets the
    in-process ContextVar. Either way, a missing ``tenant_id`` raises
    :class:`MissingTenantContext`.
    """

    is_coro = inspect.iscoroutinefunction(func)

    def _extract_tenant_id(state: Any) -> Any:
        if isinstance(state, dict):
            return state.get("tenant_id") or state.get("tenantId")
        return getattr(state, "tenant_id", None)

    @functools.wraps(func)
    async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
        if not args:
            raise MissingTenantContext(
                f"{func.__name__}: first arg must carry tenant_id (got no args)"
            )
        state = args[0]
        tenant_id = _extract_tenant_id(state)
        if tenant_id is None:
            raise MissingTenantContext(
                f"{func.__name__}: tenant_id not found in state; "
                "every @tenant_scoped_worker call must carry one"
            )
        token = set_current_tenant(tenant_id)
        db_session = kwargs.get("db_session")
        try:
            if db_session is not None:
                async with TenantContext(db_session, tenant_id):
                    return await func(*args, **kwargs)
            return await func(*args, **kwargs)
        finally:
            from soctalk.core.tenancy.context import _current_tenant_id  # noqa

            _current_tenant_id.reset(token)

    @functools.wraps(func)
    def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
        if not args:
            raise MissingTenantContext(
                f"{func.__name__}: first arg must carry tenant_id (got no args)"
            )
        state = args[0]
        tenant_id = _extract_tenant_id(state)
        if tenant_id is None:
            raise MissingTenantContext(
                f"{func.__name__}: tenant_id not found in state"
            )
        token = set_current_tenant(tenant_id)
        try:
            return func(*args, **kwargs)
        finally:
            from soctalk.core.tenancy.context import _current_tenant_id  # noqa

            _current_tenant_id.reset(token)

    return async_wrapper if is_coro else sync_wrapper


# ----------------------------------------------------------------------------
# Role-based endpoint guards
# ----------------------------------------------------------------------------


MSSP_ROLES = frozenset(
    {Role.PLATFORM_ADMIN.value, Role.MSSP_ADMIN.value, Role.ANALYST.value}
)


def _resolve_user_from_request(request: Request) -> dict[str, Any] | None:
    """Pull the authenticated identity from ``request.state``.

    The ingress-handoff middleware (see ``soctalk.core.tenancy.auth``)
    attaches ``request.state.user_identity`` as a dict with keys
    ``user_id``, ``user_type``, ``role``, ``tenant_id``, ``email``.
    """
    return getattr(request.state, "user_identity", None)


def require_role(*allowed: str | Role) -> Callable[..., Callable[..., Any]]:
    """FastAPI dependency factory that rejects calls lacking the role(s).

    Allowed values are role strings or :class:`Role` members. Example::

        @router.post("/api/mssp/tenants",
                     dependencies=[Depends(require_role(Role.MSSP_ADMIN, Role.PLATFORM_ADMIN))])
        async def create_tenant(...):
            ...
    """

    allowed_values = frozenset(
        r.value if isinstance(r, Role) else str(r) for r in allowed
    )

    async def _checker(request: Request) -> None:
        identity = _resolve_user_from_request(request)
        if identity is None:
            raise HTTPException(status_code=401, detail="authentication required")
        role = identity.get("role")
        if role not in allowed_values:
            raise HTTPException(
                status_code=403,
                detail=f"role '{role}' not permitted here",
            )

    return _checker


def require_tenant_role(*allowed: str | Role) -> Callable[..., Callable[..., Any]]:
    """Guard for ``/api/tenant/*`` endpoints.

    Requires user_type=tenant, role in allowed set, and a tenant_id claim.
    Defaults to ``customer_viewer`` if no roles passed.
    """

    # Default allows any tenant-scoped principal (tenant_admin or
    # customer_viewer). Callers can pin a tighter set when needed.
    allowed_values = (
        frozenset(r.value if isinstance(r, Role) else str(r) for r in allowed)
        if allowed
        else frozenset({Role.TENANT_ADMIN.value, Role.CUSTOMER_VIEWER.value})
    )

    async def _checker(request: Request) -> None:
        identity = _resolve_user_from_request(request)
        if identity is None:
            raise HTTPException(status_code=401, detail="authentication required")
        if identity.get("user_type") != UserType.TENANT.value:
            raise HTTPException(
                status_code=403,
                detail="tenant-scoped endpoint; MSSP-side user denied",
            )
        role = identity.get("role")
        if role not in allowed_values:
            raise HTTPException(
                status_code=403,
                detail=f"tenant role '{role}' not permitted here",
            )
        if not identity.get("tenant_id"):
            raise HTTPException(
                status_code=400,
                detail="tenant_id claim missing from token",
            )

    return _checker


def allowed_mssp_roles() -> Iterable[str]:
    """Convenience for tests / introspection."""
    return MSSP_ROLES


__all__ = [
    "MSSP_ROLES",
    "allowed_mssp_roles",
    "require_role",
    "require_tenant_role",
    "tenant_scoped_worker",
]
