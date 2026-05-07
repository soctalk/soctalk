"""Tenant context primitives.

``docs/v1/P0-1-security-model.md`` §6.1–6.4 (token claims)
and ``docs/v1/P0-4-postgres-rls.md`` §4 (session variables).

Two context flavors:

1. :class:`TenantContext`: tenant-scoped operations. Sets
   ``app.current_tenant_id`` on the current transaction; RLS enforces scope.
2. :class:`SystemContext`: explicit cross-tenant ops. Connects as the
   ``soctalk_mssp`` Postgres role (BYPASSRLS). Entry emits an audit row.

Worker jobs use :func:`tenant_scoped_worker` decorator (see
:mod:`soctalk.core.tenancy.decorators`) which wraps a call in a
:class:`TenantContext`.
"""

from __future__ import annotations

import contextlib
import contextvars
from collections.abc import AsyncIterator
from dataclasses import dataclass
from typing import TYPE_CHECKING
from uuid import UUID

import structlog
from sqlalchemy import text

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

logger = structlog.get_logger()


# ----------------------------------------------------------------------------
# Exceptions
# ----------------------------------------------------------------------------


class MissingTenantContext(RuntimeError):
    """Raised when tenant-scoped code runs without a set ``current_tenant_id``.

    The defensive default for missing context is zero rows (RLS returns nothing
    when ``current_setting('app.current_tenant_id', true)`` is NULL), but we
    raise explicitly at worker entry to catch the class of bugs where a
    background job forgot to set the context.
    """


class SystemContextNotAllowed(RuntimeError):
    """Raised when ``system_context`` is entered from a disallowed code path.

    ``system_context`` is audited and restricted; direct callers from general
    request handlers should route through an MSSP-side endpoint that uses it
    explicitly.
    """


# ----------------------------------------------------------------------------
# ContextVar for in-process propagation (workers, nested calls)
# ----------------------------------------------------------------------------


_current_tenant_id: contextvars.ContextVar[UUID | None] = contextvars.ContextVar(
    "soctalk_current_tenant_id",
    default=None,
)


def set_current_tenant(tenant_id: UUID | None) -> contextvars.Token:
    """Set the in-process tenant context. Returns a token for restoration."""
    return _current_tenant_id.set(tenant_id)


def get_current_tenant() -> UUID | None:
    """Return the currently-set tenant id, or None."""
    return _current_tenant_id.get()


async def set_request_db_context(
    session,  # AsyncSession (runtime)
    *,
    tenant_id: UUID | None,
    audience: str,
    user_role: str | None = None,
) -> None:
    """Set ``app.current_tenant_id`` / ``current_audience`` / ``current_user_role``
    on the request's DB session so RLS policies can see them.

    Values persist for the lifetime of the transaction. Called from the
    identity middleware once the user has been resolved.
    """

    await session.execute(
        text("SELECT set_config('app.current_tenant_id', :tid, true)"),
        {"tid": str(tenant_id) if tenant_id else ""},
    )
    await session.execute(
        text("SELECT set_config('app.current_audience', :a, true)"),
        {"a": audience},
    )
    if user_role is not None:
        await session.execute(
            text("SELECT set_config('app.current_user_role', :r, true)"),
            {"r": user_role},
        )


def require_current_tenant() -> UUID:
    """Return the currently-set tenant id, raising if unset."""
    tid = _current_tenant_id.get()
    if tid is None:
        raise MissingTenantContext(
            "tenant context is required but unset; every tenant-scoped "
            "code path must set app.current_tenant_id before DB access"
        )
    return tid


# ----------------------------------------------------------------------------
# TenantContext: tenant-scoped DB access
# ----------------------------------------------------------------------------


@dataclass
class TenantContext:
    """Scopes a unit of work to a single tenant.

    Usage::

        async with TenantContext(session, tenant_id):
            result = await session.execute(select(Event))  # RLS-filtered

    Sets ``app.current_tenant_id`` on the current DB transaction via
    ``SET LOCAL``; the setting is transaction-scoped and does not pollute
    the connection pool.
    """

    session: "AsyncSession"
    tenant_id: UUID

    async def __aenter__(self) -> "TenantContext":
        self._token = set_current_tenant(self.tenant_id)
        # ``SET LOCAL`` does not accept parameter binds in PostgreSQL. Use
        # ``set_config(name, value, is_local)`` which is the parameterisable
        # equivalent (and which is safe from SQL injection because the value
        # is passed as a bind param, not string-interpolated).
        await self.session.execute(
            text("SELECT set_config('app.current_tenant_id', :tid, true)"),
            {"tid": str(self.tenant_id)},
        )
        # Backend-only callers (the adapter ingest path, the
        # provisioning worker, batch jobs) need audience='mssp' to see
        # ``mssp_only`` rows under the IR RLS policies. UI request flows
        # set audience explicitly via ``set_request_db_context`` at the
        # ingress middleware; that call wins because it runs after this
        # context manager opens. ``true`` flag makes the setting
        # transaction-scoped so it can't leak across requests.
        await self.session.execute(
            text("SELECT set_config('app.current_audience', :a, true)"),
            {"a": "mssp"},
        )
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        _current_tenant_id.reset(self._token)


@contextlib.asynccontextmanager
async def tenant_context(
    session: "AsyncSession", tenant_id: UUID
) -> AsyncIterator[TenantContext]:
    """Functional shorthand for :class:`TenantContext`."""
    async with TenantContext(session, tenant_id) as ctx:
        yield ctx


# ----------------------------------------------------------------------------
# SystemContext: cross-tenant BYPASSRLS
# ----------------------------------------------------------------------------


@dataclass
class SystemContext:
    """Cross-tenant operations via the ``soctalk_mssp`` BYPASSRLS role.

    Entry emits an audit row; ``reason`` should be a short identifier
    (e.g., "mssp.fleet.summary", "alembic.migration", "cli.bulk_ops").

    Usage::

        async with system_context(mssp_session, reason="mssp.fleet.summary"):
            # queries return all tenants' rows
            ...
    """

    mssp_session: "AsyncSession"
    reason: str
    actor_id: str | None = None

    async def __aenter__(self) -> "SystemContext":
        # We do NOT set app.current_tenant_id here; BYPASSRLS role ignores policies.
        # Emit audit row for the entry.
        from soctalk.core.tenancy.models import AuditAction, AuditLog  # local import to avoid cycles

        entry = AuditLog(
            tenant_id=None,
            actor_principal="system",
            actor_id=f"system:{self.reason}",
            action=AuditAction.SYSTEM_CONTEXT_ENTER.value,
            resource_type="system_context",
            resource_id=self.reason,
            notes=f"entered by actor={self.actor_id or 'unknown'}",
        )
        self.mssp_session.add(entry)
        await self.mssp_session.flush()
        logger.info(
            "system_context_enter",
            reason=self.reason,
            actor_id=self.actor_id,
        )
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        logger.info(
            "system_context_exit",
            reason=self.reason,
            actor_id=self.actor_id,
            error=str(exc) if exc else None,
        )


def system_context(
    mssp_session: "AsyncSession",
    *,
    reason: str,
    actor_id: str | None = None,
) -> SystemContext:
    """Open a cross-tenant operation scope.

    The caller must pass a session bound to the ``soctalk_mssp`` Postgres role
    (see ``docs/v1/P0-4-postgres-rls.md``). Typical usage from MSSP endpoints
    that need fleet-wide aggregation.
    """
    return SystemContext(mssp_session=mssp_session, reason=reason, actor_id=actor_id)


__all__ = [
    "MissingTenantContext",
    "SystemContext",
    "SystemContextNotAllowed",
    "TenantContext",
    "get_current_tenant",
    "require_current_tenant",
    "set_current_tenant",
    "system_context",
    "tenant_context",
]
