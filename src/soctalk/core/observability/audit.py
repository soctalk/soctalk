"""Convenience helpers for writing AuditLog rows.

Use this module rather than constructing ``AuditLog`` rows inline in handlers: it gives a single place to enforce consistent formatting, principal encoding,
and request_id correlation.
"""

from __future__ import annotations

from typing import Any
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from soctalk.core.tenancy.models import AuditAction, AuditLog


async def log_audit(
    session: AsyncSession,
    *,
    action: str | AuditAction,
    actor_principal: str,
    actor_id: str,
    tenant_id: UUID | None = None,
    acting_as: UUID | None = None,
    resource_type: str | None = None,
    resource_id: str | None = None,
    before: dict[str, Any] | None = None,
    after: dict[str, Any] | None = None,
    request_id: str | None = None,
    notes: str | None = None,
) -> AuditLog:
    """Append an audit row and flush. Returns the row for caller convenience."""
    row = AuditLog(
        tenant_id=tenant_id,
        actor_principal=actor_principal,
        actor_id=actor_id,
        acting_as=acting_as,
        action=action.value if isinstance(action, AuditAction) else action,
        resource_type=resource_type,
        resource_id=resource_id,
        before=before,
        after=after,
        request_id=request_id,
        notes=notes,
    )
    session.add(row)
    await session.flush()
    return row


__all__ = ["log_audit"]
