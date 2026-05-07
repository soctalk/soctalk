"""Session CRUD helpers.

Sessions are DB-backed (table ``sessions``). The cookie carries only the
session ``id`` (UUID). Lifetime policy: 12h absolute, 30m idle (P1-1 §4).
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from soctalk.core.auth.models import Session


ABSOLUTE_TTL = timedelta(hours=12)
IDLE_TTL = timedelta(minutes=30)
# Throttle how often we write last_seen_at on read.
LAST_SEEN_REFRESH_INTERVAL = timedelta(seconds=60)


def _now() -> datetime:
    return datetime.now(timezone.utc)


async def create_session(
    db: AsyncSession,
    user_id: UUID,
    tenant_context: UUID | None,
    ip: str | None,
    user_agent: str | None,
) -> Session:
    now = _now()
    row = Session(
        id=uuid4(),
        user_id=user_id,
        tenant_context=tenant_context,
        created_at=now,
        last_seen_at=now,
        absolute_expiry=now + ABSOLUTE_TTL,
        idle_expiry=now + IDLE_TTL,
        revoked_at=None,
        ip_created=ip,
        user_agent=user_agent,
    )
    db.add(row)
    await db.flush()
    return row


async def resolve_session(db: AsyncSession, session_id: UUID) -> Session | None:
    """Return the session if it exists and is still valid. Also updates
    ``last_seen_at`` and ``idle_expiry`` on activity, throttled."""

    row = (
        await db.execute(select(Session).where(Session.id == session_id))
    ).scalar_one_or_none()
    if row is None:
        return None

    now = _now()
    if row.revoked_at is not None:
        return None
    if now >= row.absolute_expiry:
        return None
    if now >= row.idle_expiry:
        return None

    # Sliding idle expiry; write back at most every LAST_SEEN_REFRESH_INTERVAL.
    last_seen = row.last_seen_at
    if last_seen.tzinfo is None:
        last_seen = last_seen.replace(tzinfo=timezone.utc)
    if (now - last_seen) >= LAST_SEEN_REFRESH_INTERVAL:
        new_idle = now + IDLE_TTL
        await db.execute(
            update(Session)
            .where(Session.id == session_id)
            .values(last_seen_at=now, idle_expiry=new_idle)
        )
        row.last_seen_at = now
        row.idle_expiry = new_idle
    return row


async def revoke_session(db: AsyncSession, session_id: UUID) -> None:
    await db.execute(
        update(Session)
        .where(Session.id == session_id, Session.revoked_at.is_(None))
        .values(revoked_at=_now())
    )


async def revoke_all_user_sessions(
    db: AsyncSession, user_id: UUID, except_session_id: UUID | None = None
) -> int:
    """Revoke all active sessions for ``user_id``. Returns count revoked.

    If ``except_session_id`` is given, that session is preserved — used on
    password change so the user stays logged in on their current device.
    """

    stmt = (
        update(Session)
        .where(Session.user_id == user_id, Session.revoked_at.is_(None))
        .values(revoked_at=_now())
    )
    if except_session_id is not None:
        stmt = stmt.where(Session.id != except_session_id)
    result = await db.execute(stmt)
    return result.rowcount or 0
