"""Shared tenant-level cost-cap accounting.

Both the worker-claim path (``worker_runs.claim_run``) and the chat
turn handler (``core/api/chat.messages_post``) need to refuse new work
once the tenant has blown through its rolling 24h spend ceiling. The
query unions two cost sources:

* ``investigation_runs`` — LLM spend incurred by the worker on the
  supervisor/verdict loop. Windowed by ``COALESCE(ended_at,
  lease_expires_at, claimed_at, started_at)`` so long-running active
  runs (whose heartbeat refreshes ``lease_expires_at``) stay in window.
* ``chat_messages`` — LLM spend incurred by the chat agent. Windowed
  by ``created_at`` (point-in-time; no lifecycle columns).

A single source of truth means a busy chat session can't blow past the
runs-worker's cap and a flood of runs can't blow past the chat
handler's cap.

Defaults pull from env so operators can tune per cluster without a
schema change.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from uuid import UUID

import structlog
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession


logger = structlog.get_logger()


def tenant_daily_token_cap() -> int:
    """Per-tenant rolling 24h token ceiling. Default 10M."""
    raw = os.getenv("SOCTALK_TENANT_DAILY_TOKEN_CAP", "")
    try:
        v = int(raw) if raw else 10_000_000
    except ValueError:
        v = 10_000_000
    return v if v > 0 else 10_000_000


def tenant_daily_dollar_cap() -> float:
    """Per-tenant rolling 24h dollar ceiling. Default $50."""
    raw = os.getenv("SOCTALK_TENANT_DAILY_DOLLAR_CAP", "")
    try:
        v = float(raw) if raw else 50.0
    except ValueError:
        v = 50.0
    return v if v > 0 else 50.0


@dataclass(frozen=True, slots=True)
class TenantDailySpend:
    tokens: int
    dollars: float

    @property
    def token_cap_hit(self) -> bool:
        return self.tokens >= tenant_daily_token_cap()

    @property
    def dollar_cap_hit(self) -> bool:
        return self.dollars >= tenant_daily_dollar_cap()

    @property
    def cap_hit(self) -> bool:
        return self.token_cap_hit or self.dollar_cap_hit


_DAILY_SPEND_SQL = """
    SELECT COALESCE(SUM(s.tokens), 0)::bigint AS tokens,
           COALESCE(SUM(s.dollars), 0)::float AS dollars
    FROM (
        SELECT tokens_used::bigint AS tokens,
               dollars_used        AS dollars
          FROM investigation_runs
         WHERE tenant_id = :t
           AND COALESCE(ended_at, lease_expires_at, claimed_at, started_at)
               >= now() - interval '24 hours'
        UNION ALL
        SELECT (COALESCE(tokens_in, 0) + COALESCE(tokens_out, 0))::bigint AS tokens,
               COALESCE(dollars, 0.0)                                     AS dollars
          FROM chat_messages
         WHERE tenant_id = :t
           AND created_at >= now() - interval '24 hours'
    ) s
"""


async def get_tenant_daily_spend(
    db: AsyncSession, tenant_id: UUID
) -> TenantDailySpend:
    """Run the unified daily-cap query against the given session.

    Caller chooses the session — usually the request-bound session that
    already has the right RLS scope. ``tenant_id`` is the data column
    filter; RLS still applies on top, so tenant-scoped sessions only
    sum their own tenant's rows even if a caller passed a different
    UUID (defence in depth).
    """
    row = (
        await db.execute(text(_DAILY_SPEND_SQL), {"t": str(tenant_id)})
    ).mappings().first()
    if row is None:
        return TenantDailySpend(tokens=0, dollars=0.0)
    return TenantDailySpend(
        tokens=int(row["tokens"] or 0),
        dollars=float(row["dollars"] or 0.0),
    )


async def assert_tenant_daily_cap_ok(
    db: AsyncSession, tenant_id: UUID, *, source: str
) -> TenantDailySpend | None:
    """Return the spend snapshot if under cap, ``None`` if over.

    Caller decides what to do on ``None`` (worker returns 200/null;
    chat returns 429). ``source`` is logged so we can tell which path
    tripped the breaker.
    """
    spend = await get_tenant_daily_spend(db, tenant_id)
    if spend.cap_hit:
        logger.warning(
            "tenant_daily_cap_hit",
            source=source,
            tenant_id=str(tenant_id),
            tokens_24h=spend.tokens,
            token_cap=tenant_daily_token_cap(),
            dollars_24h=round(spend.dollars, 4),
            dollar_cap=tenant_daily_dollar_cap(),
        )
        return None
    return spend


# ---------------------------------------------------------------------------
# MSSP-user-per-day cap (fleet-scope conversations)
# ---------------------------------------------------------------------------
#
# Fleet-scope conversations have ``chat_messages.tenant_id IS NULL`` and
# therefore fall out of the tenant cap entirely. We add a parallel cap
# bound to the MSSP user so a busy fleet session can't be a budget
# side-door. Window + units mirror the tenant cap.


def mssp_user_daily_token_cap() -> int:
    raw = os.getenv("SOCTALK_MSSP_USER_DAILY_TOKEN_CAP", "")
    try:
        v = int(raw) if raw else 10_000_000
    except ValueError:
        v = 10_000_000
    return v if v > 0 else 10_000_000


def mssp_user_daily_dollar_cap() -> float:
    raw = os.getenv("SOCTALK_MSSP_USER_DAILY_DOLLAR_CAP", "")
    try:
        v = float(raw) if raw else 50.0
    except ValueError:
        v = 50.0
    return v if v > 0 else 50.0


@dataclass(frozen=True, slots=True)
class MsspUserDailySpend:
    tokens: int
    dollars: float

    @property
    def token_cap_hit(self) -> bool:
        return self.tokens >= mssp_user_daily_token_cap()

    @property
    def dollar_cap_hit(self) -> bool:
        return self.dollars >= mssp_user_daily_dollar_cap()

    @property
    def cap_hit(self) -> bool:
        return self.token_cap_hit or self.dollar_cap_hit


_MSSP_USER_DAILY_SPEND_SQL = """
    SELECT COALESCE(SUM((COALESCE(m.tokens_in, 0)
                       + COALESCE(m.tokens_out, 0))::bigint), 0)::bigint AS tokens,
           COALESCE(SUM(COALESCE(m.dollars, 0.0))::float, 0.0)::float    AS dollars
      FROM chat_messages m
      JOIN conversations c ON c.id = m.conversation_id
     WHERE c.scope = 'mssp_fleet'
       AND c.created_by_user_id = :u
       AND m.created_at >= now() - interval '24 hours'
"""


async def get_mssp_user_daily_spend(
    db: AsyncSession, user_id: UUID
) -> MsspUserDailySpend:
    row = (
        await db.execute(
            text(_MSSP_USER_DAILY_SPEND_SQL), {"u": str(user_id)}
        )
    ).mappings().first()
    if row is None:
        return MsspUserDailySpend(tokens=0, dollars=0.0)
    return MsspUserDailySpend(
        tokens=int(row["tokens"] or 0),
        dollars=float(row["dollars"] or 0.0),
    )


async def assert_mssp_user_daily_cap_ok(
    db: AsyncSession, user_id: UUID, *, source: str
) -> MsspUserDailySpend | None:
    spend = await get_mssp_user_daily_spend(db, user_id)
    if spend.cap_hit:
        logger.warning(
            "mssp_user_daily_cap_hit",
            source=source,
            user_id=str(user_id),
            tokens_24h=spend.tokens,
            token_cap=mssp_user_daily_token_cap(),
            dollars_24h=round(spend.dollars, 4),
            dollar_cap=mssp_user_daily_dollar_cap(),
        )
        return None
    return spend
