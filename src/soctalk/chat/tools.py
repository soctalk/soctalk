"""Read-only DB tools exposed to the chat agent.

Every tool routes through a role-aware session — MSSP-level roles read
through BYPASSRLS so they can answer cross-tenant questions, tenant-
bound roles read through the request-bound session that the middleware
has already RLS-scoped to their home tenant.

Each tool returns a ``ToolResult`` carrying:

* ``data`` — the actual payload, structured but JSON-serialisable.
* ``truncated`` — ``True`` if the result hit the 8 KB size guard. The
  agent system prompt instructs the model to refine its query and
  re-call when ``truncated`` is set, rather than guessing the missing
  rows.

Adding a new tool: implement an ``async def fn(identity, ...)``
helper, decorate with ``@chat_tool(name, description, schema)``, and
add to ``AVAILABLE_TOOLS``. The agent loop introspects the schemas
when binding the model.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from soctalk.core.tenancy.auth import UserIdentity


MSSP_LEVEL_ROLES = frozenset({"platform_admin", "mssp_admin"})

# 8 KB serialised result ceiling. Tool results get stuffed back into
# the LLM context on the next turn, so an unbounded query that returns
# 500 rows blows the per-turn cap fast. Truncation is communicated to
# the model via the ``truncated`` flag so it can refine.
RESULT_BYTE_CAP = 8 * 1024


@dataclass(slots=True)
class ToolResult:
    """Wrapped tool result with truncation accounting."""

    data: Any
    truncated: bool = False
    hint: str | None = None  # passed back to the model on truncation

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {"data": self.data, "truncated": self.truncated}
        if self.hint:
            out["hint"] = self.hint
        return out


def _enforce_size(data: Any, hint: str | None = None) -> ToolResult:
    """Serialise ``data`` and truncate if over the byte cap.

    Truncation strategy: if ``data`` is a list, drop tail rows until
    under the cap. If still too big, return a stub with a hint. Other
    shapes (dict, scalar) get returned as-is with truncated=True if
    they exceed — the agent gets to learn the query was too broad.
    """
    raw = json.dumps(data, default=str)
    if len(raw) <= RESULT_BYTE_CAP:
        return ToolResult(data=data, truncated=False, hint=None)
    # List shrinking.
    if isinstance(data, list):
        # Binary-search the largest prefix that fits.
        lo, hi = 0, len(data)
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if len(json.dumps(data[:mid], default=str)) <= RESULT_BYTE_CAP:
                lo = mid
            else:
                hi = mid - 1
        truncated_list = data[:lo]
        return ToolResult(
            data=truncated_list,
            truncated=True,
            hint=(
                hint
                or f"truncated to {len(truncated_list)} of {len(data)} rows; "
                "refine with a narrower filter (rule_id, severity_min, hours, etc.)"
            ),
        )
    return ToolResult(
        data={"summary": "result too large", "approx_bytes": len(raw)},
        truncated=True,
        hint=hint or "result too large; ask for a narrower scope",
    )


# -----------------------------------------------------------------------------
# Role-aware session helper
# -----------------------------------------------------------------------------


async def chat_session_for(identity: UserIdentity) -> AsyncSession:
    """Open a session appropriate for the caller's role.

    MSSP-level → BYPASSRLS. Tenant-level → app session with
    ``tenant_context`` set to the user's home tenant. Caller is
    responsible for closing.

    Returns the session directly (not an async generator) so the agent
    loop can hold one open across multiple tool calls in a turn without
    re-resolving the role on each call.
    """
    from soctalk.core.tenancy.context import tenant_context
    from soctalk.core.tenancy.db import get_app_sessionmaker, get_mssp_sessionmaker

    if identity.role in MSSP_LEVEL_ROLES:
        sm = get_mssp_sessionmaker()
        return sm()
    sm = get_app_sessionmaker()
    sess = sm()
    # tenant_context is a context manager; we need the SET inside an
    # active transaction. Caller wraps `async with chat_session_for...`
    # but we yield the session and rely on the caller managing context.
    # For simplicity here we eagerly enter the tenant_context.
    await tenant_context(sess, identity.tenant_id).__aenter__()
    return sess


# -----------------------------------------------------------------------------
# Tool implementations
# -----------------------------------------------------------------------------


async def get_investigation(
    db: AsyncSession, *, investigation_id: str
) -> ToolResult:
    """Full investigation row + active pending_review + last 10 alerts + last 20 events."""
    try:
        iid = UUID(investigation_id)
    except (TypeError, ValueError):
        return _enforce_size({"error": "invalid investigation_id"})

    inv = (
        await db.execute(
            text(
                """
                SELECT id::text, tenant_id::text, short_id, title, status,
                       severity, summary, opened_at, closed_at, close_reason,
                       reopen_count, visibility
                FROM investigations
                WHERE id = :id
                """
            ),
            {"id": str(iid)},
        )
    ).mappings().first()
    if inv is None:
        return _enforce_size({"error": "investigation not found"})

    pr = (
        await db.execute(
            text(
                """
                SELECT id::text, status, title, description, max_severity,
                       ai_decision, ai_confidence, created_at, responded_at,
                       reviewer
                FROM pending_reviews
                WHERE investigation_id = :id
                ORDER BY created_at DESC
                LIMIT 1
                """
            ),
            {"id": str(iid)},
        )
    ).mappings().first()

    alerts = (
        await db.execute(
            text(
                """
                SELECT id::text, source, rule_id, severity, signature,
                       first_event_at, ai_assessment
                FROM alerts
                WHERE investigation_id = :id
                ORDER BY first_event_at DESC
                LIMIT 10
                """
            ),
            {"id": str(iid)},
        )
    ).mappings().all()

    events = (
        await db.execute(
            text(
                """
                SELECT event_type, version, timestamp, data
                FROM events
                WHERE aggregate_id = :id
                ORDER BY version DESC
                LIMIT 20
                """
            ),
            {"id": str(iid)},
        )
    ).mappings().all()

    return _enforce_size(
        {
            "investigation": dict(inv),
            "pending_review": dict(pr) if pr else None,
            "alerts": [dict(a) for a in alerts],
            "events": [dict(e) for e in events],
        }
    )


async def list_pending_reviews(
    db: AsyncSession,
    *,
    status: str = "pending",
    limit: int = 20,
) -> ToolResult:
    """List recent pending HIL reviews matching the given status."""
    limit = max(1, min(50, limit))
    rows = (
        await db.execute(
            text(
                """
                SELECT id::text, investigation_id::text, status, title,
                       max_severity, ai_decision, ai_confidence, created_at
                FROM pending_reviews
                WHERE status = :s
                ORDER BY created_at DESC
                LIMIT :n
                """
            ),
            {"s": status, "n": limit},
        )
    ).mappings().all()
    return _enforce_size([dict(r) for r in rows])


async def recent_alerts(
    db: AsyncSession,
    *,
    rule_id: str | None = None,
    severity_min: int | None = None,
    hours: int = 24,
    limit: int = 50,
) -> ToolResult:
    """Recent alerts, optionally filtered by rule and minimum severity."""
    hours = max(1, min(168, hours))
    limit = max(1, min(100, limit))
    conds = ["first_event_at >= now() - make_interval(hours => :h)"]
    params: dict[str, Any] = {"h": hours, "n": limit}
    if rule_id:
        conds.append("rule_id = :rid")
        params["rid"] = rule_id
    if severity_min is not None:
        conds.append("severity >= :sev")
        params["sev"] = int(severity_min)
    sql = (
        "SELECT id::text, source, rule_id, severity, signature, "
        "first_event_at, investigation_id::text "
        "FROM alerts WHERE " + " AND ".join(conds)
        + " ORDER BY first_event_at DESC LIMIT :n"
    )
    rows = (await db.execute(text(sql), params)).mappings().all()
    return _enforce_size([dict(r) for r in rows])


async def audit_trail(
    db: AsyncSession,
    *,
    investigation_id: str | None = None,
    event_type: str | None = None,
    hours: int = 72,
    limit: int = 100,
) -> ToolResult:
    """Recent events from the audit log."""
    hours = max(1, min(720, hours))
    limit = max(1, min(200, limit))
    conds = ["timestamp >= now() - make_interval(hours => :h)"]
    params: dict[str, Any] = {"h": hours, "n": limit}
    if investigation_id:
        conds.append("aggregate_id = :aid")
        params["aid"] = investigation_id
    if event_type:
        conds.append("event_type = :et")
        params["et"] = event_type
    sql = (
        "SELECT event_type, aggregate_id::text, version, timestamp, data "
        "FROM events WHERE " + " AND ".join(conds)
        + " ORDER BY timestamp DESC LIMIT :n"
    )
    rows = (await db.execute(text(sql), params)).mappings().all()
    return _enforce_size([dict(r) for r in rows])


async def tenant_stats(db: AsyncSession, *, days: int = 7) -> ToolResult:
    """Rolled-up tenant activity over the last ``days`` days."""
    days = max(1, min(90, days))
    row = (
        await db.execute(
            text(
                """
                SELECT
                  (SELECT COUNT(*)::int FROM alerts
                     WHERE first_event_at >= now() - make_interval(days => :d))
                                                                AS alerts,
                  (SELECT COUNT(*)::int FROM investigations
                     WHERE created_at >= now() - make_interval(days => :d))
                                                                AS investigations,
                  (SELECT COUNT(*)::int FROM pending_reviews
                     WHERE status = 'pending')                  AS pending_reviews,
                  (SELECT COUNT(*)::int FROM pending_reviews
                     WHERE created_at >= now() - make_interval(days => :d)
                       AND ai_decision = 'escalate')            AS escalated,
                  (SELECT AVG(ai_confidence)::float FROM pending_reviews
                     WHERE created_at >= now() - make_interval(days => :d)
                       AND ai_confidence IS NOT NULL)           AS avg_ai_confidence
                """
            ),
            {"d": days},
        )
    ).mappings().first() or {}
    return _enforce_size(
        {
            "window_days": days,
            "alerts": int(row.get("alerts") or 0),
            "investigations": int(row.get("investigations") or 0),
            "pending_reviews": int(row.get("pending_reviews") or 0),
            "escalated": int(row.get("escalated") or 0),
            "avg_ai_confidence": (
                float(row["avg_ai_confidence"])
                if row.get("avg_ai_confidence") is not None
                else None
            ),
        }
    )


async def search_investigations(
    db: AsyncSession, *, query: str, limit: int = 20
) -> ToolResult:
    """ILIKE search over investigation title + summary."""
    limit = max(1, min(50, limit))
    if not query or not query.strip():
        return _enforce_size({"error": "query is empty"})
    rows = (
        await db.execute(
            text(
                """
                SELECT id::text, short_id, title, status, severity, opened_at
                FROM investigations
                WHERE title ILIKE :q OR COALESCE(summary, '') ILIKE :q
                ORDER BY opened_at DESC
                LIMIT :n
                """
            ),
            {"q": f"%{query.strip()}%", "n": limit},
        )
    ).mappings().all()
    return _enforce_size([dict(r) for r in rows])


# -----------------------------------------------------------------------------
# Tool registry
# -----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ChatTool:
    """LangChain-style tool descriptor with a typed dispatcher."""

    name: str
    description: str
    schema: dict[str, Any]  # JSON Schema for arguments
    func: Callable[..., Awaitable[ToolResult]] = field(repr=False)


AVAILABLE_TOOLS: tuple[ChatTool, ...] = (
    ChatTool(
        name="get_investigation",
        description=(
            "Fetch the full row for one investigation by UUID, plus its most "
            "recent pending HIL review, last 10 alerts, and last 20 audit "
            "events. Use when the user asks about a specific case."
        ),
        schema={
            "type": "object",
            "properties": {
                "investigation_id": {
                    "type": "string",
                    "description": "UUID of the investigation",
                },
            },
            "required": ["investigation_id"],
        },
        func=get_investigation,
    ),
    ChatTool(
        name="list_pending_reviews",
        description=(
            "List HIL reviews matching a status (default 'pending'). Use when "
            "the user asks 'what's in the queue' or 'show recent reviews'."
        ),
        schema={
            "type": "object",
            "properties": {
                "status": {
                    "type": "string",
                    "enum": [
                        "pending",
                        "approved",
                        "rejected",
                        "info_requested",
                        "expired",
                    ],
                    "default": "pending",
                },
                "limit": {"type": "integer", "minimum": 1, "maximum": 50},
            },
        },
        func=list_pending_reviews,
    ),
    ChatTool(
        name="recent_alerts",
        description=(
            "Recent Wazuh alerts, optionally filtered by rule_id and minimum "
            "severity. ``hours`` defaults to 24."
        ),
        schema={
            "type": "object",
            "properties": {
                "rule_id": {"type": "string"},
                "severity_min": {"type": "integer", "minimum": 0, "maximum": 16},
                "hours": {"type": "integer", "minimum": 1, "maximum": 168},
                "limit": {"type": "integer", "minimum": 1, "maximum": 100},
            },
        },
        func=recent_alerts,
    ),
    ChatTool(
        name="audit_trail",
        description=(
            "Read the events table. Useful for 'why did X happen' questions. "
            "Filter by investigation_id or event_type to narrow."
        ),
        schema={
            "type": "object",
            "properties": {
                "investigation_id": {"type": "string"},
                "event_type": {"type": "string"},
                "hours": {"type": "integer", "minimum": 1, "maximum": 720},
                "limit": {"type": "integer", "minimum": 1, "maximum": 200},
            },
        },
        func=audit_trail,
    ),
    ChatTool(
        name="tenant_stats",
        description=(
            "Rolled-up tenant counts over the last ``days`` days: alerts, "
            "investigations created, pending reviews, escalated reviews, avg "
            "AI confidence. Use for 'how busy are we' questions."
        ),
        schema={
            "type": "object",
            "properties": {
                "days": {"type": "integer", "minimum": 1, "maximum": 90},
            },
        },
        func=tenant_stats,
    ),
    ChatTool(
        name="search_investigations",
        description=(
            "Text search over investigation titles + summaries. Returns matching "
            "investigations sorted by opened_at desc."
        ),
        schema={
            "type": "object",
            "properties": {
                "query": {"type": "string"},
                "limit": {"type": "integer", "minimum": 1, "maximum": 50},
            },
            "required": ["query"],
        },
        func=search_investigations,
    ),
)


def find_tool(name: str) -> ChatTool | None:
    for t in AVAILABLE_TOOLS:
        if t.name == name:
            return t
    return None
