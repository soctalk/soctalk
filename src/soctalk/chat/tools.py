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

Tenant targeting (since the MSSP chat work):

* Tenant-targeted tools take a ``tenant_slug`` argument. In tenant-scope
  conversations the dispatcher fills it in from ``ctx.tenant_id`` and
  the model can omit it; in fleet-scope (``scope='mssp_fleet'``) the
  model MUST supply it or the tool returns an error result.
* The dispatcher pre-resolves ``tenant_slug`` to ``target_tenant_id``
  (passed as a private kwarg so the model never sees a UUID) and adds
  a ``_tenant`` envelope to the result in fleet scope.

Fleet roll-ups (``fleet_only=True`` on ChatTool) are only registered
when ``ctx.scope == 'mssp_fleet'``; tenant-bound chats can't accidentally
peek at the fleet without explicitly opening one.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from soctalk.core.tenancy.auth import UserIdentity


MSSP_LEVEL_ROLES = frozenset({"platform_admin", "mssp_admin", "analyst"})


class TenantSlugRequired(ValueError):
    """Raised by the dispatcher when fleet scope + missing slug arg."""


class TenantSlugMismatch(ValueError):
    """Raised by the dispatcher when tenant scope + caller passes a
    different slug than the conversation's tenant."""


class TenantSlugUnknown(ValueError):
    """Raised when the slug doesn't resolve to a tenant row."""

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
# Tenant slug resolution (used by the agent dispatcher pre-call)
# -----------------------------------------------------------------------------


# Shared JSON-Schema fragment for the optional tenant_slug arg.
# Tenant-targeted tools merge this into their ``properties`` dict so the
# model gets the same description everywhere.
_TENANT_SLUG_PROP: dict[str, Any] = {
    "tenant_slug": {
        "type": "string",
        "description": (
            "Slug of the tenant to query. Required in fleet-scope "
            "conversations (no implicit tenant); omit in tenant-scope "
            "conversations (defaults to the conversation's tenant)."
        ),
    }
}


async def resolve_tenant_slug(
    db: AsyncSession, slug: str
) -> tuple[UUID, str, str]:
    """Look up (tenant_id, slug, display_name) for a slug.

    Caller is expected to run this against an MSSP-audience or
    BYPASSRLS session (tenant slug lookup is metadata, doesn't gate on
    the tenant's RLS). Raises ``TenantSlugUnknown`` on miss.
    """
    row = (
        await db.execute(
            text(
                "SELECT id::text, slug, display_name "
                "FROM tenants WHERE slug = :s LIMIT 1"
            ),
            {"s": slug},
        )
    ).mappings().first()
    if row is None:
        raise TenantSlugUnknown(f"unknown tenant_slug: {slug!r}")
    return (UUID(row["id"]), row["slug"], row["display_name"] or row["slug"])


# -----------------------------------------------------------------------------
# Tool implementations
# -----------------------------------------------------------------------------


async def get_investigation(
    db: AsyncSession,
    *,
    investigation_id: str,
    target_tenant_id: UUID | None = None,
) -> ToolResult:
    """Full investigation row + active pending_review + last 10 alerts + last 20 events.

    ``target_tenant_id`` is injected by the dispatcher when fleet-scope
    callers pass ``tenant_slug``; if set, the investigation row must
    belong to that tenant or the tool returns "not found in tenant".
    """
    try:
        iid = UUID(investigation_id)
    except (TypeError, ValueError):
        return _enforce_size({"error": "invalid investigation_id"})

    inv_sql = """
        SELECT id::text, tenant_id::text, short_id, title, status,
               severity, summary, opened_at, closed_at, close_reason,
               reopen_count, visibility
        FROM investigations
        WHERE id = :id
    """
    inv_params: dict[str, Any] = {"id": str(iid)}
    if target_tenant_id is not None:
        inv_sql += " AND tenant_id = :tid"
        inv_params["tid"] = str(target_tenant_id)
    inv = (await db.execute(text(inv_sql), inv_params)).mappings().first()
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
    target_tenant_id: UUID | None = None,
) -> ToolResult:
    """List recent pending HIL reviews matching the given status."""
    limit = max(1, min(50, limit))
    conds = ["status = :s"]
    params: dict[str, Any] = {"s": status, "n": limit}
    if target_tenant_id is not None:
        conds.append("tenant_id = :tid")
        params["tid"] = str(target_tenant_id)
    sql = (
        "SELECT id::text, investigation_id::text, status, title, "
        "max_severity, ai_decision, ai_confidence, created_at "
        "FROM pending_reviews WHERE " + " AND ".join(conds)
        + " ORDER BY created_at DESC LIMIT :n"
    )
    rows = (await db.execute(text(sql), params)).mappings().all()
    return _enforce_size([dict(r) for r in rows])


async def recent_alerts(
    db: AsyncSession,
    *,
    rule_id: str | None = None,
    severity_min: int | None = None,
    hours: int = 24,
    limit: int = 50,
    target_tenant_id: UUID | None = None,
) -> ToolResult:
    """Recent alerts, optionally filtered by rule and minimum severity."""
    hours = max(1, min(168, hours))
    limit = max(1, min(100, limit))
    conds = ["first_event_at >= now() - make_interval(hours => :h)"]
    params: dict[str, Any] = {"h": hours, "n": limit}
    if target_tenant_id is not None:
        conds.append("tenant_id = :tid")
        params["tid"] = str(target_tenant_id)
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
    target_tenant_id: UUID | None = None,
) -> ToolResult:
    """Recent events from the audit log."""
    hours = max(1, min(720, hours))
    limit = max(1, min(200, limit))
    conds = ["timestamp >= now() - make_interval(hours => :h)"]
    params: dict[str, Any] = {"h": hours, "n": limit}
    if target_tenant_id is not None:
        conds.append("tenant_id = :tid")
        params["tid"] = str(target_tenant_id)
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


async def tenant_stats(
    db: AsyncSession,
    *,
    days: int = 7,
    target_tenant_id: UUID | None = None,
) -> ToolResult:
    """Rolled-up tenant activity over the last ``days`` days.

    In tenant scope, RLS already pins to the caller's tenant; the
    dispatcher still injects ``target_tenant_id`` so we can additionally
    AND it for defense in depth on MSSP-BYPASS sessions.
    """
    days = max(1, min(90, days))
    if target_tenant_id is not None:
        tid_clause = "AND tenant_id = '" + str(target_tenant_id) + "'"
    else:
        tid_clause = ""
    row = (
        await db.execute(
            text(
                f"""
                SELECT
                  (SELECT COUNT(*)::int FROM alerts
                     WHERE first_event_at >= now() - make_interval(days => :d)
                     {tid_clause})                              AS alerts,
                  (SELECT COUNT(*)::int FROM investigations
                     WHERE created_at >= now() - make_interval(days => :d)
                     {tid_clause})                              AS investigations,
                  (SELECT COUNT(*)::int FROM pending_reviews
                     WHERE status = 'pending'
                     {tid_clause})                              AS pending_reviews,
                  (SELECT COUNT(*)::int FROM pending_reviews
                     WHERE created_at >= now() - make_interval(days => :d)
                       AND ai_decision = 'escalate'
                     {tid_clause})                              AS escalated,
                  (SELECT AVG(ai_confidence)::float FROM pending_reviews
                     WHERE created_at >= now() - make_interval(days => :d)
                       AND ai_confidence IS NOT NULL
                     {tid_clause})                              AS avg_ai_confidence
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
    db: AsyncSession,
    *,
    query: str,
    limit: int = 20,
    target_tenant_id: UUID | None = None,
) -> ToolResult:
    """ILIKE search over investigation title + summary."""
    limit = max(1, min(50, limit))
    if not query or not query.strip():
        return _enforce_size({"error": "query is empty"})
    conds = ["(title ILIKE :q OR COALESCE(summary, '') ILIKE :q)"]
    params: dict[str, Any] = {"q": f"%{query.strip()}%", "n": limit}
    if target_tenant_id is not None:
        conds.append("tenant_id = :tid")
        params["tid"] = str(target_tenant_id)
    sql = (
        "SELECT id::text, short_id, title, status, severity, opened_at "
        "FROM investigations WHERE " + " AND ".join(conds)
        + " ORDER BY opened_at DESC LIMIT :n"
    )
    rows = (await db.execute(text(sql), params)).mappings().all()
    return _enforce_size([dict(r) for r in rows])


# -----------------------------------------------------------------------------
# Fleet roll-ups (mssp_fleet scope only — never bound in tenant scope)
# -----------------------------------------------------------------------------


async def list_tenants(db: AsyncSession) -> ToolResult:
    """Enumerate tenants the MSSP serves.

    Returns one row per tenant: ``id``, ``slug``, ``display_name``,
    plus quick counts (open investigations, pending reviews) so the
    agent has a single tool call to anchor a fleet conversation.
    """
    rows = (
        await db.execute(
            text(
                """
                SELECT t.id::text                            AS id,
                       t.slug                                AS slug,
                       t.display_name                        AS display_name,
                       COALESCE(i.cnt, 0)::int               AS open_investigations,
                       COALESCE(p.cnt, 0)::int               AS pending_reviews
                FROM tenants t
                LEFT JOIN (
                    -- Open investigations are stored as status='active'
                    -- in this codebase (see existing dashboards / IR
                    -- metrics). 'open' was a misnomer in the plan doc.
                    SELECT tenant_id, COUNT(*) AS cnt
                      FROM investigations
                     WHERE status = 'active'
                     GROUP BY tenant_id
                ) i ON i.tenant_id = t.id
                LEFT JOIN (
                    SELECT tenant_id, COUNT(*) AS cnt
                      FROM pending_reviews
                     WHERE status = 'pending'
                     GROUP BY tenant_id
                ) p ON p.tenant_id = t.id
                ORDER BY t.slug ASC
                """
            )
        )
    ).mappings().all()
    return _enforce_size([dict(r) for r in rows])


async def fleet_pending_reviews(db: AsyncSession) -> ToolResult:
    """Pending review counts per tenant — no row bodies.

    The agent uses this for fleet-wide queue questions ("which tenants
    have a backlog?") without inflating the result set.
    """
    rows = (
        await db.execute(
            text(
                """
                SELECT t.slug                       AS tenant_slug,
                       t.display_name               AS tenant_name,
                       COALESCE(p.cnt, 0)::int      AS pending_count
                FROM tenants t
                LEFT JOIN (
                    SELECT tenant_id, COUNT(*) AS cnt
                      FROM pending_reviews
                     WHERE status = 'pending'
                     GROUP BY tenant_id
                ) p ON p.tenant_id = t.id
                ORDER BY pending_count DESC, t.slug ASC
                """
            )
        )
    ).mappings().all()
    return _enforce_size([dict(r) for r in rows])


async def fleet_recent_alert_counts(
    db: AsyncSession, *, hours: int = 24
) -> ToolResult:
    """Alert counts per tenant for the last ``hours`` hours."""
    hours = max(1, min(168, hours))
    rows = (
        await db.execute(
            text(
                """
                SELECT t.slug                                 AS tenant_slug,
                       t.display_name                         AS tenant_name,
                       COALESCE(a.cnt, 0)::int                AS alert_count,
                       COALESCE(a.max_sev, 0)::int            AS max_severity
                FROM tenants t
                LEFT JOIN (
                    SELECT tenant_id,
                           COUNT(*) AS cnt,
                           MAX(severity) AS max_sev
                      FROM alerts
                     WHERE first_event_at >= now() - make_interval(hours => :h)
                     GROUP BY tenant_id
                ) a ON a.tenant_id = t.id
                ORDER BY alert_count DESC, t.slug ASC
                """
            ),
            {"h": hours},
        )
    ).mappings().all()
    return _enforce_size([dict(r) for r in rows])


async def set_fleet_focus(
    db: AsyncSession,
    *,
    slug_or_name: str,
    _conversation_id: UUID | None = None,
    _ctx: Any = None,
) -> ToolResult:
    """Pin the active fleet conversation to a tenant (soft focus).

    After this lands, subsequent fleet-scope tool calls that omit
    ``tenant_slug`` default to this tenant. Persisted to the
    ``conversations.focused_tenant_id`` column so the focus survives
    reloads / new turns.

    The ``slug_or_name`` accepts EITHER the canonical slug (``labtenant``)
    or the display name (``Lab Tenant``, case-insensitive). The dispatcher
    injects ``_conversation_id`` and the live ``_ctx`` — the model never
    sees those args.
    """
    needle = slug_or_name.strip()
    if not needle:
        return _enforce_size({"error": "slug_or_name is empty"})
    row = (
        await db.execute(
            text(
                """
                SELECT id::text, slug, display_name
                FROM tenants
                WHERE slug = :s OR LOWER(display_name) = LOWER(:s)
                LIMIT 1
                """
            ),
            {"s": needle},
        )
    ).mappings().first()
    if row is None:
        return _enforce_size(
            {"error": f"no tenant matches {slug_or_name!r} by slug or display name"}
        )
    target_id = UUID(row["id"])
    target_slug = row["slug"]
    target_name = row["display_name"] or target_slug

    if _conversation_id is None:
        return _enforce_size(
            {"error": "internal: dispatcher did not inject _conversation_id"}
        )
    # Persist the focus on the conversation row. The MSSP session this
    # tool runs under is BYPASSRLS so the UPDATE works regardless of
    # the row's tenant_id (NULL for fleet).
    await db.execute(
        text(
            "UPDATE conversations SET focused_tenant_id = :t WHERE id = :c"
        ),
        {"t": str(target_id), "c": str(_conversation_id)},
    )
    # Mutate the in-memory ctx so the rest of the same turn picks it up
    # without re-reading the row.
    if _ctx is not None:
        _ctx.focused_tenant_id = target_id
        _ctx.focused_tenant_slug = target_slug
    return _enforce_size(
        {
            "ok": True,
            "focused_on": {
                "slug": target_slug,
                "display_name": target_name,
            },
        }
    )


async def fleet_active_investigations(db: AsyncSession) -> ToolResult:
    """Open-investigation counts per tenant (by max severity bucket)."""
    rows = (
        await db.execute(
            text(
                """
                SELECT t.slug                                 AS tenant_slug,
                       t.display_name                         AS tenant_name,
                       COALESCE(i.open_cnt, 0)::int           AS open_count,
                       COALESCE(i.max_sev, 0)::int            AS max_severity
                FROM tenants t
                LEFT JOIN (
                    -- status='active' is the open state for
                    -- investigations in this schema (not 'open').
                    SELECT tenant_id,
                           COUNT(*) FILTER (WHERE status = 'active') AS open_cnt,
                           MAX(severity) FILTER (WHERE status = 'active') AS max_sev
                      FROM investigations
                     GROUP BY tenant_id
                ) i ON i.tenant_id = t.id
                ORDER BY open_count DESC, t.slug ASC
                """
            )
        )
    ).mappings().all()
    return _enforce_size([dict(r) for r in rows])


# -----------------------------------------------------------------------------
# Tool registry
# -----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ChatTool:
    """LangChain-style tool descriptor with a typed dispatcher.

    ``fleet_only`` tools are excluded from the bound tool list in
    tenant-scope conversations (e.g. ``list_tenants``, ``fleet_*``
    roll-ups). All other tools are tenant-targeted and accept the
    optional ``tenant_slug`` arg the dispatcher pre-resolves.
    """

    name: str
    description: str
    schema: dict[str, Any]  # JSON Schema for arguments
    func: Callable[..., Awaitable[ToolResult]] = field(repr=False)
    # Restrict to mssp_fleet-scope conversations only.
    fleet_only: bool = False
    # Set to False for tools that already target a global scope and
    # don't need the dispatcher to inject ``target_tenant_id`` /
    # ``_tenant`` (e.g. roll-ups). Tenant-targeted tools default True.
    tenant_targeted: bool = True


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
                **_TENANT_SLUG_PROP,
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
                **_TENANT_SLUG_PROP,
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
                **_TENANT_SLUG_PROP,
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
                **_TENANT_SLUG_PROP,
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
                **_TENANT_SLUG_PROP,
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
                **_TENANT_SLUG_PROP,
            },
            "required": ["query"],
        },
        func=search_investigations,
    ),
    # -------------------------------------------------------------------
    # Fleet roll-ups — only bound in mssp_fleet scope.
    # -------------------------------------------------------------------
    ChatTool(
        name="list_tenants",
        description=(
            "List every tenant the MSSP serves with quick counts (open "
            "investigations, pending reviews). Always call this first in a "
            "fleet conversation to learn which tenants exist."
        ),
        schema={"type": "object", "properties": {}},
        func=list_tenants,
        fleet_only=True,
        tenant_targeted=False,
    ),
    ChatTool(
        name="set_fleet_focus",
        description=(
            "Pin the active fleet conversation to a tenant so subsequent "
            "tool calls default to it without needing ``tenant_slug`` on "
            "every call. Call this AS SOON AS the user signals a tenant "
            "to work on (e.g. 'let's focus on lab tenant', 'switch to "
            "acme-corp'). Accepts either the slug ('labtenant') or the "
            "display name ('Lab Tenant'). Persists across turns. Call "
            "again with a different name to switch focus."
        ),
        schema={
            "type": "object",
            "properties": {
                "slug_or_name": {
                    "type": "string",
                    "description": "Tenant slug or display name to focus on.",
                },
            },
            "required": ["slug_or_name"],
        },
        func=set_fleet_focus,
        fleet_only=True,
        # Not tenant_targeted: the dispatcher must NOT inject
        # ``target_tenant_id`` here — this tool's job IS to set focus,
        # not to consume an already-resolved target.
        tenant_targeted=False,
    ),
    ChatTool(
        name="fleet_pending_reviews",
        description=(
            "Pending review counts per tenant (no row bodies). Use for "
            "fleet-wide queue / backlog questions in one tool call."
        ),
        schema={"type": "object", "properties": {}},
        func=fleet_pending_reviews,
        fleet_only=True,
        tenant_targeted=False,
    ),
    ChatTool(
        name="fleet_recent_alert_counts",
        description=(
            "Alert counts per tenant over the last ``hours`` hours, with "
            "max severity. Use for 'who's noisy right now?'."
        ),
        schema={
            "type": "object",
            "properties": {
                "hours": {"type": "integer", "minimum": 1, "maximum": 168},
            },
        },
        func=fleet_recent_alert_counts,
        fleet_only=True,
        tenant_targeted=False,
    ),
    ChatTool(
        name="fleet_active_investigations",
        description=(
            "Open-investigation counts per tenant with max severity. Use "
            "for fleet status / triage prioritisation questions."
        ),
        schema={"type": "object", "properties": {}},
        func=fleet_active_investigations,
        fleet_only=True,
        tenant_targeted=False,
    ),
)


def find_tool(name: str) -> ChatTool | None:
    for t in AVAILABLE_TOOLS:
        if t.name == name:
            return t
    return None
