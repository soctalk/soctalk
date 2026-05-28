"""Chat API — CRUD for conversations + streaming SSE turn endpoint.

The router wraps :mod:`soctalk.chat.agent` with:
* Auth: every route depends on ``current_identity``; bearer-only
  routes 401 cleanly.
* Tenant-id stamping: writes follow the explicit MSSP-write rule
  documented in ``docs/chat-interface-plan.md``. ``investigation_id``
  present → inherit; absent → caller's ``current_tenant`` pin (mssp_admin
  needs Open SOC active for global chat) or home tenant_id.
* Per-tenant daily-cap enforcement via
  :func:`soctalk.core.cost.assert_tenant_daily_cap_ok` — same ceiling as
  the worker-claim path.
* Conversation FOR UPDATE lock around streaming so parallel-tab turns
  conflict deterministically with a 409, not a duplicate-billing race.
* Request-disconnect polling so a closed tab cancels the LLM call
  within ~1s.
"""

from __future__ import annotations

import asyncio
import os
from datetime import datetime
from typing import Any
from uuid import UUID

import structlog
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from soctalk.chat import actions as chat_actions
from soctalk.chat import sse
from soctalk.chat.agent import (
    TurnContext,
    load_investigation_summary,
    run_turn,
)
from soctalk.core.cost import assert_tenant_daily_cap_ok
from soctalk.core.tenancy.auth import current_identity, UserIdentity


logger = structlog.get_logger()

# Mount under /api so all routes are /api/chat/* — same prefix the
# other bridges use.
router = APIRouter(
    prefix="/api/chat",
    tags=["chat"],
    dependencies=[Depends(current_identity)],
)

MSSP_LEVEL_ROLES = frozenset({"platform_admin", "mssp_admin"})


def _db(request: Request) -> AsyncSession:
    sess = getattr(request.state, "db", None)
    if sess is None:
        raise HTTPException(500, "db session not attached")
    return sess


def _default_chat_model() -> str:
    """Per-tenant override later; for Phase 1 this is the env knob."""
    return os.getenv("SOCTALK_CHAT_MODEL", "claude-sonnet-4-20250514")


def _default_budget_dollars() -> float:
    raw = os.getenv("SOCTALK_CHAT_CONVERSATION_BUDGET", "")
    try:
        v = float(raw) if raw else 1.0
    except ValueError:
        v = 1.0
    return v if v > 0 else 1.0


# ---------------------------------------------------------------------------
# Pydantic shapes
# ---------------------------------------------------------------------------


class _CreateConversationBody(BaseModel):
    investigation_id: str | None = None
    model: str | None = None


class _PostMessageBody(BaseModel):
    text: str = Field(min_length=1, max_length=4000)


class _ConversationOut(BaseModel):
    id: str
    tenant_id: str
    created_by_user_id: str
    investigation_id: str | None
    title: str | None
    model_name: str
    status: str
    total_tokens: int
    total_dollars: float
    budget_dollars: float
    created_at: datetime
    last_message_at: datetime | None


class _MessageOut(BaseModel):
    id: str
    role: str
    content: dict[str, Any]
    tokens_in: int
    tokens_out: int
    dollars: float
    created_at: datetime


class _ConversationListOut(BaseModel):
    items: list[_ConversationOut]


class _ConversationDetailOut(BaseModel):
    conversation: _ConversationOut
    messages: list[_MessageOut]


# ---------------------------------------------------------------------------
# Tenant-id resolution (MSSP-write rule)
# ---------------------------------------------------------------------------


async def _resolve_tenant_for_write(
    db: AsyncSession,
    identity: UserIdentity,
    *,
    investigation_id: UUID | None,
) -> UUID:
    """Apply the MSSP-write tenant-id rule.

    1. investigation_id provided → use that investigation's tenant_id
       (authoritative binding); MSSP role allowed cross-tenant, tenant
       role only if it matches their home tenant.
    2. No investigation_id → caller's current_tenant pin if set, else
       home tenant_id. MSSP without a pin cannot create a global chat
       (would not have a single tenant_id to stamp).
    """
    if investigation_id is not None:
        row = (
            await db.execute(
                text("SELECT tenant_id::text FROM investigations WHERE id = :id"),
                {"id": str(investigation_id)},
            )
        ).mappings().first()
        if row is None:
            raise HTTPException(404, "investigation not found")
        inv_tenant = UUID(row["tenant_id"])
        if identity.role not in MSSP_LEVEL_ROLES:
            if identity.tenant_id != inv_tenant:
                raise HTTPException(
                    403, "investigation belongs to a different tenant"
                )
        return inv_tenant

    # Global-scope chat.
    current_pin = getattr(identity, "current_tenant", None)
    if identity.role in MSSP_LEVEL_ROLES:
        if current_pin is None:
            raise HTTPException(
                400,
                "MSSP global chat requires an active tenant pin (Open SOC)",
            )
        return (
            current_pin if isinstance(current_pin, UUID) else UUID(str(current_pin))
        )
    return identity.tenant_id


def _title_from_text(s: str) -> str:
    s = " ".join(s.split())
    return s[:80] if len(s) <= 80 else s[:79] + "…"


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.post("/conversations", response_model=_ConversationOut)
async def create_conversation(
    body: _CreateConversationBody, request: Request
) -> _ConversationOut:
    identity = current_identity(request)
    db = _db(request)

    inv_uuid: UUID | None = None
    if body.investigation_id:
        try:
            inv_uuid = UUID(body.investigation_id)
        except (TypeError, ValueError) as e:
            raise HTTPException(400, "invalid investigation_id") from e

    tenant_id = await _resolve_tenant_for_write(
        db, identity, investigation_id=inv_uuid
    )
    model_name = body.model or _default_chat_model()
    budget = _default_budget_dollars()

    row = (
        await db.execute(
            text(
                """
                INSERT INTO conversations (
                    tenant_id, created_by_user_id, investigation_id,
                    model_name, status, budget_dollars
                )
                VALUES (:t, :u, :inv, :m, 'active', :b)
                RETURNING id::text, tenant_id::text, created_by_user_id::text,
                          investigation_id::text, title, model_name, status,
                          total_tokens, total_dollars, budget_dollars,
                          created_at, last_message_at
                """
            ),
            {
                "t": str(tenant_id),
                "u": str(identity.user_id),
                "inv": str(inv_uuid) if inv_uuid else None,
                "m": model_name,
                "b": budget,
            },
        )
    ).mappings().first()
    if row is None:
        raise HTTPException(500, "conversation insert failed")
    return _ConversationOut(**dict(row))


@router.get("/conversations", response_model=_ConversationListOut)
async def list_conversations(
    request: Request,
    investigation_id: str | None = None,
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0),
) -> _ConversationListOut:
    db = _db(request)
    conds = ["1=1"]
    params: dict[str, Any] = {"n": limit, "off": offset}
    if investigation_id:
        conds.append("investigation_id = :inv")
        params["inv"] = investigation_id
    sql = (
        "SELECT id::text, tenant_id::text, created_by_user_id::text, "
        "investigation_id::text, title, model_name, status, total_tokens, "
        "total_dollars, budget_dollars, created_at, last_message_at "
        "FROM conversations WHERE " + " AND ".join(conds)
        + " ORDER BY created_at DESC LIMIT :n OFFSET :off"
    )
    rows = (await db.execute(text(sql), params)).mappings().all()
    return _ConversationListOut(items=[_ConversationOut(**dict(r)) for r in rows])


@router.get("/conversations/{conv_id}", response_model=_ConversationDetailOut)
async def get_conversation(conv_id: str, request: Request) -> _ConversationDetailOut:
    db = _db(request)
    conv = (
        await db.execute(
            text(
                """
                SELECT id::text, tenant_id::text, created_by_user_id::text,
                       investigation_id::text, title, model_name, status,
                       total_tokens, total_dollars, budget_dollars,
                       created_at, last_message_at
                FROM conversations WHERE id = :id
                """
            ),
            {"id": conv_id},
        )
    ).mappings().first()
    if conv is None:
        raise HTTPException(404, "conversation not found")
    msgs = (
        await db.execute(
            text(
                """
                SELECT id::text, role, content, tokens_in, tokens_out,
                       dollars, created_at
                FROM chat_messages
                WHERE conversation_id = :cid
                ORDER BY created_at ASC, id ASC
                LIMIT 200
                """
            ),
            {"cid": conv_id},
        )
    ).mappings().all()
    return _ConversationDetailOut(
        conversation=_ConversationOut(**dict(conv)),
        messages=[_MessageOut(**dict(m)) for m in msgs],
    )


@router.delete("/conversations/{conv_id}")
async def delete_conversation(conv_id: str, request: Request) -> dict[str, bool]:
    db = _db(request)
    await db.execute(
        text("UPDATE conversations SET status = 'closed' WHERE id = :id"),
        {"id": conv_id},
    )
    return {"ok": True}


# ---------------------------------------------------------------------------
# Streaming turn endpoint
# ---------------------------------------------------------------------------


@router.post("/conversations/{conv_id}/messages")
async def post_message(
    conv_id: str, body: _PostMessageBody, request: Request
) -> StreamingResponse:
    """Append a user message and stream the assistant's reply.

    Session lifecycle is subtle:

    * Pre-stream reads/writes (lock the conversation row, daily cap
      check, persist the user message, pre-load investigation summary)
      happen on the **request-bound session**. The middleware commits
      this session when the route returns 200, which releases the FOR
      UPDATE lock — fine, the lock's job is done by then.
    * The streaming agent loop runs on a **fresh session** opened
      inside the stream generator. Reusing the request session here
      blew up with ``asyncpg.InterfaceError: another operation in
      progress`` because the middleware's commit fires the moment the
      route returns the StreamingResponse, while the agent is still
      mid-query.

    Role-aware: MSSP-level callers get a BYPASSRLS session for the
    stream (so the agent's read tools can answer cross-tenant
    questions); tenant-level callers get an app session with
    ``tenant_context`` pinned to their home tenant.
    """
    identity = current_identity(request)
    db = _db(request)

    try:
        conv_uuid = UUID(conv_id)
    except (TypeError, ValueError) as e:
        raise HTTPException(400, "invalid conv_id") from e

    # FOR UPDATE lock prevents two browser tabs from triggering
    # concurrent turns on the same conversation and double-billing.
    conv = (
        await db.execute(
            text(
                """
                SELECT id::text, tenant_id::text, created_by_user_id::text,
                       investigation_id::text, model_name, status,
                       total_dollars, budget_dollars, title
                FROM conversations WHERE id = :id FOR UPDATE NOWAIT
                """
            ),
            {"id": conv_id},
        )
    ).mappings().first()
    if conv is None:
        raise HTTPException(404, "conversation not found")
    if conv["status"] != "active":
        raise HTTPException(
            409, f"conversation is {conv['status']}"
        )

    tenant_id = UUID(conv["tenant_id"])

    # Daily-cap check shared with the worker path.
    if await assert_tenant_daily_cap_ok(db, tenant_id, source="chat_post") is None:
        raise HTTPException(429, "tenant daily cap exceeded")

    # Append the user message + auto-title on first user message.
    await db.execute(
        text(
            """
            INSERT INTO chat_messages (
                conversation_id, tenant_id, role, content, created_at
            )
            VALUES (:cid, :t, 'user', CAST(:content AS jsonb), now())
            """
        ),
        {
            "cid": conv_id,
            "t": str(tenant_id),
            "content": '{"text": ' + _json_str(body.text) + "}",
        },
    )
    if not conv["title"]:
        await db.execute(
            text("UPDATE conversations SET title = :t WHERE id = :id"),
            {"t": _title_from_text(body.text), "id": conv_id},
        )

    # Pre-load investigation summary if scoped.
    summary = None
    if conv["investigation_id"]:
        try:
            summary = await load_investigation_summary(
                db, UUID(conv["investigation_id"])
            )
        except Exception:  # noqa: BLE001
            summary = None

    # Capture pre-stream context (the agent only needs values, not the
    # request session itself — by the time _stream() runs the
    # middleware has already committed and the session is closing).
    ctx = TurnContext(
        conversation_id=conv_uuid,
        tenant_id=tenant_id,
        user_id=identity.user_id,
        model_name=conv["model_name"],
        budget_dollars=float(conv["budget_dollars"]),
        total_dollars=float(conv["total_dollars"]),
        investigation_id=(
            UUID(conv["investigation_id"]) if conv["investigation_id"] else None
        ),
        investigation_summary=summary,
        user_text=body.text,
    )

    is_mssp = identity.role in MSSP_LEVEL_ROLES

    async def _stream() -> Any:
        from soctalk.core.tenancy.context import tenant_context
        from soctalk.core.tenancy.db import (
            get_app_sessionmaker,
            get_mssp_sessionmaker,
        )

        # Fresh session for the agent loop — the request-bound session
        # has been (or is about to be) committed by the middleware on
        # the 200 response. Reusing it triggers asyncpg's "another
        # operation in progress" InterfaceError mid-stream.
        if is_mssp:
            sm = get_mssp_sessionmaker()
            tctx = None
        else:
            sm = get_app_sessionmaker()
            tctx = identity.tenant_id

        try:
            async with sm() as stream_db:
                if tctx is not None:
                    async with tenant_context(stream_db, tctx):
                        async for frame in _run_with_disconnect(
                            request, ctx, stream_db
                        ):
                            yield frame
                        await stream_db.commit()
                else:
                    async for frame in _run_with_disconnect(
                        request, ctx, stream_db
                    ):
                        yield frame
                    await stream_db.commit()
        except asyncio.CancelledError:
            ctx.disconnected.set()
            raise

    return StreamingResponse(_stream(), media_type="text/event-stream")


async def _run_with_disconnect(
    request: Request, ctx: TurnContext, db: AsyncSession
) -> Any:
    """Wrap ``run_turn`` with the disconnect-poller task lifecycle."""
    disco_task = asyncio.create_task(_poll_disconnect(request, ctx))
    try:
        async for frame in run_turn(db, ctx):
            yield frame
    finally:
        ctx.disconnected.set()
        disco_task.cancel()


async def _poll_disconnect(request: Request, ctx: TurnContext) -> None:
    while not ctx.disconnected.is_set():
        if await request.is_disconnected():
            ctx.disconnected.set()
            return
        await asyncio.sleep(0.5)


# ---------------------------------------------------------------------------
# Stop endpoint (best-effort signal; the disconnect poller will pick it up)
# ---------------------------------------------------------------------------


@router.post("/conversations/{conv_id}/stop")
async def stop_conversation(conv_id: str, request: Request) -> dict[str, bool]:
    # Phase 1: we don't keep a side-channel registry of in-flight
    # turns. The /messages stream cancels naturally when the user
    # closes the request (which the disconnect poller catches). The
    # endpoint exists for future use; ack-only for now.
    return {"ok": True}


# ---------------------------------------------------------------------------
# Confirm proposed action
# ---------------------------------------------------------------------------


@router.post("/conversations/{conv_id}/messages/{msg_id}/confirm")
async def confirm_action(
    conv_id: str, msg_id: str, request: Request
) -> dict[str, Any]:
    identity = current_identity(request)
    db = _db(request)
    try:
        result = await chat_actions.dispatch_confirm(
            db,
            message_id=UUID(msg_id),
            conversation_id=UUID(conv_id),
            reviewer_user_id=identity.user_id,
            reviewer_email=identity.email,
        )
    except LookupError as e:
        raise HTTPException(404, str(e))
    except ValueError as e:
        raise HTTPException(400, str(e))
    return result


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------


def _json_str(s: str) -> str:
    """JSON-encode a string (with quotes) for inline SQL literal."""
    import json as _j

    return _j.dumps(s)
