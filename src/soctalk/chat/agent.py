"""Chat-turn execution loop.

Public entry: :func:`run_turn` — async generator that yields SSE bytes
as the assistant works. The caller (the chat POST handler) consumes
the generator, writes each frame to the StreamingResponse, and polls
``request.is_disconnected()`` between frames so a closed tab cancels
the LLM call promptly.

Loop shape:

1. Load the conversation history (system + recent turns + tool results).
2. Apply context eviction (system + last 2 user/assistant turns kept
   full; older tool results replaced with 1-line summaries; oldest
   dropped first if still over the per-turn cap).
3. Bind the read-only tools (`AVAILABLE_TOOLS`) to the model.
4. Invoke the model with the message list.
5. For each model response:
   - If text: stream as ``delta`` events; accumulate into the assistant
     message.
   - If tool call: emit ``tool_call``; dispatch; emit ``tool_result``;
     append to history; re-invoke.
   - If structured ``proposed_action`` (the model formats it as JSON
     inside a delimited block): emit ``proposed_action``, persist as
     ``role='action'`` chat_messages row.
6. After end-of-turn, emit ``usage`` and ``done``.

Mid-stream concerns:

* ``request.is_disconnected()`` polling — the caller decides; this loop
  surfaces a ``cancelled=True`` flag via the ``Cancelled`` sentinel.
* Per-conversation budget exhaustion — checked at the top of every
  model invocation; on overshoot the loop emits ``budget_exhausted``
  + ``done`` (stop_reason=budget_exhausted) and persists what it has.
* Provider errors — classified via the verdict node's
  ``_classify_llm_error`` helper so credit-lack / rate-limit don't leak
  raw messages.
"""

from __future__ import annotations

import asyncio
import json
import re
from dataclasses import dataclass, field
from typing import Any, AsyncIterator
from uuid import UUID, uuid4

import structlog
from langchain_core.messages import (
    AIMessage,
    BaseMessage,
    HumanMessage,
    SystemMessage,
    ToolMessage,
)
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from soctalk.chat import actions, prompts, sse
from soctalk.chat.tools import (
    AVAILABLE_TOOLS,
    ChatTool,
    ToolResult,
    find_tool,
    get_investigation,
)
from soctalk.config import get_config
from soctalk.graph import budget as token_budget
from soctalk.llm import create_chat_model
from soctalk.supervisor.verdict import _classify_llm_error


logger = structlog.get_logger()


# Per-turn structural limits. The model's own ``max_tokens`` (2k by
# default) bounds the output; this bounds how much *prior* context we
# stuff back in.
DEFAULT_KEEP_FULL_TURNS = 2  # last N user+assistant turn pairs
MAX_TOOL_ITERATIONS = 6  # safety net for runaway tool loops


# Pattern the model uses to emit a structured proposed action inside
# its prose. JSON between ``<action>`` … ``</action>`` markers so the
# normal text stream can intersperse explanation around it.
_ACTION_BLOCK_RE = re.compile(
    r"<action>\s*(\{.*?\})\s*</action>", re.DOTALL | re.IGNORECASE
)


@dataclass(slots=True)
class TurnContext:
    """Everything the loop needs to know about one turn."""

    conversation_id: UUID
    tenant_id: UUID
    user_id: UUID
    model_name: str
    budget_dollars: float
    total_dollars: float
    investigation_id: UUID | None
    # Pre-fetched compact investigation context (or None).
    investigation_summary: dict[str, Any] | None
    # The user's new message text (already persisted as a row before
    # ``run_turn`` is invoked).
    user_text: str
    # Set by the caller to signal cancellation (closed tab, /stop).
    disconnected: asyncio.Event = field(default_factory=asyncio.Event)


# ---------------------------------------------------------------------------
# History loading + eviction
# ---------------------------------------------------------------------------


async def _load_history(
    db: AsyncSession, conversation_id: UUID
) -> list[dict[str, Any]]:
    """Pull the conversation log in insertion order.

    JSONB columns come back from asyncpg as *str* when accessed via
    raw ``text()`` SQL (no SQLAlchemy column type info). Deserialise
    explicitly so downstream ``content.get('text')`` works — without
    this the agent silently dropped every user message and Anthropic
    rejected the turn with ``messages: at least one message is required``.
    """
    rows = (
        await db.execute(
            text(
                """
                SELECT id::text, role, content, created_at
                FROM chat_messages
                WHERE conversation_id = :cid
                ORDER BY created_at ASC, id ASC
                """
            ),
            {"cid": str(conversation_id)},
        )
    ).mappings().all()
    out: list[dict[str, Any]] = []
    for r in rows:
        d = dict(r)
        c = d.get("content")
        if isinstance(c, str):
            try:
                d["content"] = json.loads(c)
            except (TypeError, ValueError):
                d["content"] = {}
        out.append(d)
    return out


def _summarise_tool_row(row: dict[str, Any]) -> str:
    """One-line evictable summary of an old tool call."""
    content = row.get("content") or {}
    name = content.get("name") or "tool"
    args = content.get("args") or {}
    args_str = ", ".join(f"{k}={v!r}" for k, v in list(args.items())[:3])
    result = content.get("result")
    if isinstance(result, dict) and "data" in result:
        data = result["data"]
    else:
        data = result
    if isinstance(data, list):
        summary = f"{len(data)} rows"
    elif isinstance(data, dict):
        keys = list(data.keys())[:3]
        summary = "keys=" + ",".join(keys)
    else:
        summary = str(data)[:60]
    return f"[older] {name}({args_str}) → {summary}"


def _build_messages(
    history: list[dict[str, Any]],
    *,
    system_prompt: str,
    keep_full_turns: int = DEFAULT_KEEP_FULL_TURNS,
) -> list[BaseMessage]:
    """Apply context eviction and return the LangChain message list.

    Strategy:
    * Always include the system prompt.
    * Walk backwards from the end of history; keep full content for
      the last ``keep_full_turns`` user+assistant pairs (plus any
      adjacent tool messages from those turns).
    * Older user/assistant messages: keep full text (cheap).
    * Older tool messages: replace with a 1-line summary.

    Returns the message list in chronological order (oldest first).
    """
    out: list[BaseMessage] = [SystemMessage(content=system_prompt)]

    # Count back the last N user messages — index of the cutoff.
    user_indices = [i for i, r in enumerate(history) if r["role"] == "user"]
    cutoff_user_idx = (
        user_indices[-keep_full_turns] if len(user_indices) >= keep_full_turns
        else (user_indices[0] if user_indices else 0)
    )

    for i, row in enumerate(history):
        role = row["role"]
        content = row.get("content") or {}
        keep_full = i >= cutoff_user_idx
        if role == "user":
            out.append(HumanMessage(content=content.get("text") or ""))
        elif role == "assistant":
            text_val = content.get("text") or ""
            if keep_full:
                out.append(AIMessage(content=text_val))
            else:
                # Older assistant — still keep, but trimmed.
                out.append(AIMessage(content=text_val[:400]))
        elif role == "tool":
            # Always summarise tool calls from prior turns as a system
            # note rather than emitting a ``ToolMessage``. Anthropic
            # requires every ``tool_result`` block to be preceded by
            # the assistant message containing the matching
            # ``tool_use`` block. We DON'T persist the assistant's raw
            # tool_use intent (only its text reply) — so reconstructing
            # the chain would always orphan the tool_result and
            # Anthropic rejects the turn with 400. The summary
            # preserves the *information* the model needs to remember
            # without forcing the brittle ordering reconstruction.
            #
            # In-turn tool calls (within the same ``run_turn``
            # iteration) DO get proper ToolMessage round-trips because
            # they're appended directly to ``messages`` after the
            # corresponding response — those flow via a different code
            # path and don't come from this history rebuild.
            out.append(SystemMessage(content=_summarise_tool_row(row)))
        elif role == "system":
            # In-line system note (rare; e.g. budget warning). Preserve.
            out.append(SystemMessage(content=content.get("text") or ""))
        elif role == "action":
            # Past action proposal — describe it but don't ask the
            # model to re-emit. Helps the analyst's mental state and
            # the model's continuity without producing duplicate
            # buttons in the UI.
            label = content.get("action", "action")
            tid = (content.get("target") or {}).get("id", "?")
            status = "confirmed" if content.get("confirmed_at") else "pending"
            out.append(
                SystemMessage(content=f"[prior_action] {label} on {tid} ({status})")
            )

    return out


# ---------------------------------------------------------------------------
# Tool dispatch
# ---------------------------------------------------------------------------


async def _dispatch_tool(
    tool: ChatTool, db: AsyncSession, raw_args: dict[str, Any]
) -> ToolResult:
    """Call the tool function with kwarg unpacking. Catches errors."""
    try:
        return await tool.func(db, **raw_args)  # type: ignore[arg-type]
    except TypeError as e:
        return ToolResult(data={"error": f"bad arguments: {e}"})
    except Exception as e:  # noqa: BLE001
        logger.exception("chat_tool_error tool=%s", tool.name)
        return ToolResult(data={"error": f"{type(e).__name__}: {e}"[:200]})


# ---------------------------------------------------------------------------
# LLM tool-binding (provider-agnostic via LangChain)
# ---------------------------------------------------------------------------


def _tool_specs_for_binding() -> list[dict[str, Any]]:
    """Render tool schemas in the LangChain ``tool`` format."""
    return [
        {
            "type": "function",
            "function": {
                "name": t.name,
                "description": t.description,
                "parameters": t.schema,
            },
        }
        for t in AVAILABLE_TOOLS
    ]


# ---------------------------------------------------------------------------
# Persistence helpers
# ---------------------------------------------------------------------------


async def _insert_message(
    db: AsyncSession,
    *,
    conversation_id: UUID,
    tenant_id: UUID,
    role: str,
    content: dict[str, Any],
    tokens_in: int = 0,
    tokens_out: int = 0,
    dollars: float = 0.0,
    model_name: str | None = None,
) -> UUID:
    """Insert one chat_messages row and return its id."""
    msg_id = uuid4()
    await db.execute(
        text(
            """
            INSERT INTO chat_messages (
                id, conversation_id, tenant_id, role, content,
                tokens_in, tokens_out, dollars, model_name, created_at
            ) VALUES (
                :id, :cid, :t, :role, CAST(:content AS jsonb),
                :tin, :tout, :dollars, :model, now()
            )
            """
        ),
        {
            "id": str(msg_id),
            "cid": str(conversation_id),
            "t": str(tenant_id),
            "role": role,
            "content": json.dumps(content, default=str),
            "tin": tokens_in,
            "tout": tokens_out,
            "dollars": dollars,
            "model": model_name,
        },
    )
    return msg_id


async def _update_conversation_totals(
    db: AsyncSession,
    *,
    conversation_id: UUID,
    add_tokens: int,
    add_dollars: float,
    new_status: str | None = None,
) -> tuple[int, float]:
    """Increment the rolling totals on the conversation row.

    Returns ``(new_total_tokens, new_total_dollars)`` so the caller
    can include them in the ``usage`` SSE frame without a re-read.
    """
    row = (
        await db.execute(
            text(
                """
                UPDATE conversations
                   SET total_tokens = total_tokens + :tk,
                       total_dollars = total_dollars + :d,
                       last_message_at = now(),
                       status = COALESCE(:st, status)
                 WHERE id = :id
                RETURNING total_tokens, total_dollars
                """
            ),
            {
                "tk": int(add_tokens),
                "d": float(add_dollars),
                "st": new_status,
                "id": str(conversation_id),
            },
        )
    ).mappings().first()
    if row is None:
        return (0, 0.0)
    return (int(row["total_tokens"] or 0), float(row["total_dollars"] or 0.0))


# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------


async def run_turn(
    db: AsyncSession, ctx: TurnContext
) -> AsyncIterator[bytes]:
    """Yield SSE frames for one assistant turn.

    The caller is responsible for:
    * Holding the conversation row's ``FOR UPDATE`` lock (taken in
      ``chat.py`` before this is invoked).
    * Calling ``ctx.disconnected.set()`` when the client disconnects.
    """
    # 0. Per-conversation budget check up-front. If already exhausted,
    #    short-circuit before any LLM cost.
    if ctx.total_dollars >= ctx.budget_dollars:
        yield sse.error(
            "budget_exhausted",
            "This conversation has reached its $%.2f cap." % ctx.budget_dollars,
        )
        yield sse.done(str(uuid4()), stop_reason="budget_exhausted")
        return

    # 1. Build the system prompt.
    if ctx.investigation_summary:
        system_prompt = prompts.per_investigation_system_prompt(
            ctx.investigation_summary
        )
    else:
        system_prompt = prompts.GLOBAL_SYSTEM_PROMPT

    # 2. Load history + build the message list with eviction.
    history = await _load_history(db, ctx.conversation_id)
    messages = _build_messages(history, system_prompt=system_prompt)

    # 3. Set up the model with tools.
    app_config = get_config()
    llm = create_chat_model(
        app_config.llm,
        model=ctx.model_name,
        temperature=0.2,
        max_tokens=2048,
    )
    try:
        llm = llm.bind_tools(_tool_specs_for_binding())
    except (AttributeError, TypeError):
        # Some providers don't support bind_tools; the loop still
        # works as a chat-only agent without tool calls.
        logger.warning("chat_bind_tools_unavailable model=%s", ctx.model_name)

    # 4. Iterate: invoke → handle response (text/tool_call) → repeat.
    assistant_text_buf = ""
    final_message_id = uuid4()
    total_tokens_in = 0
    total_tokens_out = 0
    total_turn_dollars = 0.0
    iterations = 0
    stop_reason = "end_turn"

    try:
        while iterations < MAX_TOOL_ITERATIONS:
            iterations += 1
            if ctx.disconnected.is_set():
                stop_reason = "disconnected"
                break

            response = await llm.ainvoke(messages)
            # Track usage on the in-flight state for budget checks.
            state: dict[str, Any] = {
                "tokens_used": 0,
                "dollars_used": 0.0,
                "tokens_budget": 10**9,
                "dollars_budget": ctx.budget_dollars,
            }
            token_budget.track(state, response)
            turn_in = max(0, int(state["tokens_used"]) - total_tokens_out - total_tokens_in)
            total_tokens_in += turn_in  # crude but ordered-correct
            turn_dollars_this_call = float(state["dollars_used"])
            total_turn_dollars += turn_dollars_this_call

            # Anthropic-via-LangChain returns ``response.content`` as
            # *either* a plain string (text-only turn) or a list of
            # content blocks (text + tool_use mixed). Flatten to a
            # single string so the action-block regex + delta stream
            # work uniformly.
            raw_content = response.content
            if isinstance(raw_content, list):
                response_text = "".join(
                    b.get("text", "") if isinstance(b, dict) and b.get("type") == "text"
                    else (b if isinstance(b, str) else "")
                    for b in raw_content
                )
            else:
                response_text = raw_content or ""
            tool_calls = getattr(response, "tool_calls", None) or []

            # Update message list with the model's response for the
            # next iteration even if tool calls.
            messages.append(response)

            # Check for a structured proposed_action block embedded in
            # the prose. Multiple blocks per turn are unusual but we
            # tolerate; only the first one is persisted in Phase 1.
            action_payload: dict[str, Any] | None = None
            for m in _ACTION_BLOCK_RE.finditer(response_text):
                try:
                    raw = json.loads(m.group(1))
                    payload = actions.build_proposed_action(
                        action=raw.get("action"),
                        target_kind=(raw.get("target") or {}).get("kind"),
                        target_id=(raw.get("target") or {}).get("id"),
                        target_title=(raw.get("target") or {}).get("title"),
                        reason=raw.get("reason") or "",
                        evidence=raw.get("evidence") or [],
                        confidence=raw.get("confidence"),
                        feedback=raw.get("feedback"),
                    )
                    action_payload = payload
                    break
                except (ValueError, KeyError, json.JSONDecodeError) as e:
                    logger.warning(
                        "chat_action_parse_failed err=%s block=%s",
                        str(e),
                        m.group(1)[:100],
                    )
                    continue

            # Strip the action block from the text we stream to the
            # user so they see the analyst-friendly paragraph, not
            # the JSON.
            display_text = _ACTION_BLOCK_RE.sub("", response_text).strip()

            # Stream the text content. (No real token streaming since
            # langchain-anthropic's ainvoke returns the full message;
            # we surface it as one delta. For real streaming we'd use
            # astream — Phase 1 ships ainvoke for simplicity.)
            if display_text:
                assistant_text_buf += display_text
                yield sse.delta(display_text)

            if action_payload is not None:
                yield sse.proposed_action(action_payload)

            if not tool_calls:
                # Model done with tools; exit the loop after streaming.
                break

            for tc in tool_calls:
                if ctx.disconnected.is_set():
                    stop_reason = "disconnected"
                    break
                tname = tc.get("name") if isinstance(tc, dict) else getattr(tc, "name", None)
                targs = tc.get("args") if isinstance(tc, dict) else getattr(tc, "args", None) or {}
                call_id = tc.get("id") if isinstance(tc, dict) else getattr(tc, "id", None)
                call_id = call_id or str(uuid4())

                tool = find_tool(tname or "")
                yield sse.tool_call(call_id, tname or "", targs or {})

                if tool is None:
                    result = ToolResult(data={"error": f"unknown tool: {tname!r}"})
                else:
                    result = await _dispatch_tool(tool, db, targs or {})

                yield sse.tool_result(
                    call_id, result.to_dict(), truncated=result.truncated
                )

                # Persist the tool message in chat_messages for audit
                # and history reconstruction on later turns.
                await _insert_message(
                    db,
                    conversation_id=ctx.conversation_id,
                    tenant_id=ctx.tenant_id,
                    role="tool",
                    content={
                        "name": tname,
                        "args": targs or {},
                        "result": result.to_dict(),
                        "call_id": call_id,
                    },
                )

                # Append a ToolMessage so the next ainvoke sees the
                # result in the model's context.
                messages.append(
                    ToolMessage(
                        content=json.dumps(result.to_dict(), default=str),
                        tool_call_id=call_id,
                    )
                )

            if ctx.disconnected.is_set():
                stop_reason = "disconnected"
                break

            # Budget check between iterations.
            if ctx.total_dollars + total_turn_dollars >= ctx.budget_dollars:
                stop_reason = "budget_exhausted"
                break

        # Persist the assistant message.
        if assistant_text_buf or stop_reason != "end_turn":
            await _insert_message(
                db,
                conversation_id=ctx.conversation_id,
                tenant_id=ctx.tenant_id,
                role="assistant",
                content={"text": assistant_text_buf or ""},
                tokens_in=total_tokens_in,
                tokens_out=total_tokens_out,
                dollars=total_turn_dollars,
                model_name=ctx.model_name,
            )

        # Persist the proposed_action if any (last one wins). We don't
        # persist this until *after* the turn ends so a half-built
        # action from a cancelled stream doesn't show up as a stale
        # button.
        if action_payload is not None and stop_reason == "end_turn":
            await _insert_message(
                db,
                conversation_id=ctx.conversation_id,
                tenant_id=ctx.tenant_id,
                role="action",
                content=action_payload,
            )

        # Roll up conversation totals.
        new_total_tokens, new_total_dollars = await _update_conversation_totals(
            db,
            conversation_id=ctx.conversation_id,
            add_tokens=(total_tokens_in + total_tokens_out),
            add_dollars=total_turn_dollars,
            new_status=(
                "budget_exhausted" if stop_reason == "budget_exhausted" else None
            ),
        )

        yield sse.usage(
            tokens_in=total_tokens_in,
            tokens_out=total_tokens_out,
            dollars=total_turn_dollars,
            conv_total_dollars=new_total_dollars,
        )
        yield sse.done(str(final_message_id), stop_reason=stop_reason)
    except Exception as e:  # noqa: BLE001
        category = _classify_llm_error(e)
        logger.exception(
            "chat_turn_failed conv=%s category=%s",
            str(ctx.conversation_id),
            category,
        )
        yield sse.error(category, "LLM turn failed.")
        yield sse.done(str(final_message_id), stop_reason="error")


# ---------------------------------------------------------------------------
# Pre-turn investigation summary fetcher (used by the API handler to
# pre-load context before invoking the loop).
# ---------------------------------------------------------------------------


async def load_investigation_summary(
    db: AsyncSession, investigation_id: UUID
) -> dict[str, Any] | None:
    """Fetch a compact case summary for the system prompt."""
    res = await get_investigation(db, investigation_id=str(investigation_id))
    if not isinstance(res.data, dict) or res.data.get("error"):
        return None
    return res.data
