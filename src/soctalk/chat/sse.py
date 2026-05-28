"""Server-Sent Events frame serializer for the chat stream.

Event types — see ``docs/chat-interface-plan.md`` §"SSE wire format".
Each event is a single named frame with a JSON payload; the frontend
parses by ``event:`` line. Newlines inside ``data`` are split into
multiple ``data:`` lines per the SSE spec.
"""

from __future__ import annotations

import json
from typing import Any, Literal


SseEventType = Literal[
    "delta",
    "tool_call",
    "tool_result",
    "proposed_action",
    "usage",
    "done",
    "error",
    "heartbeat",
]


def sse_frame(event: SseEventType, data: dict[str, Any]) -> bytes:
    """Encode one SSE event to wire bytes."""
    payload = json.dumps(data, default=str)
    # Per SSE spec: each newline in payload must be split into its own
    # ``data:`` line. Our JSON encoder doesn't emit raw newlines so
    # this is mostly defensive.
    payload_lines = payload.split("\n")
    body = "\n".join(f"data: {line}" for line in payload_lines)
    return f"event: {event}\n{body}\n\n".encode("utf-8")


# --- type-safe constructors ---


def delta(text: str) -> bytes:
    return sse_frame("delta", {"text": text})


def tool_call(call_id: str, name: str, args: dict[str, Any]) -> bytes:
    return sse_frame("tool_call", {"call_id": call_id, "name": name, "args": args})


def tool_result(call_id: str, result: Any, truncated: bool = False) -> bytes:
    return sse_frame(
        "tool_result",
        {"call_id": call_id, "result": result, "truncated": truncated},
    )


def proposed_action(payload: dict[str, Any]) -> bytes:
    return sse_frame("proposed_action", payload)


def usage(
    tokens_in: int,
    tokens_out: int,
    dollars: float,
    conv_total_dollars: float,
) -> bytes:
    return sse_frame(
        "usage",
        {
            "tokens_in": tokens_in,
            "tokens_out": tokens_out,
            "dollars": dollars,
            "conv_total_dollars": conv_total_dollars,
        },
    )


def done(message_id: str, stop_reason: str = "end_turn") -> bytes:
    return sse_frame(
        "done", {"message_id": message_id, "stop_reason": stop_reason}
    )


def error(category: str, message: str) -> bytes:
    return sse_frame("error", {"category": category, "message": message})


def heartbeat() -> bytes:
    """Keepalive frame so reverse proxies don't close the stream."""
    return sse_frame("heartbeat", {})
