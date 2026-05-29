"""Bridge from MCP-bound tools (Wazuh, future Cortex/MISP/TheHive) into
the chat agent's tool surface.

The verdict node already binds these MCP clients on the runs-worker side.
For the chat agent we want the same tools — analysts asking "show me
the Wazuh rule that fired on this alert" should be able to call the
mcp-server-wazuh's tools directly.

Design:
* :func:`build_mcp_chat_tools` runs at import-time (lazy via accessor)
  and rolls every currently-connected MCP server's tools into a list of
  :class:`soctalk.chat.tools.ChatTool` instances. The tool ``func``
  closes over the MCP client + tool name and calls ``client.call_tool``
  on dispatch.
* Tool names are namespaced ``wazuh.<tool>`` / ``cortex.<tool>`` so the
  agent's tool-binding doesn't collide with the read-only DB tools.
* The dispatched call result is stringified into the standard
  ``ToolResult`` shape so the rest of the agent loop is unchanged.

Important: the chat agent runs in the **soctalk-system API pod**. The
MCP clients must be bound on that process's startup — the runs-worker
binding doesn't help. See ``core/api/app_v1.py`` for the lifespan
hook that calls ``mcp.bindings.bind_clients``.
"""

from __future__ import annotations

from typing import Any

import structlog
from sqlalchemy.ext.asyncio import AsyncSession

from soctalk.chat.tools import ChatTool, ToolResult, _enforce_size
from soctalk.mcp import get_cortex_client, get_thehive_client, get_wazuh_client


logger = structlog.get_logger()


def _make_mcp_chat_tool(
    *, prefix: str, raw_tool_name: str, schema: dict[str, Any], client
) -> ChatTool:
    """Wrap one MCP tool as a ChatTool the agent loop can bind + dispatch."""

    namespaced = f"{prefix}_{raw_tool_name}"
    description = schema.get("description") or f"{prefix} tool: {raw_tool_name}"
    input_schema = schema.get("inputSchema") or schema.get("input_schema") or {
        "type": "object",
        "properties": {},
    }
    # Anthropic's tool schema is sensitive — ``additionalProperties: false`` on
    # an empty properties dict trips the validator. Strip if present.
    if isinstance(input_schema, dict) and not input_schema.get("properties"):
        input_schema.pop("additionalProperties", None)

    async def _dispatch(db: AsyncSession, **kwargs: Any) -> ToolResult:
        # ``db`` ignored — MCP tools don't need the DB session, but
        # keeping the signature uniform with read-only DB tools lets
        # the agent's existing dispatcher call them without branching.
        try:
            result = await client.call_tool(raw_tool_name, kwargs)
        except Exception as e:  # noqa: BLE001
            logger.exception(
                "chat_mcp_tool_error tool=%s err=%s",
                namespaced,
                str(e)[:200],
            )
            return ToolResult(data={"error": f"{type(e).__name__}: {e}"[:300]})
        # ``call_tool`` returns the joined text content. Try to parse
        # JSON, otherwise pass through as plain text.
        return _enforce_size(_maybe_decode(result))

    return ChatTool(
        name=namespaced,
        description=description[:500],
        schema=input_schema,
        func=_dispatch,
        # MCP servers advertise their own schemas; they don't know
        # about ``tenant_slug`` or ``target_tenant_id`` and would 400
        # if we injected them. The MCP server is the boundary that
        # owns its own multi-tenant routing (if any). Treat MCP tools
        # as globally-scoped from the chat dispatcher's perspective.
        tenant_targeted=False,
    )


def _maybe_decode(s: Any) -> Any:
    if not isinstance(s, str):
        return s
    s = s.strip()
    if not s:
        return ""
    if s.startswith("{") or s.startswith("["):
        import json

        try:
            return json.loads(s)
        except (TypeError, ValueError):
            return s
    return s


def build_mcp_chat_tools() -> list[ChatTool]:
    """Snapshot every bound MCP client into ChatTool instances.

    Called on every turn so a late-binding MCP server (e.g. tenant
    config changed mid-session) gets picked up without an API restart.
    Empty list if no MCP client is connected.
    """
    out: list[ChatTool] = []
    for prefix, getter in (
        ("wazuh", get_wazuh_client),
        ("cortex", get_cortex_client),
        ("thehive", get_thehive_client),
    ):
        client = getter()
        if client is None:
            continue
        try:
            tool_names = client.get_available_tools()
        except Exception:  # noqa: BLE001
            continue
        for raw_name in tool_names:
            schema = client.get_tool_schema(raw_name) or {}
            out.append(
                _make_mcp_chat_tool(
                    prefix=prefix,
                    raw_tool_name=raw_name,
                    schema=schema,
                    client=client,
                )
            )
    if out:
        logger.info("chat_mcp_tools_bound", count=len(out), names=[t.name for t in out])
    return out
