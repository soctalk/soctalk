"""AI SOC analyst chat — backend package.

See ``docs/chat-interface-plan.md`` for the design. Public entry points:

* ``soctalk.chat.agent.run_turn`` — LangGraph-driven assistant turn,
  yields SSE events as it streams.
* ``soctalk.chat.tools.AVAILABLE_TOOLS`` — read-only DB tool surface.
* ``soctalk.chat.actions.dispatch_confirm`` — server-side confirm
  flow for proposed-action messages.
"""

__all__ = ()
