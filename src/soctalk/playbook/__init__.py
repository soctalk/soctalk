"""Playbook layer: deterministic guardrails over the agentic triage loop (issue #43).

The pattern, everywhere: the LLM proposes and a deterministic gate disposes —

    LLM node -> deterministic guard node -> { commit | override | reroute | interrupt }

The judgment stays declarative and reasoned (authorization facts + the expectedness
engine); the playbook is procedural — what must run, in what order, which gates apply.
A playbook never decides a SECURITY disposition from surface features; that judgment
belongs to the engine and the model. The one deterministic disposition a playbook may
carry (``close_operational``) is a CLASS decision — "this is agent-health/ops noise,
not a security event" — and it applies only when every alert attests the class and no
security indicator is present; any indicator routes to full LLM triage instead.

Built-ins today: ``dual-use-privileged-exec`` (a ``gather_authorization_context``
required step with a pre-decision reroute, plus the post-verdict guard enforcing
contradicted→escalate and IOC→escalate with an audit record per override) and
``agent-health-operational`` (the deterministic operational close). Underneath both
sits the non-overridable safety floor (IOC / contradicted authorization / active
incident) on every auto-close plane. No tenant-authored playbooks and no sandboxed
condition language yet — the schema is the contract either way.
"""

from soctalk.playbook.models import Playbook, PlaybookMatch
from soctalk.playbook.registry import BUILTIN_PLAYBOOKS, match_playbook

__all__ = ["BUILTIN_PLAYBOOKS", "Playbook", "PlaybookMatch", "match_playbook"]
