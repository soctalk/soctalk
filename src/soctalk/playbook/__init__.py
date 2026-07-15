"""Playbook layer: deterministic guardrails over the agentic triage loop (issue #43).

The pattern, everywhere: the LLM proposes and a deterministic gate disposes —

    LLM node -> deterministic guard node -> { commit | override | reroute | interrupt }

The judgment stays declarative and reasoned (authorization facts + the expectedness
engine); the playbook is procedural — what must run, in what order, which gates apply.
A playbook never decides a disposition from surface features; it wraps the engine.

First increment (see the issue for the full design): one built-in playbook for the
dual-use privileged-exec class, a ``gather_authorization_context`` required step with a
pre-verdict reroute, a post-verdict guard enforcing contradicted→escalate and
IOC→escalate with an audit record per override, and a non-overridable safety floor
(IOC / active incident) on both auto-close planes. No tenant registry and no condition
language yet — those land when a second playbook justifies them.
"""

from soctalk.playbook.models import Playbook, PlaybookMatch
from soctalk.playbook.registry import BUILTIN_PLAYBOOKS, match_playbook

__all__ = ["BUILTIN_PLAYBOOKS", "Playbook", "PlaybookMatch", "match_playbook"]
