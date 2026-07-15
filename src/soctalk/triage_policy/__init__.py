"""Triage-policy layer: deterministic guardrails over the agentic triage loop (issue #43).

The pattern, everywhere: the LLM proposes and a deterministic gate disposes —

    LLM node -> deterministic guard node -> { commit | override | reroute | interrupt }

The judgment stays declarative and reasoned (authorization facts + the expectedness
engine); the triage policy is procedural — what must run, in what order, which gates apply.
A triage policy never decides a SECURITY disposition from surface features; that judgment
belongs to the engine and the model. The one deterministic disposition a triage policy may
carry (``close_operational``) is a CLASS decision — "this is agent-health/ops noise,
not a security event" — and it applies only when every alert attests the class and no
security indicator is present; any indicator routes to full LLM triage instead.

Built-ins today: ``dual-use-privileged-exec`` (a ``gather_authorization_context``
required step with a pre-decision reroute, plus the post-verdict guard enforcing
contradicted→escalate and IOC→escalate with an audit record per override) and
``agent-health-operational`` (the deterministic operational close). Underneath both
sits the non-overridable safety floor (IOC / contradicted authorization / active
incident) on every auto-close plane. No tenant-authored triage policies and no sandboxed
condition language yet — the schema is the contract either way.
"""

from soctalk.triage_policy.models import TriagePolicy, TriagePolicyMatch
from soctalk.triage_policy.registry import BUILTIN_TRIAGE_POLICIES, match_triage_policy

__all__ = ["BUILTIN_TRIAGE_POLICIES", "TriagePolicy", "TriagePolicyMatch", "match_triage_policy"]
