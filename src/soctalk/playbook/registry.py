"""Built-in playbook registry (hard-coded playbooks, no tenant authoring yet).
``match_playbook`` is pure and deterministic — the resolver node calls it once per
run and writes the winner into graph state. Registry order is priority order:
security-judgment playbooks come before operational ones, so an alert that somehow
matches both gets the stricter treatment."""

from __future__ import annotations

from typing import Any

from soctalk.playbook.models import (
    CLOSE_OPERATIONAL,
    GATHER_AUTHORIZATION_CONTEXT,
    Playbook,
    PlaybookMatch,
)

# The dual-use privileged-exec class: host-auth activity (sudo/su) where the same
# observable event is routine administration under a covering record and an incident
# without one. Matches natively on sudo/su rule groups, and on any investigation that
# carries an account-track authorization context (the M1 claim/fixture seam).
PRIVILEGED_EXEC_PLAYBOOK = Playbook(
    id="dual-use-privileged-exec",
    version=1,
    applies_to=PlaybookMatch(
        rule_groups=["sudo", "su"],
        authorization_tracks=["account"],
    ),
    required_steps=[GATHER_AUTHORIZATION_CONTEXT],
    decision_modules=["authorization_engine"],
)

# The agent-health/operational class: Wazuh agent self-monitoring noise ("Agent
# event queue is flooded", buffer full/flooded) — an infrastructure or agent-health
# condition, not a security event, unless security indicators say otherwise. The
# deterministic disposition closes it as operational WITHOUT an LLM look; any veto
# in soctalk.playbook.operational (MITRE mapping, IOCs, critical severity,
# malicious signal) sends it to full triage instead. This is what makes verdicts
# on this class consistent: a pure function cannot flip between 30% and 50%.
AGENT_HEALTH_PLAYBOOK = Playbook(
    id="agent-health-operational",
    version=1,
    applies_to=PlaybookMatch(
        # Wazuh internal agent-health rules: 202 "Agent event queue is flooded"
        # and its buffer siblings carry the agent_flooding/agent_buffer groups.
        rule_groups=["agent_flooding", "agent_buffer"],
        rule_ids=["202"],
    ),
    deterministic_disposition=CLOSE_OPERATIONAL,
)

BUILTIN_PLAYBOOKS: tuple[Playbook, ...] = (
    PRIVILEGED_EXEC_PLAYBOOK,
    AGENT_HEALTH_PLAYBOOK,
)


def _alert_rule_groups(investigation: dict[str, Any]) -> set[str]:
    groups: set[str] = set()
    for alert in investigation.get("alerts") or []:
        if isinstance(alert, dict):
            groups.update(str(g).lower() for g in alert.get("rule_groups") or [])
    return groups


def _alert_rule_ids(investigation: dict[str, Any]) -> set[str]:
    ids: set[str] = set()
    for alert in investigation.get("alerts") or []:
        if isinstance(alert, dict) and alert.get("rule_id"):
            ids.add(str(alert["rule_id"]))
    return ids


def _authorization_track(investigation: dict[str, Any]) -> str | None:
    ctx = investigation.get("authorization_context")
    if not isinstance(ctx, dict):
        return None
    activity = ctx.get("activity")
    if not isinstance(activity, dict):
        return None
    track = activity.get("track")
    return str(track) if track else None


def match_playbook(investigation: dict[str, Any]) -> Playbook | None:
    """First matching built-in playbook for this investigation, or None.

    Registry order is priority order. Matching reads only the projected alert dicts
    (``rule_groups``/``rule_id``) and the authorization context's activity track —
    it selects WHICH playbook governs the run, never a security judgment (that stays
    in the engine + LLM). A matched deterministic disposition still has to clear its
    own per-alert class attestation and security-indicator vetoes before it applies.
    """
    groups = _alert_rule_groups(investigation)
    rule_ids = _alert_rule_ids(investigation)
    track = _authorization_track(investigation)
    for pb in BUILTIN_PLAYBOOKS:
        if pb.applies_to.rule_groups and groups.intersection(
            g.lower() for g in pb.applies_to.rule_groups
        ):
            return pb
        if pb.applies_to.rule_ids and rule_ids.intersection(pb.applies_to.rule_ids):
            return pb
        if track is not None and track in pb.applies_to.authorization_tracks:
            return pb
    return None
