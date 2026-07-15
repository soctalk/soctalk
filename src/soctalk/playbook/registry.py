"""Built-in playbook registry (first increment: one hard-coded playbook, no tenant
authoring). ``match_playbook`` is pure and deterministic — the resolver node calls it
once per run and writes the winner into graph state."""

from __future__ import annotations

from typing import Any

from soctalk.playbook.models import (
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

BUILTIN_PLAYBOOKS: tuple[Playbook, ...] = (PRIVILEGED_EXEC_PLAYBOOK,)


def _alert_rule_groups(investigation: dict[str, Any]) -> set[str]:
    groups: set[str] = set()
    for alert in investigation.get("alerts") or []:
        if isinstance(alert, dict):
            groups.update(str(g).lower() for g in alert.get("rule_groups") or [])
    return groups


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
    (``rule_groups``) and the authorization context's activity track — surface routing
    only, never a disposition (the judgment stays in the engine + LLM).
    """
    groups = _alert_rule_groups(investigation)
    track = _authorization_track(investigation)
    for pb in BUILTIN_PLAYBOOKS:
        if pb.applies_to.rule_groups and groups.intersection(
            g.lower() for g in pb.applies_to.rule_groups
        ):
            return pb
        if track is not None and track in pb.applies_to.authorization_tracks:
            return pb
    return None
