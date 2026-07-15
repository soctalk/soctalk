"""Pre-decision gating: required steps and the playbook's legal action set (#43/#45).

Pure functions over graph state, consumed by the supervisor's routing edge (post-call
defense in depth) and by the supervisor node itself (pre-call schema narrowing — an
illegal action can't even be sampled).

Phases are deterministic, never LLM-driven: a run is in the ``triage`` phase until the
playbook's required deterministic steps have all run, then in ``decide``. VERDICT
belongs in a triage legal set even when the phase's purpose is evidence-gathering —
proposing VERDICT is what triggers the required-step reroute; the gate, not the
model, decides whether it proceeds.
"""

from __future__ import annotations

from typing import Any, Literal

import structlog

from soctalk.models.enums import SupervisorAction
from soctalk.playbook.models import KNOWN_STEP_NODES

logger = structlog.get_logger()

PHASE_TRIAGE = "triage"
PHASE_DECIDE = "decide"

_VALID_ACTIONS = {a.value for a in SupervisorAction}


def missing_required_steps(state: dict[str, Any]) -> list[str]:
    """Playbook-required deterministic steps that have not run yet (pure).

    Only step names the graph actually has nodes for count — an unknown name in a
    playbook is logged and skipped rather than deadlocking the run (there is nowhere
    to route to, and the post-verdict guard still enforces the floor edges).
    """
    playbook = state.get("playbook") or {}
    required = playbook.get("required_steps") or []
    done = set(state.get("playbook_steps_run") or [])
    missing = []
    for step in required:
        if step in done:
            continue
        if step not in KNOWN_STEP_NODES:
            logger.warning(
                "playbook_unknown_required_step",
                playbook=playbook.get("id"),
                step=step,
            )
            continue
        missing.append(step)
    return missing


def playbook_phase(state: dict[str, Any]) -> Literal["triage", "decide"]:
    """``triage`` until every required step has run, then ``decide``. Deterministic
    from playbook state — never from the LLM-written ``current_phase``."""
    return PHASE_TRIAGE if missing_required_steps(state) else PHASE_DECIDE


def legal_actions_for(state: dict[str, Any]) -> frozenset[str] | None:
    """The supervisor actions the active playbook allows in the current phase,
    or None when unconstrained (no playbook, no ``legal_actions``, or the phase
    isn't listed). Unknown action names in playbook data are dropped with a
    warning — and if that leaves an empty set, the constraint is VOID (None):
    an authoring error must degrade to full triage, never to a wedged run.
    """
    playbook = state.get("playbook") or {}
    legal_map = playbook.get("legal_actions") or {}
    if not legal_map:
        return None
    actions = legal_map.get(playbook_phase(state))
    if not actions:
        return None
    valid = frozenset(str(a).upper() for a in actions) & frozenset(_VALID_ACTIONS)
    dropped = {str(a).upper() for a in actions} - valid
    if dropped:
        logger.warning(
            "playbook_unknown_legal_actions",
            playbook=playbook.get("id"),
            dropped=sorted(dropped),
        )
    return valid or None
