"""Playbook schema — declarative data, interpreted by the graph.

A playbook is data, not code: it names required deterministic steps and (later)
capabilities; it can never supply new code. Guardrail conditions stay OUT of the
schema in this increment — the two enforced edges (contradicted→escalate,
IOC→escalate) live in ``soctalk.playbook.guard`` as code until a second playbook
justifies a sandboxed condition language. The safety floor (``soctalk.playbook.floor``)
is enforced by the executor and is deliberately not expressible here: a playbook can
only add stricter gates, never weaken the floor.
"""

from __future__ import annotations

from pydantic import BaseModel, Field

# Required steps must name deterministic graph nodes (never supervisor actions — the
# action enum is fixed); the pre-verdict gate reroutes to them by name.
GATHER_AUTHORIZATION_CONTEXT = "gather_authorization_context"
KNOWN_STEP_NODES = frozenset({GATHER_AUTHORIZATION_CONTEXT})

# Deterministic dispositions are vetted capability names, exactly like steps: a
# playbook references one by name and can reference nothing else. Resolution of an
# unknown name fails closed — to FULL triage, never to a close (the safe direction
# for a close-shaped capability).
CLOSE_OPERATIONAL = "close_operational"
KNOWN_DISPOSITIONS = frozenset({CLOSE_OPERATIONAL})


class PlaybookMatch(BaseModel):
    """Alert-matching rules. Criteria are OR'd: the playbook applies when ANY listed
    criterion matches (each criterion is itself an any-of over its values)."""

    rule_groups: list[str] = Field(default_factory=list)
    rule_ids: list[str] = Field(default_factory=list)
    # Match when the investigation carries an authorization context whose activity
    # track is listed — the definitive marker of the dual-use class this layer serves.
    authorization_tracks: list[str] = Field(default_factory=list)


class Playbook(BaseModel):
    """One procedural playbook: which alerts it owns and what must run before VERDICT."""

    id: str
    version: int = 1
    tenant: str = "*"
    applies_to: PlaybookMatch = Field(default_factory=PlaybookMatch)
    # Deterministic node names that must have run before VERDICT is legal.
    required_steps: list[str] = Field(default_factory=list)
    # Vetted decision modules the guard consults (capability names; only the
    # authorization engine exists today).
    decision_modules: list[str] = Field(default_factory=list)
    # A KNOWN_DISPOSITIONS capability applied INSTEAD of LLM triage when no
    # security-indicator veto fires (see soctalk.playbook.operational). The class
    # decision is deterministic; the model is invoked only for the ambiguous rest.
    deterministic_disposition: str | None = None
