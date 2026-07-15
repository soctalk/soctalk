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

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from soctalk.playbook.conditions import validate_condition

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


# Raise-only ranking for guardrail overrides (#44): an override may only move a
# decision UP this ladder. Suppression (anything -> close) is inexpressible.
DECISION_RANK = {"close": 0, "needs_more_info": 1, "escalate": 2}


class Guardrail(BaseModel):
    """One declarative guardrail: a sandboxed condition over the state contract
    plus an effect. Conditions are the ONLY logic an author writes (#43); the
    operators and referencable fields live in ``soctalk.playbook.conditions``.
    Effects can only raise suspicion: ``override`` moves the decision up the
    close < needs_more_info < escalate ladder; ``interrupt`` keeps the draft and
    routes to human sign-off. (``cap``/``veto`` from the #43 vocabulary are
    reserved; the executor floor owns hard vetoes.)"""

    model_config = ConfigDict(extra="forbid")

    when: dict[str, Any]
    effect: Literal["override", "interrupt"]
    to: Literal["escalate", "needs_more_info", "human_review"]
    reason: str = Field(min_length=1, max_length=512)

    @model_validator(mode="after")
    def _legality(self) -> Guardrail:
        validate_condition(self.when)  # author-time, fail closed
        if self.effect == "interrupt" and self.to != "human_review":
            raise ValueError("interrupt guardrails route to human_review only")
        if self.effect == "override" and self.to == "human_review":
            raise ValueError("override guardrails target a disposition, not review")
        return self


class PlaybookMatch(BaseModel):
    """Alert-matching rules. Criteria are OR'd: the playbook applies when ANY listed
    criterion matches (each criterion is itself an any-of over its values)."""

    model_config = ConfigDict(extra="forbid")

    rule_groups: list[str] = Field(default_factory=list)
    rule_ids: list[str] = Field(default_factory=list)
    # Match when the investigation carries an authorization context whose activity
    # track is listed — the definitive marker of the dual-use class this layer serves.
    authorization_tracks: list[str] = Field(default_factory=list)


class Playbook(BaseModel):
    """One procedural playbook: which alerts it owns and what must run before VERDICT.

    ``extra="forbid"``: a typo'd field in an authored file rejects the whole file at
    load (fail closed) instead of silently doing nothing."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=1, max_length=128)
    version: int = 1
    tenant: str = "*"
    # active playbooks govern; shadow playbooks are matched and evaluated for
    # audit only — decisions logged, nothing enforced (#44: shadow-run before
    # activation). File-loaded playbooks default to shadow.
    status: Literal["active", "shadow"] = "active"
    # Registry priority: lower wins on a multi-match (built-ins use 10/50;
    # file-loaded playbooks default below them).
    priority: int = 100
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
    # Legal supervisor actions per phase ("triage" until required_steps ran, then
    # "decide"), from the fixed SupervisorAction enum only (#45). Enforced twice:
    # the supervisor's structured-output enum is narrowed BEFORE the call, and the
    # routing gate remaps an illegal action after it. An unlisted phase is
    # unconstrained. Include VERDICT in a triage set — proposing it is what
    # triggers the required-step reroute.
    legal_actions: dict[str, list[str]] = Field(default_factory=dict)
    # A committing LLM close whose activity's asset carries one of these data
    # classifications is INTERRUPTED for human sign-off instead (#45): the draft
    # stays intact, the case routes to human review. The #43 worked example's
    # "a close on a PCI asset requires human sign-off", as data.
    close_signoff_data_classes: list[str] = Field(default_factory=list)
    # Declarative guardrails (#44), evaluated by the post-verdict guard AFTER the
    # non-overridable code edges (IOC, contradicted authorization) — additive
    # only: the effective set is floor ∪ playbook, and nothing here can weaken
    # the floor. First matching guardrail wins.
    guardrails: list[Guardrail] = Field(default_factory=list, max_length=16)
