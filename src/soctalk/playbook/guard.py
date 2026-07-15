"""Post-verdict guard: pure functions that decide whether the LLM's verdict commits.

The guard fires only on deterministic edges; the ambiguous middle passes through:

- ``authz.class == contradicted`` caps a close at escalate — authorization records ARE
  present but fail to cover (expired, out-of-window, wrong scope, CAB-unapproved) or a
  prohibition forbids the action. The mismatch is the finding; a human responder is the
  right verifier. This is the engine's judgment enforced, not a keyword branch.
- malicious signal caps a close at escalate — the "authorization never overrides an
  IOC" sentence in the verdict prompt, promoted from instruction to enforcement.

``absent`` (no record of the right kind) deliberately does NOT override in this
increment: the verdict prompt already steers absent-evidence cases to needs_more_info
and the model is free to close on non-authorization grounds. Everything here is
side-effect free and unit-tested case-for-case, same discipline as the expectedness
parity test.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any, Literal

from pydantic import BaseModel

from soctalk.authorization.engine import (
    evaluate_authorization,
    resolved_entity,
    select_facts,
)
from soctalk.models.authorization import (
    AuthorizationComponents,
    AuthorizationContext,
    AuthorizationEntityKind,
    AuthorizationTrack,
    GrantFact,
)

AuthzClass = Literal["covered", "contradicted", "absent"]

GUARDRAIL_AUTHZ_CONTRADICTED = "authorization_contradicted_close"
GUARDRAIL_IOC_OVER_CLOSE = "ioc_over_close"
# Sign-off scope note (#45): this rule governs LLM-close COMMITS in the graph
# plane, where asset data classification is knowable (authorization facts). The
# ingest plane cannot apply it — no facts exist at ingest — so a memoized close
# cached BEFORE the rule existed can still replay for a sensitive shape until
# its TTL. Forward-protected: an interrupted close memoizes as ``escalate``, so
# post-rule recurrences of a sign-off shape always reach review. Full ingest
# coverage arrives with shape provenance / CMDB classification (M2 Phase b).
GUARDRAIL_SIGNOFF_CLOSE = "sensitive_asset_close_signoff"


class GuardOverride(BaseModel):
    """One fired guardrail — the audit record of an override or interrupt."""

    guardrail: str
    effect: Literal["override", "interrupt"] = "override"
    from_decision: str
    to_decision: str
    reason: str


class GuardResult(BaseModel):
    final_decision: str
    authz_class: AuthzClass | None = None
    components: AuthorizationComponents | None = None
    overrides: list[GuardOverride] = []
    # interrupt (#45): the draft decision stands, but a human signs off before it
    # takes effect — distinct from an override in both routing and audit.
    interrupted: bool = False

    @property
    def overridden(self) -> bool:
        return any(o.effect == "override" for o in self.overrides)


def derive_authz_class(
    context: AuthorizationContext | None,
) -> tuple[AuthzClass, AuthorizationComponents | None]:
    """Classify the engine components into the guard vocabulary (issue #43):

    - ``covered``: ``in_scope`` and ``policy_allowed`` hold — a single record fully
      covers the activity and no prohibition forbids it.
    - ``contradicted``: records are present but do not cover (grants exist, none
      covers) OR a high-priority prohibition forbids the action.
    - ``absent``: no record of the right kind exists — never treated as approval,
      but also not the guard's edge to force.

    "Records present" is judged over the facts the ENGINE would select (same track,
    same tenant, not superseded) — a wrong-track, foreign-tenant, or revoked grant is
    not a record on file for this activity and must not manufacture a contradiction.
    """
    if context is None:
        return "absent", None
    selected = select_facts(context.facts, context.activity.track, context.tenant)
    if not selected:
        return "absent", None
    components = evaluate_authorization(context.activity, context.facts, context.tenant)
    if not components.policy_allowed:
        return "contradicted", components
    if components.in_scope:
        return "covered", components
    if any(isinstance(f, GrantFact) for f in selected):
        return "contradicted", components
    return "absent", components


def asset_data_classification(context: AuthorizationContext | None) -> str | None:
    """The trust-resolved data classification of the activity's asset, or None
    when unknown (no context, FIM track, or no asset record). Uses the engine's
    own selection + resolution so the sign-off rule and the evaluation can never
    disagree about which record speaks for the asset."""
    if context is None or context.activity.track != AuthorizationTrack.ACCOUNT:
        return None
    if not context.activity.host:
        return None
    selected = select_facts(context.facts, context.activity.track, context.tenant)
    asset = resolved_entity(selected, AuthorizationEntityKind.ASSET, context.activity.host)
    if asset is None or asset.data_classification is None:
        return None
    return str(asset.data_classification).lower()


def evaluate_guard(
    *,
    verdict_decision: str,
    context: AuthorizationContext | None,
    malicious_signal: bool,
    close_signoff_data_classes: Sequence[str] = (),
) -> GuardResult:
    """The guard's whole decision, as a pure function.

    Only a ``close`` draft is ever touched; escalate and needs_more_info always commit
    (the guard only ever RAISES suspicion, mirroring the engine, which only ever lowers
    it by finding covering evidence). The IOC edge is checked first — the floor always
    outranks authorization reasoning. A close that would otherwise COMMIT is
    interrupted for human sign-off when the activity's asset carries one of the
    playbook's ``close_signoff_data_classes`` (#45): the draft stays intact, a human
    disposes — even a fully covered close on such an asset is not automatic.
    """
    authz_class, components = derive_authz_class(context)
    overrides: list[GuardOverride] = []
    interrupted = False
    if verdict_decision == "close" and malicious_signal:
        overrides.append(
            GuardOverride(
                guardrail=GUARDRAIL_IOC_OVER_CLOSE,
                from_decision="close",
                to_decision="escalate",
                reason=(
                    "malicious indicators present — authorization/benign evidence "
                    "never overrides an IOC"
                ),
            )
        )
    elif verdict_decision == "close" and authz_class == "contradicted":
        overrides.append(
            GuardOverride(
                guardrail=GUARDRAIL_AUTHZ_CONTRADICTED,
                from_decision="close",
                to_decision="escalate",
                reason=(
                    "authorization records present but do not cover this activity — "
                    "acting outside the terms of an authorization is the finding"
                ),
            )
        )
    elif verdict_decision == "close" and close_signoff_data_classes:
        data_class = asset_data_classification(context)
        if data_class is not None and data_class in {
            str(c).lower() for c in close_signoff_data_classes
        }:
            interrupted = True
            overrides.append(
                GuardOverride(
                    guardrail=GUARDRAIL_SIGNOFF_CLOSE,
                    effect="interrupt",
                    from_decision="close",
                    to_decision="human_review",
                    reason=(
                        f"close on a {data_class}-classified asset requires human "
                        "sign-off — the draft stands, a human disposes"
                    ),
                )
            )
    return GuardResult(
        final_decision=(
            "escalate" if any(o.effect == "override" for o in overrides)
            else verdict_decision
        ),
        authz_class=authz_class,
        components=components,
        overrides=overrides,
        interrupted=interrupted,
    )


def decision_value(raw: Any) -> str:
    """A verdict/supervisor decision as a plain lowercase string. Pydantic
    ``model_dump()`` keeps (str, Enum) instances in the state dict, so a naive
    ``str(v)`` yields ``"VerdictDecision.close"``."""
    if hasattr(raw, "value"):
        return str(raw.value).lower()
    return str(raw or "").lower()
