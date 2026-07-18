"""ASK_AUTHORIZATION: the human-in-the-loop authorization question and its answer (epic M3).

When triage cannot decide because authorization evidence is *absent* (not contradicted, not
malicious), the engine's four components come back not-expected but the activity is otherwise
benign. Rather than a generic needs_more_info, we raise a typed authorization question to the
analyst: "was this activity authorized?" The analyst answers explicitly, and an affirmative
answer becomes a durable ``analyst_asserted`` grant with a scope and an expiry, so the same
question is not asked again (ask-once, remember).

Two guardrails from the epic (handoff §8) are load-bearing here:
- (§1) absence is needs_more_info, never auto-close; the question only fires on needs_more_info.
- (§2) authorization never overrides a malicious signal; the question never fires when the
  investigation carries a malicious enrichment or an IOC/MISP hit.
- (§4) memory is never auto-learned from a close/reject. A fact is minted ONLY by the explicit
  affirmative answer with scope + expiry (``grant_from_activity`` is called only there).
"""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import uuid4

from pydantic import BaseModel

from soctalk.authorization.engine import derive_authz_class
from soctalk.authorization.render import has_malicious_signal, parse_authorization_context
from soctalk.models.authorization import (
    TRUST_TIER,
    AuthorizationActivity,
    AuthorizationSourceType,
    AuthorizationTrack,
    FactScope,
    GrantClass,
    GrantFact,
    GrantStatus,
)

_ANALYST_TRUST = TRUST_TIER[AuthorizationSourceType.ANALYST_ASSERTED]


class AuthorizationQuestion(BaseModel):
    """A typed authorization question surfaced to the analyst on a pending review.

    ``proposed_scope`` is the narrowest fact scope that would cover exactly this activity — the
    default the answer form pre-fills. ``prompt`` is the human-readable question.
    """

    track: AuthorizationTrack
    activity: AuthorizationActivity
    proposed_scope: FactScope
    prompt: str


def _proposed_scope(activity: AuthorizationActivity) -> FactScope:
    """The narrowest scope covering exactly this activity (never a wildcard)."""
    if activity.track == AuthorizationTrack.ACCOUNT:
        return FactScope(subject=activity.account, target=activity.host, action=activity.action)
    return FactScope(target=activity.path, change_type=activity.change_type)


def _prompt(activity: AuthorizationActivity) -> str:
    if activity.track == AuthorizationTrack.ACCOUNT:
        return (
            f"Was account '{activity.account}' performing '{activity.action}' on host "
            f"'{activity.host}' authorized?"
        )
    change = getattr(activity.change_type, "value", activity.change_type)
    return f"Was a '{change}' change to '{activity.path}' authorized?"


def authorization_question_for(
    investigation: dict[str, Any], *, disposition: str
) -> AuthorizationQuestion | None:
    """Return an authorization question when the case is unresolved *because authorization is
    absent*, or None otherwise.

    Fires iff: the disposition is ``needs_more_info`` (§1); there is no malicious signal (§2);
    the canonical classifier reports the authorization state is ``absent`` (no record of the
    right kind on file — NOT merely no covering grant); and the actor is genuine.

    The ``absent`` gate is the same ``derive_authz_class`` the safety floor and the triage-policy
    guard read, so the detector can never disagree with them. This is the load-bearing
    distinction: a stale, expired, or wrong-target grant is ``contradicted``, not ``absent`` —
    we must not ask "was this authorized" there, because an affirmative answer would mint a fresh
    grant that papers over exactly the contradiction the floor exists to veto.
    """
    if disposition != "needs_more_info":
        return None
    ctx = parse_authorization_context(investigation)
    if ctx is None:
        return None
    if has_malicious_signal(investigation):
        return None
    authz_class, components = derive_authz_class(ctx)
    if authz_class != "absent":
        return None
    # A compromised actor is a contradiction the analyst cannot fix by asserting authorization.
    if components is not None and not components.actor_genuine:
        return None
    return AuthorizationQuestion(
        track=ctx.activity.track,
        activity=ctx.activity,
        proposed_scope=_proposed_scope(ctx.activity),
        prompt=_prompt(ctx.activity),
    )


def grant_from_activity(
    activity: AuthorizationActivity,
    *,
    valid_until: datetime,
    scope: FactScope | None = None,
    fact_id: str | None = None,
    created_by: str = "",
) -> GrantFact:
    """Build the durable ``analyst_asserted`` grant that answers an authorization question.

    Called ONLY on an explicit affirmative answer (§4 — never from a close/reject). The grant is
    a ``change_ticket`` so the model enforces the mandatory expiry (``valid_until``). Scope
    defaults to the narrowest tuple that covers exactly this activity; a caller may pass an
    explicit ``scope`` to narrow it further, never to wildcard it.
    """
    resolved_scope = scope if scope is not None else _proposed_scope(activity)
    return GrantFact(
        id=fact_id or f"analyst:{uuid4()}",
        track=activity.track,
        scope=resolved_scope,
        grant_class=GrantClass.CHANGE_TICKET,
        status=GrantStatus.APPROVED,
        cab_required=False,
        cab_approved=True,
        source_type=AuthorizationSourceType.ANALYST_ASSERTED,
        trust=_ANALYST_TRUST,
        created_by=created_by,
        valid_until=valid_until,
    )
