"""M3 ASK_AUTHORIZATION: detection + answer-adapter unit tests (no DB).

The load-bearing property (Codex pre-implementation review): the detector must ask ONLY when
authorization is truly ``absent``, never when it is ``contradicted`` (a stale/expired/wrong-scope
grant on file). Asking there and saving a fact would paper over the contradiction the floor vetoes.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime

os.environ.setdefault("SOCTALK_JWT_SIGNING_KEY", "test-signing-key-32-bytes-plaintext")

from soctalk.authorization.question import (  # noqa: E402
    authorization_question_for,
    grant_from_activity,
)
from soctalk.models.authorization import (  # noqa: E402
    AuthorizationActivity,
    AuthorizationContext,
    AuthorizationEntityKind,
    AuthorizationSourceType,
    AuthorizationTrack,
    ChangeKind,
    CompromiseStatus,
    EntityContextFact,
    FactScope,
    GrantClass,
    GrantFact,
)

_T = datetime(2026, 7, 1, 3, 0, tzinfo=UTC)
_EXPIRY = datetime(2026, 8, 1, tzinfo=UTC)


def _acct() -> AuthorizationActivity:
    return AuthorizationActivity(
        track="account", host="web01", account="deploy", action="ssh", time=_T
    )


def _inv(facts: list, enrichments: list | None = None, misp: dict | None = None) -> dict:
    ctx = AuthorizationContext(activity=_acct(), facts=facts)
    inv = {"authorization_context": ctx.model_dump(mode="json"), "enrichments": enrichments or []}
    if misp is not None:
        inv["misp_context"] = misp
    return inv


def _ticket(target: str, valid_until: datetime, action: str = "ssh") -> dict:
    return GrantFact(
        id=f"T-{target}",
        track=AuthorizationTrack.ACCOUNT,
        scope=FactScope(subject="deploy", target=target, action=action),
        grant_class=GrantClass.CHANGE_TICKET,
        valid_until=valid_until,
    ).model_dump(mode="json")


# --- detection: the absent-vs-contradicted line ---


def test_absent_authorization_asks():
    q = authorization_question_for(_inv([]), disposition="needs_more_info")
    assert q is not None
    assert q.track == AuthorizationTrack.ACCOUNT
    assert q.proposed_scope.subject == "deploy"
    assert q.proposed_scope.target == "web01"
    assert q.proposed_scope.action == "ssh"
    assert "deploy" in q.prompt and "web01" in q.prompt


def test_non_covering_grant_is_contradicted_not_absent():
    # a grant for the WRONG host is on file — contradicted, must NOT ask
    inv = _inv([_ticket("OTHER-HOST", datetime(2027, 1, 1, tzinfo=UTC))])
    assert authorization_question_for(inv, disposition="needs_more_info") is None


def test_expired_covering_grant_is_contradicted_not_absent():
    inv = _inv([_ticket("web01", datetime(2020, 1, 1, tzinfo=UTC))])
    assert authorization_question_for(inv, disposition="needs_more_info") is None


def test_covering_grant_does_not_ask():
    inv = _inv([_ticket("web01", datetime(2027, 1, 1, tzinfo=UTC))])
    assert authorization_question_for(inv, disposition="needs_more_info") is None


def test_malicious_signal_never_asks():
    assert (
        authorization_question_for(
            _inv([], enrichments=[{"verdict": "malicious"}]), disposition="needs_more_info"
        )
        is None
    )
    assert (
        authorization_question_for(
            _inv([], misp={"matches": [{"value": "1.2.3.4"}]}), disposition="needs_more_info"
        )
        is None
    )


def test_only_needs_more_info_asks():
    for d in ("escalate", "close", "close_fp", ""):
        assert authorization_question_for(_inv([]), disposition=d) is None


def test_compromised_actor_does_not_ask():
    # A compromised-account entity fact makes actor_genuine False. The class is still ``absent``
    # (an entity record, no grant), but asserting authorization cannot fix a compromised actor,
    # so the detector must not ask.
    compromised = EntityContextFact(
        id="ENT-U0",
        track=AuthorizationTrack.ACCOUNT,
        entity_type=AuthorizationEntityKind.ACCOUNT,
        name="deploy",
        compromise_status=CompromiseStatus.COMPROMISED,
        trust=80,
    ).model_dump(mode="json")
    inv = _inv([compromised])
    assert authorization_question_for(inv, disposition="needs_more_info") is None


def test_no_authorization_context_no_question():
    assert authorization_question_for({"enrichments": []}, disposition="needs_more_info") is None


# --- answer adapter: scope + provenance + guardrail-shaped fields ---


def test_grant_from_activity_account_scope_and_stamp():
    g = grant_from_activity(_acct(), valid_until=_EXPIRY, created_by="analyst-1")
    assert isinstance(g, GrantFact)
    assert g.grant_class == GrantClass.CHANGE_TICKET
    assert g.source_type == AuthorizationSourceType.ANALYST_ASSERTED
    assert g.trust == 60
    assert g.scope.subject == "deploy" and g.scope.target == "web01" and g.scope.action == "ssh"
    assert g.valid_until == _EXPIRY  # expiry is mandatory and preserved
    assert g.created_by == "analyst-1"
    assert not g.cab_required


def test_grant_from_activity_fim_scope():
    fim = AuthorizationActivity(
        track="fim", path="/etc/passwd", change_type=ChangeKind.MODIFY, time=_T
    )
    g = grant_from_activity(fim, valid_until=_EXPIRY)
    assert g.track == AuthorizationTrack.FIM
    assert g.scope.target == "/etc/passwd"
    assert g.scope.change_type == ChangeKind.MODIFY


def test_grant_from_activity_scope_override_narrows():
    narrow = FactScope(subject="deploy", target="web01", action="ssh")
    g = grant_from_activity(_acct(), valid_until=_EXPIRY, scope=narrow)
    assert g.scope == narrow


def test_saved_grant_makes_next_activity_covered():
    # ask-once-remember at the unit level: the fact the answer mints covers the same activity,
    # so a subsequent evaluation no longer reports absent -> no repeat question.
    g = grant_from_activity(_acct(), valid_until=_EXPIRY)
    inv = _inv([g.model_dump(mode="json")])
    assert authorization_question_for(inv, disposition="needs_more_info") is None
