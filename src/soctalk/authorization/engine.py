"""Deterministic authorization evaluator: activity + facts -> the four expectedness components.

This is a faithful port of the soctalk-goldens answer keys (expectedness.py account track,
fim.py FIM track), rewritten over the AuthorizationFact contract. The file-fed parity test
(tests/v1/test_authorization_parity.py) asserts it reproduces the benchmark's gold components
case-for-case; the asymmetries below are source-faithful and must NOT be "cleaned up":

  - account sanction checks CAB (approved AND cab-approved-if-required); FIM sanction checks
    status=="approved" only.
  - single-covering-record rule: in_scope needs ONE grant satisfying subject/target/action
    (+change_type)/window/validity/CAB together — partial grants are never OR'd.
  - freeze divergence: an account freeze gates change tickets only (baselines and routine
    sightings pass); a FIM freeze gates ALL coverage including baselines, and EVERY active
    freeze must be excepted by a covering change ticket.
  - tenancy is enforced on the account track only (org linkage is symmetric; an unknown
    account has owner_org "" which matches an unowned asset).

Guardrail framing (§8): this engine only ever LOWERS suspicion by finding covering evidence;
absence of facts yields escalate-shaped components, never a close. It carries no malicious-signal
override — correlation/IOC handling stays upstream and always wins.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from datetime import datetime, time
from enum import Enum
from fnmatch import fnmatch
from typing import Literal

from soctalk.models.authorization import (
    AccountKind,
    AuthorizationActivity,
    AuthorizationComponents,
    AuthorizationContext,
    AuthorizationEntityKind,
    AuthorizationFact,
    AuthorizationTrack,
    ChangeFreezeFact,
    ChangeKind,
    EntityContextFact,
    GrantClass,
    GrantFact,
    PolicyPriority,
    ProhibitionFact,
)

ROUTINE_MIN = 5  # sightings at/above this count (and not IOC) count as established routine

_COMPROMISED = ("compromised", "contained")

# Source-model defaults used when an entity fact is absent or an attribute is unset.
_ASSET_DEFAULTS: dict[str, str] = {
    "environment": "prod",
    "criticality": "medium",
    "data_classification": "none",
    "owner_org": "",
    "compromise_status": "clean",
}
_WATCHED_PATH_DEFAULTS: dict[str, str] = {
    "config_class": "app",
    "environment": "prod",
    "criticality": "medium",
    "owner_org": "",
    "compromise_status": "clean",
}

# Entity conflict tiebreak field orders per entity type (see entity_resolution_key).
_ASSET_KEY_ORDER = (
    ("name", None),
    ("environment", "prod"),
    ("criticality", "medium"),
    ("owner_org", ""),
    ("custodian_account", ""),
    ("data_classification", "none"),
    ("compromise_status", "clean"),
)
_WATCHED_PATH_KEY_ORDER = (
    ("name", None),
    ("config_class", "app"),
    ("criticality", "medium"),
    ("environment", "prod"),
    ("owner_org", ""),
    ("approver", ""),
    ("compromise_status", "clean"),
)
_ACCOUNT_KEY_ORDER = (
    ("name", None),
    ("account_type", ""),
    ("owner_org", ""),
    ("privileged", False),
    ("break_glass", False),
    ("service_owner", ""),
    ("on_call", True),
)
_ORG_KEY_ORDER: tuple[tuple[str, object], ...] = (
    ("name", None),
    ("linked_orgs", ()),
)
_KEY_ORDERS = {
    AuthorizationEntityKind.ASSET: _ASSET_KEY_ORDER,
    AuthorizationEntityKind.WATCHED_PATH: _WATCHED_PATH_KEY_ORDER,
    AuthorizationEntityKind.ACCOUNT: _ACCOUNT_KEY_ORDER,
    AuthorizationEntityKind.ORG: _ORG_KEY_ORDER,
}


def entity_resolution_key(fact: EntityContextFact) -> str:
    """Deterministic tiebreak for equal-trust entity records: canonical JSON of the ENTITY
    attributes only, in source-model field order, defaults filled. Envelope fields (id,
    provenance, ...) must never influence which record wins."""
    order = _KEY_ORDERS[fact.entity_type]
    out: dict[str, object] = {}
    for field, default in order:
        if field == "name":
            out[field] = fact.name
            continue
        value = getattr(fact, field, None)
        if isinstance(value, Enum):
            value = value.value
        out[field] = default if value is None else value
    out["trust"] = fact.trust
    return json.dumps(out, separators=(",", ":"))


def _select(
    facts: Sequence[AuthorizationFact], track: AuthorizationTrack, tenant: str | None
) -> list[AuthorizationFact]:
    """Track + tenant + lifecycle gate, all fail-closed:

    - a tenant-scoped evaluation uses ONLY facts stamped with that exact tenant — an
      unscoped (tenant=None) or foreign-tenant grant must never authorize a tenant's
      activity. Untenanted evaluation (tenant=None: benchmark parity, single-tenant
      fixtures) applies no tenant gate.
    - superseded facts are dead: a revoked/replaced record neither authorizes nor
      blocks nor resolves an entity (the superseding record speaks for itself).
    """
    return [
        f
        for f in facts
        if f.track == track
        and (tenant is None or f.tenant == tenant)
        and f.superseded_by is None
    ]


def _grants(facts: Sequence[AuthorizationFact]) -> list[GrantFact]:
    return [f for f in facts if isinstance(f, GrantFact)]


def _prohibitions(facts: Sequence[AuthorizationFact]) -> list[ProhibitionFact]:
    return [f for f in facts if isinstance(f, ProhibitionFact)]


def _freezes(facts: Sequence[AuthorizationFact]) -> list[ChangeFreezeFact]:
    return [f for f in facts if isinstance(f, ChangeFreezeFact)]


def _resolved_entity(
    facts: Sequence[AuthorizationFact], entity_type: AuthorizationEntityKind, name: str
) -> EntityContextFact | None:
    matches = [
        f
        for f in facts
        if isinstance(f, EntityContextFact) and f.entity_type == entity_type and f.name == name
    ]
    if not matches:
        return None
    return max(matches, key=lambda f: (f.trust, entity_resolution_key(f)))


def _account_fact(facts: Sequence[AuthorizationFact], name: str) -> EntityContextFact | None:
    """Highest-trust account record with a known type (contract: entity conflicts resolve
    by trust). Compromise-only stubs (account_type None) never shadow a real record, and a
    compromise flag is handled separately by _account_compromised so it cannot be
    trust-resolved away."""
    matches = [
        f
        for f in facts
        if isinstance(f, EntityContextFact)
        and f.entity_type == AuthorizationEntityKind.ACCOUNT
        and f.name == name
        and f.account_type is not None
    ]
    if not matches:
        return None
    return max(matches, key=lambda f: (f.trust, entity_resolution_key(f)))


def _account_compromised(facts: Sequence[AuthorizationFact], name: str) -> bool:
    """ANY compromise-flagged record for the subject wins — a compromise flag is never
    trust-resolved away by a cleaner record."""
    return any(
        isinstance(f, EntityContextFact)
        and f.entity_type == AuthorizationEntityKind.ACCOUNT
        and f.name == name
        and f.compromise_status in _COMPROMISED
        for f in facts
    )


def _attr(fact: EntityContextFact | None, name: str, defaults: dict[str, str]) -> str:
    """Entity attribute as its plain string value, source-model default when unset."""
    value = getattr(fact, name) if fact is not None else None
    if value is None:
        return defaults[name]
    return str(value.value) if isinstance(value, Enum) else str(value)


def _parse_hhmm(value: str) -> time:
    h, m = value.split(":")
    return time(int(h), int(m))


def _in_window(t: datetime, start: str, end: str) -> bool:
    # inclusive on both ends, seconds included (a 04:00:30 event is OUTSIDE an 04:00 window end)
    return _parse_hhmm(start) <= t.time() <= _parse_hhmm(end)


def _in_recurring_window(g: GrantFact, t: datetime) -> bool:
    w = g.scope.recurring_window
    return w is None or _in_window(t, w.start, w.end)


def _in_validity(g: GrantFact, t: datetime) -> bool:
    if g.valid_from is not None and not g.valid_from <= t:
        return False
    if g.valid_until is not None and not t <= g.valid_until:
        return False
    return True


def _grant_ok(g: GrantFact) -> bool:
    """Approved AND CAB-approved-if-required (the account-track ticket gate)."""
    return g.status.value == "approved" and (not g.cab_required or g.cab_approved)


def _org_linked(facts: Sequence[AuthorizationFact], a: str, b: str) -> bool:
    """Symmetric org linkage over the TRUST-RESOLVED org record per name — a low-trust
    org fact must not add a linkage the authoritative record doesn't carry."""
    if a == b:
        return True
    for name, other in ((a, b), (b, a)):
        org = _resolved_entity(facts, AuthorizationEntityKind.ORG, name)
        if org is not None and org.linked_orgs and other in org.linked_orgs:
            return True
    return False


# --- account track -----------------------------------------------------------------------------


def _acct_freeze_blocks(
    facts: Sequence[AuthorizationFact], asset_env: str, g: GrantFact, t: datetime
) -> bool:
    if g.freeze_exception:
        return False
    for fr in _freezes(facts):
        if asset_env in fr.freeze_scope.envs and fr.start <= t <= fr.end:
            if g.id not in fr.allowed_exception_ids:
                return True
    return False


def _acct_ticket_covers(
    facts: Sequence[AuthorizationFact],
    g: GrantFact,
    a: AuthorizationActivity,
    asset_env: str,
) -> bool:
    return (
        g.grant_class == GrantClass.CHANGE_TICKET
        and _grant_ok(g)
        and g.scope.target == a.host
        and g.scope.subject == a.account
        and g.scope.action == a.action
        and _in_recurring_window(g, a.time)
        and _in_validity(g, a.time)
        and not _acct_freeze_blocks(facts, asset_env, g, a.time)
    )


def _acct_baseline_covers(g: GrantFact, a: AuthorizationActivity) -> bool:
    return (
        g.grant_class == GrantClass.STANDING_BASELINE
        and g.scope.target == a.host
        and g.scope.subject == a.account
        and g.scope.action == a.action
        and _in_recurring_window(g, a.time)
        and _in_validity(g, a.time)
    )


def _acct_routine(g: GrantFact, a: AuthorizationActivity) -> bool:
    return (
        g.grant_class == GrantClass.ROUTINE_OBSERVATION
        and g.scope.subject == a.account
        and g.scope.target == a.host
        and g.scope.action == a.action
        and (g.seen_count or 0) >= ROUTINE_MIN
        and not g.ioc
        and _in_recurring_window(g, a.time)
        and _in_validity(g, a.time)
    )


def _acct_sanctioned(grants: Sequence[GrantFact], a: AuthorizationActivity) -> bool:
    for g in grants:
        if (
            g.grant_class == GrantClass.CHANGE_TICKET
            and _grant_ok(g)
            and g.scope.subject == a.account
            and g.scope.action == a.action
        ):
            return True  # sanction is looser than coverage: no host, no window
        if (
            g.grant_class == GrantClass.STANDING_BASELINE
            and g.scope.subject == a.account
            and g.scope.action == a.action
        ):
            return True
    return any(_acct_routine(g, a) for g in grants)


def _acct_components(
    facts: Sequence[AuthorizationFact], a: AuthorizationActivity
) -> AuthorizationComponents:
    grants = _grants(facts)
    asset = _resolved_entity(facts, AuthorizationEntityKind.ASSET, a.host or "")
    asset_env = _attr(asset, "environment", _ASSET_DEFAULTS)
    account = _account_fact(facts, a.account or "")

    covered = (
        any(_acct_ticket_covers(facts, g, a, asset_env) for g in grants)
        or any(_acct_baseline_covers(g, a) for g in grants)
        or any(_acct_routine(g, a) for g in grants)
    )
    acct_org = (account.owner_org or "") if account else ""
    asset_org = _attr(asset, "owner_org", _ASSET_DEFAULTS)
    in_scope = covered and _org_linked(facts, acct_org, asset_org)

    actor_genuine = True
    if _account_compromised(facts, a.account or ""):
        actor_genuine = False
    elif _attr(asset, "compromise_status", _ASSET_DEFAULTS) in _COMPROMISED:
        actor_genuine = False
    elif account is not None:
        privileged = bool(account.privileged)
        on_call = account.on_call if account.on_call is not None else True
        break_glass = bool(account.break_glass)
        if account.account_type == AccountKind.SERVICE and a.interactive:
            actor_genuine = False
        elif (
            account.account_type == AccountKind.HUMAN
            and privileged
            and not on_call
            and not break_glass
        ):
            actor_genuine = False

    acct_type = account.account_type if account else None
    policy_allowed = True
    for p in _prohibitions(facts):
        if (
            p.forbid_action != a.action
            or p.priority != PolicyPriority.HIGH
            or p.waiver_present
        ):
            continue
        if p.forbid_account_type is not None and acct_type != p.forbid_account_type:
            continue
        if p.applies_to.env is not None and asset_env not in p.applies_to.env:
            continue
        if (
            p.applies_to.criticality is not None
            and _attr(asset, "criticality", _ASSET_DEFAULTS) not in p.applies_to.criticality
        ):
            continue
        if (
            p.applies_to.data_class is not None
            and _attr(asset, "data_classification", _ASSET_DEFAULTS)
            not in p.applies_to.data_class
        ):
            continue
        if (
            p.break_glass_exception
            and account is not None
            and bool(account.break_glass)
            and any(g.emergency and _acct_ticket_covers(facts, g, a, asset_env) for g in grants)
        ):
            continue  # break-glass needs a COVERING emergency change, not just any
        policy_allowed = False
        break

    return AuthorizationComponents(
        sanctioned_or_routine=_acct_sanctioned(grants, a),
        in_scope=in_scope,
        actor_genuine=actor_genuine,
        policy_allowed=policy_allowed,
    )


# --- FIM track ---------------------------------------------------------------------------------


def _fim_type_matches(g: GrantFact, change: ChangeKind | None) -> bool:
    return g.scope.change_type in (None, ChangeKind.ANY) or g.scope.change_type == change


def _fim_cr_covers(g: GrantFact, a: AuthorizationActivity) -> bool:
    """Coverage ignoring freezes; the FIM freeze gate is applied once over ALL coverage."""
    return (
        g.grant_class == GrantClass.CHANGE_TICKET
        and _grant_ok(g)
        and g.scope.target is not None
        and fnmatch(a.path or "", g.scope.target)
        and _fim_type_matches(g, a.change_type)
        and _in_recurring_window(g, a.time)
        and _in_validity(g, a.time)
    )


def _fim_baseline_covers(g: GrantFact, a: AuthorizationActivity) -> bool:
    return (
        g.grant_class == GrantClass.STANDING_BASELINE
        and g.scope.target is not None
        and fnmatch(a.path or "", g.scope.target)
        and _fim_type_matches(g, a.change_type)
        and _in_recurring_window(g, a.time)
        and _in_validity(g, a.time)
    )


def _fim_components(
    facts: Sequence[AuthorizationFact], a: AuthorizationActivity
) -> AuthorizationComponents:
    grants = _grants(facts)
    wp = _resolved_entity(facts, AuthorizationEntityKind.WATCHED_PATH, a.path or "")
    config_class = _attr(wp, "config_class", _WATCHED_PATH_DEFAULTS)

    sanctioned = False
    for g in grants:
        if g.scope.target is None or not fnmatch(a.path or "", g.scope.target):
            continue
        if not _fim_type_matches(g, a.change_type):
            continue
        # FIM sanction checks approval only — no CAB. Source-faithful asymmetry.
        if g.grant_class == GrantClass.CHANGE_TICKET and g.status.value == "approved":
            sanctioned = True
            break
        if g.grant_class == GrantClass.STANDING_BASELINE:
            sanctioned = True
            break

    covering_crs = [g for g in grants if _fim_cr_covers(g, a)]
    covered = bool(covering_crs) or any(_fim_baseline_covers(g, a) for g in grants)
    in_scope = covered
    if covered:
        for fr in _freezes(facts):
            active = config_class in fr.freeze_scope.config_classes and (
                fr.start <= a.time <= fr.end
            )
            if active and not any(
                g.freeze_exception or g.id in fr.allowed_exception_ids for g in covering_crs
            ):
                in_scope = False
                break

    actor_genuine = _attr(wp, "compromise_status", _WATCHED_PATH_DEFAULTS) not in _COMPROMISED

    policy_allowed = True
    for p in _prohibitions(facts):
        if p.priority != PolicyPriority.HIGH or p.waiver_present:
            continue
        if p.applies_to.config_class and config_class not in p.applies_to.config_class:
            continue
        change = a.change_type.value if a.change_type is not None else ""
        if p.forbid_change_type is not None and change not in p.forbid_change_type:
            continue
        if p.break_glass_exception and any(g.emergency and _fim_cr_covers(g, a) for g in grants):
            continue  # break-glass needs a COVERING emergency change
        policy_allowed = False
        break

    return AuthorizationComponents(
        sanctioned_or_routine=sanctioned,
        in_scope=in_scope,
        actor_genuine=actor_genuine,
        policy_allowed=policy_allowed,
    )


# --- public surface ----------------------------------------------------------------------------


def select_facts(
    facts: Sequence[AuthorizationFact],
    track: AuthorizationTrack,
    tenant: str | None = None,
) -> list[AuthorizationFact]:
    """The facts the engine would actually reason over for this track/tenant — the
    track + tenant + lifecycle gate, public so callers (the triage policy guard's
    ``records present`` classifier) apply the same selection the evaluation does. A
    wrong-track, foreign-tenant, or superseded record is not "a record on file"."""
    return _select(facts, track, tenant)


def resolved_entity(
    facts: Sequence[AuthorizationFact],
    entity_type: AuthorizationEntityKind,
    name: str,
) -> EntityContextFact | None:
    """The trust-resolved entity record for a name — the exact resolution the
    evaluation uses (highest trust, deterministic tiebreak), public so callers
    (the triage policy guard's sign-off rule reads asset data_classification) can never
    disagree with the engine about which record speaks for an entity."""
    return _resolved_entity(facts, entity_type, name)


def evaluate_authorization(
    activity: AuthorizationActivity,
    facts: Sequence[AuthorizationFact],
    tenant: str | None = None,
) -> AuthorizationComponents:
    """Compute the four expectedness components for an activity against a set of facts.

    Deterministic, side-effect free. With no facts at all this returns all-False components
    except actor_genuine/policy_allowed defaults — i.e. escalate-shaped output: absence of
    evidence is never authorization (§8 guardrail 1).
    """
    selected = _select(facts, activity.track, tenant)
    if activity.track == AuthorizationTrack.FIM:
        return _fim_components(selected, activity)
    return _acct_components(selected, activity)


def find_covering_grants(
    activity: AuthorizationActivity,
    facts: Sequence[AuthorizationFact],
    tenant: str | None = None,
) -> list[GrantFact]:
    """The grants whose per-record coverage predicate holds for this activity. The FIM freeze
    gate (applied across records) is NOT included here. Used by the ask-once simulation and
    for audit rendering ("which record justified this")."""
    selected = _select(facts, activity.track, tenant)
    grants = _grants(selected)
    if activity.track == AuthorizationTrack.FIM:
        return [
            g
            for g in grants
            if _fim_cr_covers(g, activity) or _fim_baseline_covers(g, activity)
        ]
    asset = _resolved_entity(selected, AuthorizationEntityKind.ASSET, activity.host or "")
    asset_env = _attr(asset, "environment", _ASSET_DEFAULTS)
    return [
        g
        for g in grants
        if _acct_ticket_covers(selected, g, activity, asset_env)
        or _acct_baseline_covers(g, activity)
        or _acct_routine(g, activity)
    ]


AuthzClass = Literal["covered", "contradicted", "absent"]


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

    Single canonical classifier: the safety floor, the triage-policy guard, and the M3
    ASK_AUTHORIZATION detector all read it, so they can never disagree about whether
    authorization is absent (ask/needs-info) or contradicted (escalate).
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
