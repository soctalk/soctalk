"""Deterministic engine scenarios — the CI floor for the authorization reasoning contract.

The file-fed parity test (test_authorization_parity.py) proves fidelity to the benchmark on
hundreds of generated cases but skips when no parity dataset is present; these hand-built
scenarios pin every rule the engine must honor — including paths the benchmark generator
never exercises (org linkage, interactive service accounts, unknown-but-compromised subjects,
multi-freeze partial exceptions, trust ties).
"""

from datetime import UTC, datetime

from soctalk.authorization.engine import evaluate_authorization, find_covering_grants
from soctalk.models.authorization import (
    AuthorizationActivity,
    ChangeFreezeFact,
    EntityContextFact,
    FactScope,
    FreezeScope,
    GrantFact,
    PolicyApplicability,
    ProhibitionFact,
    RecurringWindow,
)

T = datetime(2026, 7, 11, 3, 0, 12, tzinfo=UTC)
HOST, ACCT, ACTION = "app-01", "svc-a", "ssh-remote-exec"
PATH = "/etc/app-01/service.conf"


def activity(**kw) -> AuthorizationActivity:
    base = dict(track="account", host=HOST, account=ACCT, action=ACTION, time=T)
    base.update(kw)
    return AuthorizationActivity(**base)


def fim_activity(**kw) -> AuthorizationActivity:
    base = dict(track="fim", path=PATH, change_type="modify", time=T)
    base.update(kw)
    return AuthorizationActivity(**base)


def ticket(track="account", **kw) -> GrantFact:
    scope = (
        FactScope(subject=ACCT, target=HOST, action=ACTION,
                  recurring_window=RecurringWindow(start="01:00", end="04:00"))
        if track == "account"
        else FactScope(target="/etc/app-01/*", change_type="any",
                       recurring_window=RecurringWindow(start="01:00", end="04:00"))
    )
    base = dict(id="CHG-1", track=track, grant_class="change_ticket", scope=scope,
                valid_from="2020-01-01T00:00:00+00:00", valid_until="2026-07-31T00:00:00+00:00")
    base.update(kw)
    return GrantFact(**base)


def baseline(track="account", **kw) -> GrantFact:
    scope = (
        FactScope(subject=ACCT, target=HOST, action=ACTION,
                  recurring_window=RecurringWindow(start="01:00", end="04:00"))
        if track == "account"
        else FactScope(target="/etc/app-01/*", change_type="any",
                       recurring_window=RecurringWindow(start="01:00", end="04:00"))
    )
    base = dict(id="BASE-1", track=track, grant_class="standing_baseline", scope=scope)
    base.update(kw)
    return GrantFact(**base)


def sighting(seen_count=25, ioc=False, **kw) -> GrantFact:
    base = dict(id="OBS-0", track="account", grant_class="routine_observation",
                scope=FactScope(subject=ACCT, target=HOST, action=ACTION),
                source_type="telemetry_routine", trust=40, seen_count=seen_count, ioc=ioc)
    base.update(kw)
    return GrantFact(**base)


def account_entity(**kw) -> EntityContextFact:
    base = dict(id="ENT-U0", track="account", entity_type="account", name=ACCT,
                account_type="service")
    base.update(kw)
    return EntityContextFact(**base)


def asset_entity(**kw) -> EntityContextFact:
    base = dict(id="ENT-A0", track="account", entity_type="asset", name=HOST)
    base.update(kw)
    return EntityContextFact(**base)


def freeze(track="account", **kw) -> ChangeFreezeFact:
    scope = (
        FreezeScope(envs=["prod"]) if track == "account"
        else FreezeScope(config_classes=["app"])
    )
    base = dict(id="FRZ-0", track=track, freeze_scope=scope,
                start="2026-07-10T00:00:00+00:00", end="2026-07-12T00:00:00+00:00")
    base.update(kw)
    return ChangeFreezeFact(**base)


def comps(activity_, facts, tenant=None):
    c = evaluate_authorization(activity_, facts, tenant)
    return (c.sanctioned_or_routine, c.in_scope, c.actor_genuine, c.policy_allowed, c.decision)


# --- coverage & the single-record rule -----------------------------------------------------


def test_covering_ticket_closes():
    assert comps(activity(), [ticket()]) == (True, True, True, True, "close")


def test_no_facts_is_never_authorized():
    c = evaluate_authorization(activity(), [])
    assert not c.sanctioned_or_routine and not c.in_scope and c.decision == "escalate"


def test_partial_grants_must_not_or():
    """Right account+action on one ticket, right host on another: sanctioned, never in_scope."""
    window = RecurringWindow(start="01:00", end="04:00")
    t1 = ticket(id="CHG-1", scope=FactScope(subject="svc-other", target=HOST, action=ACTION,
                                            recurring_window=window))
    t2 = ticket(id="CHG-2", scope=FactScope(subject=ACCT, target="app-99", action=ACTION,
                                            recurring_window=window))
    assert comps(activity(), [t1, t2]) == (True, False, True, True, "escalate")


def test_expired_pending_cab_window_all_fail_scope():
    expired = ticket(valid_until="2026-07-01T00:00:00+00:00")
    assert comps(activity(), [expired])[1] is False
    pending = ticket(status="pending")
    assert comps(activity(), [pending]) == (False, False, True, True, "escalate")
    cab = ticket(cab_required=True, cab_approved=False)
    assert comps(activity(), [cab]) == (False, False, True, True, "escalate")
    off_window = ticket(scope=FactScope(
        subject=ACCT, target=HOST, action=ACTION,
        recurring_window=RecurringWindow(start="05:00", end="06:00")))
    assert comps(activity(), [off_window]) == (True, False, True, True, "escalate")
    future = ticket(valid_from="2026-08-01T00:00:00+00:00")
    assert comps(activity(), [future]) == (True, False, True, True, "escalate")


def test_window_end_is_second_exact():
    """03:00:12 is OUTSIDE a window ending 03:00 — seconds are not truncated."""
    edge = ticket(scope=FactScope(subject=ACCT, target=HOST, action=ACTION,
                                  recurring_window=RecurringWindow(start="01:00", end="03:00")))
    assert comps(activity(), [edge])[1] is False


# --- freeze divergence ----------------------------------------------------------------------


def test_account_freeze_blocks_ticket_but_not_baseline_or_routine():
    assert comps(activity(), [ticket(), freeze()])[1] is False
    assert comps(activity(), [ticket(freeze_exception=True), freeze()])[1] is True
    fr = freeze(allowed_exception_ids=["CHG-1"])
    assert comps(activity(), [ticket(), fr])[1] is True
    # baselines and routine sightings are NOT gated by account-track freezes
    assert comps(activity(), [baseline(), freeze()]) == (True, True, True, True, "close")
    assert comps(activity(), [sighting(), freeze()]) == (True, True, True, True, "close")


def test_fim_freeze_blocks_baseline_too():
    wp = EntityContextFact(id="ENT-P0", track="fim", entity_type="watched_path",
                           name=PATH, config_class="app")
    assert comps(fim_activity(), [baseline(track="fim"), freeze(track="fim"), wp])[1] is False
    # a covering CR carrying the exception lifts the freeze
    ok = [ticket(track="fim", freeze_exception=True), freeze(track="fim"), wp]
    assert comps(fim_activity(), ok) == (True, True, True, True, "close")


def test_fim_multi_freeze_every_active_freeze_must_be_excepted():
    wp = EntityContextFact(id="ENT-P0", track="fim", entity_type="watched_path",
                           name=PATH, config_class="app")
    f1 = freeze(track="fim", id="FRZ-0", allowed_exception_ids=["CHG-1"])
    f2 = freeze(track="fim", id="FRZ-1")  # not excepted
    assert comps(fim_activity(), [ticket(track="fim"), f1, f2, wp])[1] is False


def test_fim_sanction_ignores_cab_account_sanction_checks_it():
    fim_cab = ticket(track="fim", cab_required=True, cab_approved=False)
    c = evaluate_authorization(fim_activity(), [fim_cab])
    assert c.sanctioned_or_routine is True and c.in_scope is False  # FIM: approved is enough
    acct_cab = ticket(cab_required=True, cab_approved=False)
    assert evaluate_authorization(activity(), [acct_cab]).sanctioned_or_routine is False


# --- routine sightings ------------------------------------------------------------------------


def test_routine_thresholds():
    assert comps(activity(), [sighting(seen_count=25)])[4] == "close"
    assert comps(activity(), [sighting(seen_count=2)])[4] == "escalate"
    assert comps(activity(), [sighting(ioc=True)])[4] == "escalate"


# --- tenancy (account track only) --------------------------------------------------------------


def test_cross_tenant_fails_scope_and_org_link_passes():
    facts = [ticket(), account_entity(owner_org="org-a"), asset_entity(owner_org="org-b")]
    assert comps(activity(), facts)[1] is False
    linked = facts + [EntityContextFact(id="ENT-O0", track="account", entity_type="org",
                                        name="org-a", linked_orgs=["org-b"])]
    assert comps(activity(), linked)[1] is True


def test_unknown_account_passes_tenancy_vacuously():
    assert comps(activity(), [ticket(), asset_entity()])[1] is True  # "" == "" tenancy


# --- actor_genuine ------------------------------------------------------------------------------


def test_compromised_subject_and_contained_target():
    stub = EntityContextFact(id="ENT-C0", track="account", entity_type="account",
                             name=ACCT, compromise_status="compromised")
    assert comps(activity(), [ticket(), stub])[2] is False  # unknown-but-compromised subject
    assert comps(activity(), [ticket(), asset_entity(compromise_status="contained")])[2] is False
    # a compromise flag is never trust-resolved away by a cleaner record
    clean = account_entity(compromise_status=None)
    assert comps(activity(), [ticket(), clean, stub])[2] is False


def test_service_interactive_and_off_call_privileged():
    assert comps(activity(interactive=True), [ticket(), account_entity()])[2] is False
    off_call = account_entity(account_type="human", privileged=True, on_call=False,
                              break_glass=False)
    assert comps(activity(), [ticket(), off_call])[2] is False
    on_call = account_entity(account_type="human", privileged=True, on_call=True)
    assert comps(activity(), [ticket(), on_call])[2] is True


# --- policy -------------------------------------------------------------------------------------


def test_policy_priority_waiver_and_scoping():
    block = ProhibitionFact(id="P-1", track="account", forbid_action=ACTION)
    assert comps(activity(), [ticket(), block])[3] is False
    medium = ProhibitionFact(id="P-1", track="account", forbid_action=ACTION, priority="medium")
    assert comps(activity(), [ticket(), medium])[3] is True
    waived = ProhibitionFact(id="P-1", track="account", forbid_action=ACTION, waiver_present=True)
    assert comps(activity(), [ticket(), waived])[3] is True
    # None = any env; [] = applies nowhere (source-faithful asymmetry)
    nowhere = ProhibitionFact(id="P-2", track="account", forbid_action=ACTION,
                              applies_to=PolicyApplicability(env=[]))
    assert comps(activity(), [ticket(), nowhere])[3] is True
    pci_only = ProhibitionFact(id="P-3", track="account", forbid_action=ACTION,
                               applies_to=PolicyApplicability(data_class=["pci"]))
    facts = [ticket(), asset_entity(data_classification="pci"), pci_only]
    assert comps(activity(), facts)[3] is False


def test_break_glass_needs_covering_emergency_grant():
    policy = ProhibitionFact(id="P-1", track="account", forbid_action=ACTION,
                             break_glass_exception=True)
    bg_account = account_entity(break_glass=True)
    covering = ticket(emergency=True)
    assert comps(activity(), [covering, bg_account, policy])[3] is True
    non_covering = ticket(emergency=True, scope=FactScope(
        subject=ACCT, target="app-99", action=ACTION,
        recurring_window=RecurringWindow(start="01:00", end="04:00")))
    assert comps(activity(), [non_covering, bg_account, policy])[3] is False


def test_fim_policy_empty_class_list_means_any():
    wp = EntityContextFact(id="ENT-P0", track="fim", entity_type="watched_path",
                           name=PATH, config_class="security")
    any_class = ProhibitionFact(id="CP-1", track="fim",
                                applies_to=PolicyApplicability(config_class=[]))
    assert comps(fim_activity(), [ticket(track="fim"), wp, any_class])[3] is False
    other_class = ProhibitionFact(id="CP-2", track="fim",
                                  applies_to=PolicyApplicability(config_class=["system"]))
    assert comps(fim_activity(), [ticket(track="fim"), wp, other_class])[3] is True
    typed = ProhibitionFact(id="CP-3", track="fim", forbid_change_type=["delete"])
    assert comps(fim_activity(), [ticket(track="fim"), wp, typed])[3] is True  # modify != delete


# --- entity conflict resolution -----------------------------------------------------------------


def test_higher_trust_asset_record_wins():
    facts = [
        ticket(),
        account_entity(owner_org="org-a"),
        asset_entity(id="ENT-A0", owner_org="org-a", trust=50),
        asset_entity(id="ENT-A1", owner_org="org-b", trust=100),
    ]
    assert comps(activity(), facts)[1] is False  # the fresher (org-b) record wins -> cross-tenant
    facts[3] = asset_entity(id="ENT-A1", owner_org="org-b", trust=40)
    assert comps(activity(), facts)[1] is True  # stale low-trust record loses


def test_account_records_resolve_by_trust():
    """Contract: conflicting entity_context resolves by trust — a low-trust benign account
    record must not shadow a high-trust off-call privileged-human record (Codex probe)."""
    low = account_entity(id="ENT-low", trust=40)  # service, inert
    high = account_entity(id="ENT-high", account_type="human", privileged=True,
                          on_call=False, break_glass=False, trust=100)
    assert comps(activity(), [ticket(), low, high])[2] is False
    # and the compromise flag still wins regardless of trust ordering
    stub = EntityContextFact(id="ENT-C0", track="account", entity_type="account",
                             name=ACCT, compromise_status="compromised", trust=10)
    assert comps(activity(), [ticket(), account_entity(trust=100), stub])[2] is False


def test_org_linkage_resolves_by_trust():
    """A low-trust org record must not add a linkage the authoritative record lacks."""
    facts = [ticket(), account_entity(owner_org="org-a"), asset_entity(owner_org="org-b")]
    weak_link = EntityContextFact(id="ENT-O0", track="account", entity_type="org",
                                  name="org-a", linked_orgs=["org-b"], trust=20)
    authoritative = EntityContextFact(id="ENT-O1", track="account", entity_type="org",
                                      name="org-a", linked_orgs=[], trust=100)
    assert comps(activity(), facts + [weak_link])[1] is True  # only record -> linked
    assert comps(activity(), facts + [weak_link, authoritative])[1] is False  # outvoted


def test_equal_trust_tie_is_deterministic_and_envelope_free():
    a = asset_entity(id="ENT-A0", owner_org="org-a", trust=100)
    b = asset_entity(id="ENT-A1", owner_org="org-b", trust=100)
    facts = [ticket(), account_entity(owner_org="org-a"), a, b]
    first = comps(activity(), facts)
    swapped = comps(activity(), [ticket(), account_entity(owner_org="org-a"), b, a])
    assert first == swapped  # order- and id-independent tiebreak


# --- tenant isolation ---------------------------------------------------------------------------


def test_foreign_tenant_facts_are_dropped():
    foreign = ticket(tenant="tenant-b")
    assert comps(activity(), [foreign], tenant="tenant-a")[4] == "escalate"
    own = ticket(tenant="tenant-a")
    assert comps(activity(), [own], tenant="tenant-a")[4] == "close"


def test_unscoped_facts_never_authorize_a_tenant():
    """Fail-closed: a tenant=None grant must not close a tenant-scoped evaluation
    (only untenanted evaluation, tenant=None, skips the gate)."""
    unscoped = ticket()  # tenant defaults to None
    assert comps(activity(), [unscoped], tenant="tenant-a")[4] == "escalate"
    assert comps(activity(), [unscoped], tenant=None)[4] == "close"


def test_superseded_facts_are_dead():
    """A revoked/replaced record neither authorizes, nor blocks, nor resolves an entity."""
    revoked = ticket(superseded_by="CHG-2")
    assert comps(activity(), [revoked])[4] == "escalate"
    dead_policy = ProhibitionFact(id="P-1", track="account", forbid_action=ACTION,
                                  superseded_by="P-2")
    assert comps(activity(), [ticket(), dead_policy])[3] is True
    dead_freeze = freeze(superseded_by="FRZ-1")
    assert comps(activity(), [ticket(), dead_freeze])[1] is True
    dead_asset = asset_entity(compromise_status="contained", superseded_by="ENT-A9")
    assert comps(activity(), [ticket(), dead_asset])[2] is True


# --- find_covering_grants -----------------------------------------------------------------------


def test_find_covering_grants_names_the_justifying_record():
    got = find_covering_grants(activity(), [ticket(), sighting(), baseline(id="BASE-9")])
    assert {g.id for g in got} == {"CHG-1", "OBS-0", "BASE-9"}
    assert find_covering_grants(activity(), [ticket(status="pending")]) == []
