"""Ask-once-memory simulation (evals/authorization_m0) unit tests on hand-built fixtures.

DB-free, LLM-free, benchmark-free: the fixtures are tiny gold.jsonl/orgstate.jsonl files in
the goldens wire shape, so these tests also pin the file contract the simulation consumes.
"""

import json

from soctalk.evals.authorization_m0 import run_simulation

TS = "2026-07-11T03:00:12+00:00"
HOST, ACCT, ACTION = "app-01", "svc-a", "ssh-remote-exec"


def _ticket(**kw):
    base = {
        "id": "CHG-1", "account": ACCT, "host": HOST, "action": ACTION,
        "window_start": "01:00", "window_end": "04:00", "status": "approved",
        "valid_until": "2026-07-31T00:00:00+00:00",
        "effective_from": "2020-01-01T00:00:00+00:00",
        "cab_required": False, "cab_approved": True, "emergency": False,
        "freeze_exception": False,
    }
    base.update(kw)
    return base


def _account_org(**kw):
    base = {
        "host": HOST,
        "accounts": [{"name": ACCT, "type": "service", "owner_org": "", "privileged": False,
                      "break_glass": False, "service_owner": "", "on_call": True}],
        "tickets": [_ticket()],
        "baselines": [], "policies": [], "compromised_accounts": [], "orgs": [],
        "assets": [], "freezes": [], "observations": [],
    }
    base.update(kw)
    return base


def _gold(cid, decision, dim, group, paraphrase_of=None, is_trap=False):
    return {
        "id": cid, "decision": decision,
        "components": {"sanctioned_or_routine": decision == "close",
                       "in_scope": decision == "close",
                       "actor_genuine": True, "policy_allowed": True},
        "metadata": {"technique": "T1021.004", "flipped_dimension": dim, "is_trap": is_trap,
                     "paraphrase_of": paraphrase_of, "counterfactual_group": group,
                     "crossability": "dual_use", "seed": 0, "render_style": "plain"},
    }


def _acct_row(cid, org):
    activity = {"host": HOST, "account": ACCT, "action": ACTION, "time": TS,
                "source_ip": "10.0.0.9", "auth_method": "key", "interactive": False, "mfa": True}
    return {"id": cid, "track": "account", "activity": activity, "org_state": org}


def _fim_row(cid, org, path="/etc/app-01/service.conf"):
    activity = {"path": path, "change_type": "modify", "time": TS}
    return {"id": cid, "track": "fim", "activity": activity, "org_state": org}


def _fim_org(**kw):
    base = {
        "path": "/etc/app-01/service.conf",
        "paths": [{"path": "/etc/app-01/service.conf", "config_class": "app",
                   "criticality": "medium", "environment": "prod", "owner_org": "",
                   "approver": "", "compromise_status": "clean", "source_reliability": 100}],
        "change_requests": [{
            "id": "CHG-9", "path_glob": "/etc/app-01/*", "change_type": "any",
            "window_start": "01:00", "window_end": "04:00", "status": "approved",
            "valid_until": "2026-07-31T00:00:00+00:00",
            "effective_from": "2020-01-01T00:00:00+00:00",
            "cab_required": False, "cab_approved": True, "emergency": False,
            "freeze_exception": False}],
        "change_baselines": [], "change_freezes": [], "change_policies": [], "orgs": [],
    }
    base.update(kw)
    return base


def _write_dataset(tmp_path):
    """Three groups. G1 (account): base close -> expiry trap -> compromised -> ioc-covered close
    -> paraphrase-of-base. G2 (fim): base close. G3 (fim, distinct path so G2's memory cannot
    cover it): cr_absent escalate."""
    rows = [
        _acct_row("c1", _account_org()),
        _acct_row("c2", _account_org(tickets=[_ticket(valid_until="2026-07-01T00:00:00+00:00")])),
        _acct_row("c3", _account_org(compromised_accounts=[ACCT])),
        _acct_row("c4", _account_org(observations=[{"account": ACCT, "host": HOST,
                                                    "action": ACTION, "seen_count": 25,
                                                    "ioc": True}])),
        _acct_row("c5", _account_org()),
        _fim_row("f1", _fim_org()),
        _fim_row("f2", _fim_org(path="/etc/app-02/web.conf", change_requests=[]),
                 path="/etc/app-02/web.conf"),
    ]
    gold = [
        _gold("c1", "close", "base", "g1"),
        _gold("c2", "escalate", "expiry", "g1", is_trap=True),
        _gold("c3", "escalate", "actor_compromised", "g1", is_trap=True),
        _gold("c4", "close", "ioc_true_covered", "g1"),
        _gold("c5", "close", "base", "g1", paraphrase_of="c1"),
        _gold("f1", "close", "base", "g2"),
        _gold("f2", "escalate", "cr_absent", "g3"),
    ]
    d = tmp_path / "data"
    d.mkdir()
    (d / "orgstate.jsonl").write_text("\n".join(json.dumps(r) for r in rows) + "\n")
    (d / "gold.jsonl").write_text("\n".join(json.dumps(g) for g in gold) + "\n")
    return d


def _outcome(report, pass_no, key):
    return report["passes"][pass_no - 1]["outcome_counts"].get(key, 0)


def test_simulation_is_deterministic(tmp_path):
    d = _write_dataset(tmp_path)
    a = run_simulation([d], memory_scope="ticket_terms", passes=2)
    b = run_simulation([d], memory_scope="ticket_terms", passes=2)
    assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)


def test_paraphrases_are_skipped(tmp_path):
    report = run_simulation([_write_dataset(tmp_path)])
    assert report["totals"]["cases"] == 6  # c5 dropped
    assert report["totals"]["gold_close"] == 3  # c1, c4, f1 (c5 skipped)


def test_never_ask_gate_precedes_close_and_ask(tmp_path):
    report = run_simulation([_write_dataset(tmp_path)])
    p1 = report["passes"][0]
    # c3 (compromised actor) and c4 (IOC sighting, even though gold=close) never generate
    # questions and never close; c4 lands in the safety-override bucket, not FN.
    assert p1["outcome_counts"]["escalate_no_ask"] == 2
    assert p1["safety_override_escalations"] == 1
    assert all(f["id"] not in ("c3", "c4") for f in report["false_negative_cases"])


def test_ask_once_then_reuse_across_passes(tmp_path):
    report = run_simulation([_write_dataset(tmp_path)], passes=2)
    p1, p2 = report["passes"]
    assert p1["question_volume"] == 3  # c1, f1 (gold yes) + f2 (gold no)
    assert p2["question_volume"] == 0 and p2["repeat_questions"] == 1  # f2 re-asks, un-stored
    assert _outcome(report, 2, "close_memory") >= 2  # c1 and f1 close from memory on pass 2
    assert report["memory"]["facts_stored"] == 2  # a 'no' is never stored (§8.4)
    assert report["memory"]["facts_reused"] == 2


def test_stale_memory_fn_is_bucketed(tmp_path):
    report = run_simulation([_write_dataset(tmp_path)], passes=1)
    fns = report["false_negative_cases"]
    # c2 (expiry trap, gold escalate) is closed by the memory learned from c1 moments earlier
    assert [f["id"] for f in fns] == ["c2"]
    assert fns[0]["cause"] == "stale_memory"
    assert report["passes"][0]["false_negative_rate"] == 1 / 3  # c2 of {c2, c3, f2}


def test_siem_only_floor_and_tracks(tmp_path):
    report = run_simulation([_write_dataset(tmp_path)])
    assert report["stackless"]["siem_only_close_rate"] == 0.0  # no non-IOC routine sightings
    p1 = report["passes"][0]
    assert p1["per_track"]["fim"]["questions"] == 2  # f1 yes, f2 no
    assert p1["per_track"]["account"]["gold_close"] == 2


def test_ticket_terms_memory_from_routine_source_stores_baseline():
    """A routine-history covering grant must be stored as a standing baseline without
    crashing the GrantFact validator (Codex #5)."""
    from soctalk.authorization.adapter import facts_from_row, stackless_facts_from_row
    from soctalk.evals.authorization_m0 import Memory, SimCase

    org = _account_org(
        tickets=[],
        observations=[{"account": ACCT, "host": HOST, "action": ACTION,
                       "seen_count": 25, "ioc": False}],
    )
    row = _acct_row("r1", org)
    activity, full = facts_from_row(row)
    _, stackless = stackless_facts_from_row(row)
    case = SimCase(row, _gold("r1", "close", "routine_scanner", "g9"), activity, full, stackless)
    memory = Memory(scope_policy="ticket_terms")
    memory.remember(case)
    stored = memory.facts[0]
    assert stored.grant_class.value == "standing_baseline"
    assert stored.seen_count is None and stored.ioc is None


def test_memory_scope_policies_both_run(tmp_path):
    d = _write_dataset(tmp_path)
    for scope in ("ticket_terms", "tuple_forever"):
        report = run_simulation([d], memory_scope=scope, passes=2)
        assert report["config"]["memory_scope"] == scope
        assert report["passes"][1]["auto_close_rate"] > 0
