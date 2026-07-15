"""SIEM-routine shadow scoring (epic M2 Phase a) — the guardrails, in code.

DB-free: exercises the pure decision surface (`evaluate_shadow`, `should_score`,
`exclusion_reasons`). The DB history query is covered by the integration triage tests.
"""

from datetime import UTC, datetime

from soctalk.core.ir.authz_shadow import (
    ShadowSettings,
    evaluate_shadow,
    exclusion_reasons,
    should_score,
)

TS = datetime(2026, 7, 11, 3, 0, 12, tzinfo=UTC)
SETTINGS = ShadowSettings(families=frozenset({"sshd"}), min_days=5, max_severity=9)


def _shadow(**kw):
    base = dict(
        seen_days=25, severity=5, mitre=None, initial_iocs=None,
        host="app-01", account="svc-a", action="sshd", ts=TS, settings=SETTINGS,
    )
    base.update(kw)
    return evaluate_shadow(**base)


def test_mature_routine_non_malicious_would_close():
    assert _shadow()["would_close"] is True


def test_ioc_present_never_would_close():
    r = _shadow(initial_iocs=[{"type": "ip", "value": "1.2.3.4"}])
    assert r["would_close"] is False
    assert "ioc_present" in r["excluded"]


def test_mitre_mapped_never_would_close_singular_and_plural():
    # legacy singular
    assert _shadow(mitre={"id": ["T1021.004"]})["would_close"] is False
    # canonical wire shape (soctalk_wire.events uses plural ids/tactics/techniques)
    r = _shadow(mitre={"ids": ["T1110"], "tactics": ["Credential Access"],
                       "techniques": ["Brute Force"]})
    assert r["would_close"] is False and "mitre_mapped" in r["excluded"]
    # a technique-only mapping still blocks
    assert _shadow(mitre={"techniques": ["Brute Force"]})["would_close"] is False


def test_ioc_tainted_routine_never_would_close():
    # the sighting itself is IOC-flagged (threat-intel hit on the routine), even though the
    # current alert is clean — the goldens `ioc_sighting` red-team dimension
    r = _shadow(history_ioc=True)
    assert r["would_close"] is False and "routine_ioc_tainted" in r["excluded"]
    # without the taint it would have closed on the same mature history
    assert _shadow(history_ioc=False)["would_close"] is True


def test_high_severity_excluded():
    r = _shadow(severity=12)
    assert r["would_close"] is False and "severity_too_high" in r["excluded"]


def test_immature_history_never_would_close():
    r = _shadow(seen_days=4)  # below min_days=5
    assert r["would_close"] is False and r["mature_history"] is False
    # exactly at the threshold does close
    assert _shadow(seen_days=5)["would_close"] is True


def test_multiple_exclusions_reported():
    reasons = exclusion_reasons(
        severity=13, mitre={"id": ["T1003"]},
        initial_iocs=[{"type": "ip", "value": "9.9.9.9"}], settings=SETTINGS,
    )
    assert set(reasons) == {"severity_too_high", "mitre_mapped", "ioc_present"}


def _on():  # both flags a real boolean True
    return {"authz_routine_shadow_enabled": True, "entity_correlation_enabled": True}


def test_should_score_gate():
    assert should_score(SETTINGS, _on(), "sshd") is True
    assert should_score(SETTINGS, {**_on(), "authz_routine_shadow_enabled": False}, "sshd") is False
    assert should_score(SETTINGS, _on(), "sudo") is False  # family not enabled
    assert should_score(SETTINGS, _on(), None) is False  # no decoder
    kill = ShadowSettings(kill=True, families=frozenset({"sshd"}))
    assert should_score(kill, _on(), "sshd") is False  # kill switch wins
    empty = ShadowSettings(families=frozenset())
    assert should_score(empty, _on(), "sshd") is False  # no families configured


def test_should_score_requires_entity_correlation():
    # §8.2: scoring while correlation is off would count a would-be-correlated alert routine
    assert should_score(SETTINGS, {"authz_routine_shadow_enabled": True}, "sshd") is False
    assert should_score(
        SETTINGS, {"authz_routine_shadow_enabled": True, "entity_correlation_enabled": False},
        "sshd",
    ) is False


def test_should_score_rejects_stringly_true():
    # bool("false") is True — the flag must be a real boolean True to enable
    assert should_score(SETTINGS, {"authz_routine_shadow_enabled": "false",
                                   "entity_correlation_enabled": True}, "sshd") is False
    assert should_score(SETTINGS, {"authz_routine_shadow_enabled": "true",
                                   "entity_correlation_enabled": True}, "sshd") is False


def test_settings_from_env(monkeypatch):
    monkeypatch.setenv("SOCTALK_AUTHZ_ROUTINE_FAMILIES", "sshd, sudo ,")
    monkeypatch.setenv("SOCTALK_AUTHZ_ROUTINE_MIN_DAYS", "7")
    monkeypatch.setenv("SOCTALK_AUTHZ_ROUTINE_KILL", "true")
    s = ShadowSettings.from_env()
    assert s.families == frozenset({"sshd", "sudo"})
    assert s.min_days == 7 and s.kill is True


def test_settings_from_env_fails_closed_on_bad_value(monkeypatch):
    # a malformed numeric env must disable scoring (kill), never raise on the ingest path
    monkeypatch.setenv("SOCTALK_AUTHZ_ROUTINE_MIN_DAYS", "abc")
    monkeypatch.setenv("SOCTALK_AUTHZ_ROUTINE_FAMILIES", "sshd")
    s = ShadowSettings.from_env()
    assert s.kill is True
    assert should_score(s, _on(), "sshd") is False


def test_discriminating_entities_keeps_all_and_verbatim():
    from soctalk.core.ir.authz_shadow import _discriminating_entities

    ents = [
        {"type": "host", "value": "SRV-1"},
        {"type": "ip", "value": "10.0.0.1"},
        {"type": "ip", "value": "10.0.0.2"},  # second same-type entity must survive
        {"type": "user", "value": "svc-A"},
        {"type": "rule", "value": "5715"},  # non-discriminating — dropped
        {"type": "ip", "value": "10.0.0.1"},  # dup — deduped
    ]
    got = _discriminating_entities(ents)
    # both IPs kept, case preserved (verbatim — NOT lowercased), rule dropped, dup removed
    assert {"type": "ip", "value": "10.0.0.1"} in got
    assert {"type": "ip", "value": "10.0.0.2"} in got
    assert {"type": "host", "value": "SRV-1"} in got  # verbatim case
    assert all(e["type"] != "rule" for e in got)
    assert len(got) == 4


class _FakeResult:
    def __init__(self, value):
        self._v = value

    def scalar_one(self):
        return self._v


class _CapturingDB:
    """Captures the history COUNT SELECT (for SQL/param assertions) and answers the second
    EXISTS (IOC-taint) query with `history_ioc`."""

    def __init__(self, seen_days=25, history_ioc=False):
        self.seen_days = seen_days
        self.history_ioc = history_ioc
        self.captured = None

    async def execute(self, stmt, params):
        sql = str(stmt)
        if "EXISTS" in sql:
            return _FakeResult(self.history_ioc)
        self.captured = (sql, params)  # the routine-history COUNT query
        return _FakeResult(self.seen_days)


async def test_score_builds_one_containment_clause_per_entity(monkeypatch):
    from uuid import uuid4

    import soctalk.core.ir.authz_shadow as m

    async def _noop_audit(*a, **k):
        return None

    monkeypatch.setattr(m, "log_audit", _noop_audit)
    db = _CapturingDB(seen_days=25)
    evidence = {
        "decoder": "sshd",
        "template_hash": "abc123",
        "entities": [
            {"type": "host", "value": "app-01"},
            {"type": "ip", "value": "10.0.0.1"},
            {"type": "ip", "value": "10.0.0.2"},
            {"type": "user", "value": "svc-a"},
        ],
    }
    result = await m.score_alert_shadow(
        db, tenant_id=uuid4(), source="wazuh", rule_id="5715", severity=5,
        initial_iocs=[], evidence=evidence, ts=TS, alert_id=uuid4(), settings=SETTINGS,
    )
    sql, params = db.captured
    # 4 discriminating entities -> 4 containment clauses, each a distinct bound param
    assert sql.count("entities @> CAST(:ent_") == 4
    ent_params = {k: v for k, v in params.items() if k.startswith("ent_")}
    assert len(ent_params) == 4
    assert result["would_close"] is True  # 25 seen days, non-malicious, mature


async def test_score_returns_none_without_host_or_template(monkeypatch):
    from uuid import uuid4

    import soctalk.core.ir.authz_shadow as m

    monkeypatch.setattr(m, "log_audit", lambda *a, **k: None)
    db = _CapturingDB()
    # no host entity
    r = await m.score_alert_shadow(
        db, tenant_id=uuid4(), source="wazuh", rule_id=None, severity=5,
        initial_iocs=[], evidence={"decoder": "sshd", "template_hash": "x",
                                   "entities": [{"type": "ip", "value": "1.1.1.1"}]},
        ts=TS, alert_id=uuid4(), settings=SETTINGS,
    )
    assert r is None and db.captured is None


def test_components_surface_in_result():
    r = _shadow()
    assert set(r["components"]) == {
        "sanctioned_or_routine", "in_scope", "actor_genuine", "policy_allowed"
    }
    assert r["components"]["sanctioned_or_routine"] is True
