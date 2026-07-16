"""Response-playbook layer (issue #49), DB-free half.

Schema fail-closed semantics, registry loading + tenant-scoped matching, the
envelope condition contract, dispatch kill switch, webhook signing. The
DB-backed half (enqueue at complete_run, executor drain, execution_log ledger)
lives in test_response_dispatch_integration.py.
"""

from __future__ import annotations

from uuid import uuid4

import pytest

from soctalk.response.capabilities import sign_webhook_body
from soctalk.response.dispatch import (
    _idempotency_key,
    response_dispatch_killed,
)
from soctalk.response.envelope import condition_context
from soctalk.response.models import (
    RESPONSE_STATE_CONTRACT,
    ResponsePlaybook,
)
from soctalk.response.registry import (
    match_response_playbooks,
    parse_response_playbook_text,
    reset_registry_cache,
)
from soctalk.triage_policy.conditions import (
    ConditionError,
    evaluate_condition,
    validate_condition,
)

VALID_PLAYBOOK = """
id: sudo-escalation-handoff
version: 2
tenant: "*"
applies_to:
  rule_groups: [sudo, su]
response:
  on_escalate:
    - capability: notify_webhook
      when: {">=": [{"var": "severity"}, 10]}
    - capability: annotate_investigation
      params: {body: "escalated to external SOAR"}
  on_close:
    - capability: annotate_investigation
      params: {body: "auto-closed by triage"}
"""


# ---------------------------------------------------------------------------
# Schema: fail closed on everything not explicitly allowed
# ---------------------------------------------------------------------------


def test_valid_playbook_parses_and_defaults_to_shadow():
    pb = parse_response_playbook_text(VALID_PLAYBOOK)
    assert pb.id == "sudo-escalation-handoff"
    assert pb.status == "shadow", "file playbooks must default to shadow (#44 gate)"
    assert [a.capability for a in pb.response.on_escalate] == [
        "notify_webhook",
        "annotate_investigation",
    ]


def test_explicit_active_status_is_honored():
    pb = parse_response_playbook_text(VALID_PLAYBOOK + "\nstatus: active\n")
    assert pb.status == "active"


def test_unknown_capability_rejects_file():
    with pytest.raises(ValueError, match="vetted allowlist"):
        parse_response_playbook_text(
            "id: bad\nresponse: {on_escalate: [{capability: isolate_host}]}"
        )


def test_on_close_restricted_to_annotation_tier():
    with pytest.raises(ValueError, match="on_close permits only"):
        parse_response_playbook_text(
            "id: bad\nresponse: {on_close: [{capability: notify_webhook}]}"
        )


def test_unknown_field_rejects_file():
    with pytest.raises(ValueError):
        parse_response_playbook_text(VALID_PLAYBOOK + "\nrespond_to: everything\n")


def test_condition_outside_contract_rejects_file():
    with pytest.raises(ValueError, match="state contract"):
        parse_response_playbook_text(
            "id: bad\nresponse: {on_escalate: [{capability: annotate_investigation, "
            'when: {"==": [{"var": "authz.class"}, "covered"]}}]}'
        )


def test_response_contract_is_disjoint_surface():
    # authz.* is triage-policy surface; the response contract publishes the
    # envelope only. A drive-by union of the two contracts is an API decision,
    # not an accident this test lets slide.
    assert "authz.class" not in RESPONSE_STATE_CONTRACT
    for field in RESPONSE_STATE_CONTRACT:
        validate_condition({"!!": [{"var": field}]}, RESPONSE_STATE_CONTRACT)


def test_triage_contract_unchanged_by_default_param():
    with pytest.raises(ConditionError):
        validate_condition({"!!": [{"var": "severity"}]})  # triage default contract


# ---------------------------------------------------------------------------
# Registry: loading + matching
# ---------------------------------------------------------------------------


def _write_dir(tmp_path, monkeypatch, files: dict[str, str]):
    for name, body in files.items():
        (tmp_path / name).write_text(body)
    monkeypatch.setenv("SOCTALK_RESPONSE_PLAYBOOK_DIR", str(tmp_path))
    reset_registry_cache()


def test_registry_loads_valid_skips_invalid(tmp_path, monkeypatch):
    _write_dir(
        tmp_path,
        monkeypatch,
        {
            "good.yaml": VALID_PLAYBOOK + "\nstatus: active\n",
            "bad.yaml": "id: nope\nresponse: {on_escalate: [{capability: rm_rf}]}",
        },
    )
    try:
        matched = match_response_playbooks(
            rule_groups={"sudo"}, rule_ids=set(),
            tenant_identifiers=frozenset({"any"}), status="active",
        )
        assert [pb.id for pb in matched] == ["sudo-escalation-handoff"]
    finally:
        reset_registry_cache()


def test_tenant_scoping_matches_uuid_or_slug_only(tmp_path, monkeypatch):
    tenant_uuid = str(uuid4())
    _write_dir(
        tmp_path,
        monkeypatch,
        {
            "scoped.yaml": VALID_PLAYBOOK.replace('tenant: "*"', f"tenant: {tenant_uuid}")
            + "\nstatus: active\n",
        },
    )
    try:
        assert match_response_playbooks(
            rule_groups={"sudo"}, rule_ids=set(),
            tenant_identifiers=frozenset({tenant_uuid, "acme"}), status="active",
        )
        assert not match_response_playbooks(
            rule_groups={"sudo"}, rule_ids=set(),
            tenant_identifiers=frozenset({str(uuid4()), "other"}), status="active",
        )
    finally:
        reset_registry_cache()


def test_applies_to_mitre_technique_and_tactic(tmp_path, monkeypatch):
    """A playbook can MATCH on ATT&CK technique ids and tactics (envelope v2).
    Criteria are OR'd with rule groups/ids."""
    _write_dir(
        tmp_path,
        monkeypatch,
        {
            "att.yaml": (
                "id: att-lateral\nstatus: active\n"
                "applies_to: {mitre_techniques: [T1021], mitre_tactics: [TA0008]}\n"
                "response: {on_escalate: [{capability: annotate_investigation}]}"
            )
        },
    )
    ids = frozenset({"t"})
    try:
        # technique id hit
        assert match_response_playbooks(
            rule_groups=set(), rule_ids=set(), tenant_identifiers=ids,
            status="active", mitre_techniques=frozenset({"T1021"}),
        )
        # tactic hit
        assert match_response_playbooks(
            rule_groups=set(), rule_ids=set(), tenant_identifiers=ids,
            status="active", mitre_tactics=frozenset({"TA0008"}),
        )
        # a technique NAME must NOT match (names aren't the identifier)
        assert not match_response_playbooks(
            rule_groups=set(), rule_ids=set(), tenant_identifiers=ids,
            status="active", mitre_techniques=frozenset({"Remote Services"}),
        )
        # unrelated technique → no match, and NOT a match-everything
        assert not match_response_playbooks(
            rule_groups=set(), rule_ids=set(), tenant_identifiers=ids,
            status="active", mitre_techniques=frozenset({"T1078"}),
        )
    finally:
        reset_registry_cache()


def test_empty_applies_to_matches_everything(tmp_path, monkeypatch):
    _write_dir(
        tmp_path,
        monkeypatch,
        {
            "catchall.yaml": (
                "id: catchall\nstatus: active\n"
                "response: {on_escalate: [{capability: annotate_investigation}]}"
            )
        },
    )
    try:
        assert match_response_playbooks(
            rule_groups=set(), rule_ids=set(),
            tenant_identifiers=frozenset({"t"}), status="active",
        )
    finally:
        reset_registry_cache()


def test_shadow_and_active_are_disjoint_match_sets(tmp_path, monkeypatch):
    _write_dir(tmp_path, monkeypatch, {"shadowed.yaml": VALID_PLAYBOOK})
    try:
        assert not match_response_playbooks(
            rule_groups={"sudo"}, rule_ids=set(),
            tenant_identifiers=frozenset({"t"}), status="active",
        )
        assert match_response_playbooks(
            rule_groups={"sudo"}, rule_ids=set(),
            tenant_identifiers=frozenset({"t"}), status="shadow",
        )
    finally:
        reset_registry_cache()


# ---------------------------------------------------------------------------
# Envelope condition context + conditions
# ---------------------------------------------------------------------------


def _envelope(**over):
    base = {
        "version": 1,
        "tenant_id": "t",
        "investigation_id": "c",
        "run_id": "r",
        "disposition": "escalate",
        "worker_disposition": "close_fp",
        "floor": {"server_veto": "active_incident", "worker_vetoes": []},
        "verdict": {"summary": "s", "confidence": 0.4},
        "severity": 12,
        "rule": {"ids": ["5710"], "groups": ["sudo"]},
        # envelope v2: techniques = Txxxx ids, tactics = tactic refs, names demoted.
        "mitre": {
            "techniques": ["T1078"],
            "tactics": ["TA0004"],
            "technique_names": ["Valid Accounts"],
        },
        "entities": [],
        "iocs": [],
    }
    base.update(over)
    return base


def test_condition_context_projects_contract_fields_only():
    ctx = condition_context(_envelope())
    assert ctx["disposition"] == "escalate"
    assert ctx["floor_vetoed"] is True
    assert "entities" not in ctx and "iocs" not in ctx, (
        "context must expose the declared contract, not envelope internals"
    )


def test_conditions_evaluate_over_context():
    ctx = condition_context(_envelope())
    assert evaluate_condition({">=": [{"var": "severity"}, 10]}, ctx)
    assert evaluate_condition({"in": ["sudo", {"var": "rule.groups"}]}, ctx)
    assert evaluate_condition({"in": ["T1078", {"var": "mitre.techniques"}]}, ctx), (
        "mitre.techniques carries the canonical Txxxx ids (envelope v2)"
    )
    assert evaluate_condition({"in": ["TA0004", {"var": "mitre.tactics"}]}, ctx)
    assert evaluate_condition({"!!": [{"var": "floor_vetoed"}]}, ctx)
    assert not evaluate_condition(
        {"==": [{"var": "worker_disposition"}, "escalate"]}, ctx
    )


def test_floor_vetoed_false_when_no_vetoes():
    ctx = condition_context(
        _envelope(floor={"server_veto": None, "worker_vetoes": []})
    )
    assert ctx["floor_vetoed"] is False


# ---------------------------------------------------------------------------
# Dispatch plumbing: idempotency, kill switch, signing
# ---------------------------------------------------------------------------


def test_idempotency_key_is_stable_and_version_scoped():
    pb = ResponsePlaybook(id="p", version=3)
    run_id = uuid4()
    assert _idempotency_key(run_id, pb, 0) == f"response:{run_id}:p@3:0"
    assert _idempotency_key(run_id, pb, 0) != _idempotency_key(
        run_id, ResponsePlaybook(id="p", version=4), 0
    ), "a playbook edit must re-key its actions"


def test_dispatch_kill_switch_env_and_policy(monkeypatch):
    assert not response_dispatch_killed({})
    assert response_dispatch_killed({"response_dispatch_kill": True})
    assert not response_dispatch_killed({"response_dispatch_kill": "true"}), (
        "stringly true must not kill (same rule as auto_close_killed)"
    )
    monkeypatch.setenv("SOCTALK_RESPONSE_DISPATCH_KILL", "1")
    assert response_dispatch_killed({})


def test_webhook_url_guard_rejects_non_global_targets(monkeypatch):
    from soctalk.response.capabilities import assert_webhook_url_allowed

    with pytest.raises(ValueError, match="must be https"):
        assert_webhook_url_allowed("http://example.com/hook")
    for url in (
        "https://10.0.0.1/hook",
        "https://169.254.169.254/latest/meta-data",
        "https://127.0.0.1/hook",
        "https://localhost/hook",
    ):
        with pytest.raises(ValueError, match="non-global"):
            assert_webhook_url_allowed(url)

    monkeypatch.setattr(
        "socket.getaddrinfo",
        lambda *a, **k: [(2, 1, 6, "", ("93.184.216.34", 443))],
    )
    assert_webhook_url_allowed("https://soar.example/hook")


def test_webhook_url_guard_http_escape_hatch(monkeypatch):
    from soctalk.response.capabilities import assert_webhook_url_allowed

    monkeypatch.setenv("SOCTALK_RESPONSE_WEBHOOK_ALLOW_HTTP", "1")
    monkeypatch.setattr(
        "socket.getaddrinfo",
        lambda *a, **k: [(2, 1, 6, "", ("93.184.216.34", 80))],
    )
    assert_webhook_url_allowed("http://soar.example/hook")
    # The escape hatch relaxes the scheme, never the address floor.
    monkeypatch.setattr(
        "socket.getaddrinfo",
        lambda *a, **k: [(2, 1, 6, "", ("127.0.0.1", 80))],
    )
    with pytest.raises(ValueError, match="non-global"):
        assert_webhook_url_allowed("http://127.0.0.1/hook")


def test_webhook_signature_is_hmac_sha256_of_exact_bytes():
    body = b'{"a":1}'
    sig = sign_webhook_body("secret", body)
    assert sig.startswith("sha256=") and len(sig) == 7 + 64
    assert sig == sign_webhook_body("secret", body)
    assert sig != sign_webhook_body("secret", b'{"a": 1}'), (
        "signature must bind to exact bytes, not JSON equivalence"
    )
