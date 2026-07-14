"""AuthorizationFact contract unit tests: discrimination, per-kind legality, round-trips.

DB-free, LLM-free. These are the CI-side guarantee that the wire contract holds its shape;
semantic fidelity to the benchmark is covered by test_authorization_engine_unit.py and the
file-fed test_authorization_parity.py.
"""

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from soctalk.models.authorization import (
    AUTHORIZATION_FACT_ADAPTER,
    AuthorizationActivity,
    AuthorizationComponents,
    AuthorizationContext,
    ChangeFreezeFact,
    EntityContextFact,
    GrantFact,
    ProhibitionFact,
)

TS = "2026-07-11T03:00:12+00:00"


def _ticket(**kw) -> dict:
    base = {
        "id": "CHG-1",
        "kind": "grant",
        "track": "account",
        "grant_class": "change_ticket",
        "scope": {
            "subject": "svc-a",
            "target": "app-01",
            "action": "ssh-remote-exec",
            "recurring_window": {"start": "01:00", "end": "04:00"},
        },
        "valid_until": "2026-07-31T00:00:00+00:00",
    }
    base.update(kw)
    return base


def test_each_kind_parses_and_discriminates():
    rows = [
        _ticket(),
        {
            "id": "P-1",
            "kind": "prohibition",
            "track": "account",
            "forbid_action": "ssh-remote-exec",
        },
        {
            "id": "FRZ-0",
            "kind": "change_freeze",
            "track": "account",
            "freeze_scope": {"envs": ["prod"]},
            "start": TS,
            "end": TS,
        },
        {
            "id": "ENT-1",
            "kind": "entity_context",
            "track": "account",
            "entity_type": "asset",
            "name": "app-01",
        },
    ]
    kinds = []
    for row in rows:
        fact = AUTHORIZATION_FACT_ADAPTER.validate_python(row)
        kinds.append(type(fact))
        # round-trip: dump -> validate -> identical dump
        dumped = fact.model_dump(mode="json")
        again = AUTHORIZATION_FACT_ADAPTER.validate_python(dumped)
        assert again.model_dump(mode="json") == dumped
    assert kinds == [GrantFact, ProhibitionFact, ChangeFreezeFact, EntityContextFact]


def test_unknown_kind_rejected():
    with pytest.raises(ValidationError):
        AUTHORIZATION_FACT_ADAPTER.validate_python(
            {"id": "X", "kind": "blessing", "track": "account"}
        )


def test_change_ticket_requires_valid_until():
    row = _ticket()
    del row["valid_until"]
    with pytest.raises(ValidationError, match="valid_until"):
        AUTHORIZATION_FACT_ADAPTER.validate_python(row)


def test_routine_fields_only_on_routine_observation():
    with pytest.raises(ValidationError, match="routine_observation"):
        AUTHORIZATION_FACT_ADAPTER.validate_python(_ticket(seen_count=9))
    with pytest.raises(ValidationError, match="seen_count"):
        AUTHORIZATION_FACT_ADAPTER.validate_python(
            {
                "id": "OBS-0",
                "kind": "grant",
                "track": "account",
                "grant_class": "routine_observation",
            }
        )


def test_baseline_carries_no_change_management_fields():
    with pytest.raises(ValidationError):
        AUTHORIZATION_FACT_ADAPTER.validate_python(
            _ticket(grant_class="standing_baseline", emergency=True, valid_until=None)
        )


def test_prohibition_track_legality():
    with pytest.raises(ValidationError, match="forbid_action"):
        AUTHORIZATION_FACT_ADAPTER.validate_python(
            {"id": "P-1", "kind": "prohibition", "track": "account"}
        )
    with pytest.raises(ValidationError, match="account-track"):
        AUTHORIZATION_FACT_ADAPTER.validate_python(
            {"id": "P-1", "kind": "prohibition", "track": "fim", "forbid_action": "x"}
        )


def test_freeze_track_legality():
    with pytest.raises(ValidationError, match="envs"):
        AUTHORIZATION_FACT_ADAPTER.validate_python(
            {
                "id": "FRZ-0",
                "kind": "change_freeze",
                "track": "account",
                "freeze_scope": {"config_classes": ["app"]},
                "start": TS,
                "end": TS,
            }
        )


def test_entity_attribute_legality():
    with pytest.raises(ValidationError, match="non-account"):
        AUTHORIZATION_FACT_ADAPTER.validate_python(
            {
                "id": "ENT-1",
                "kind": "entity_context",
                "track": "account",
                "entity_type": "asset",
                "name": "app-01",
                "privileged": True,
            }
        )


def test_naive_datetimes_coerced_to_utc():
    fact = AUTHORIZATION_FACT_ADAPTER.validate_python(
        _ticket(valid_until="2026-07-31T00:00:00")  # naive
    )
    assert fact.valid_until is not None and fact.valid_until.tzinfo is not None
    activity = AuthorizationActivity(
        track="account",
        host="app-01",
        account="svc-a",
        action="ssh-remote-exec",
        time=datetime(2026, 7, 11, 3, 0, 12),  # naive
    )
    assert activity.time.tzinfo == UTC


def test_activity_requires_track_fields():
    with pytest.raises(ValidationError, match="account activity"):
        AuthorizationActivity(track="account", time=TS)
    with pytest.raises(ValidationError, match="fim activity"):
        AuthorizationActivity(track="fim", time=TS)


def test_components_decision():
    all_true = AuthorizationComponents(
        sanctioned_or_routine=True, in_scope=True, actor_genuine=True, policy_allowed=True
    )
    assert all_true.expected and all_true.decision == "close"
    one_false = all_true.model_copy(update={"in_scope": False})
    assert not one_false.expected and one_false.decision == "escalate"


def test_context_roundtrip_json():
    ctx = AuthorizationContext(
        tenant="t-1",
        activity=AuthorizationActivity(
            track="account", host="app-01", account="svc-a", action="ssh-remote-exec", time=TS
        ),
        facts=[AUTHORIZATION_FACT_ADAPTER.validate_python(_ticket())],
        note="fixture",
    )
    dumped = ctx.model_dump(mode="json")
    again = AuthorizationContext.model_validate(dumped)
    assert again.model_dump(mode="json") == dumped
    assert again.facts[0].id == "CHG-1"
