"""Unit tests for the shared soctalk_wire package (#17 T1/T4).

Redaction (both failure directions), template hashing, entity/mitre
extraction from Wazuh hits, and schema-version handling.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

# The adapter is packaged separately (Dockerfile.adapter), so its module
# isn't on the default path; add src/ for the _hit_to_event tests.
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from soctalk_wire import (  # noqa: E402
    SCHEMA_VERSION,
    AdapterEvent,
    IngestBatch,
    redact_text,
    template_hash,
)
from soctalk_wire.redaction import REDACTION_VERSION, _luhn_ok  # noqa: E402


# --------------------------------------------------------------------- redaction


@pytest.mark.parametrize(
    "text,must_contain,must_not_contain",
    [
        ("login password=hunter2 ok", "<REDACTED:credential>", "hunter2"),
        ("Authorization: Bearer abc123def456ghi", "<REDACTED:auth_token>", "abc123def456ghi"),
        ("token=deadbeefcafebabe0011", "<REDACTED:credential>", "deadbeefcafebabe0011"),
        ("db=postgres://user:s3cr3t@host/db", "<REDACTED:url_credential>", "s3cr3t"),
        ("key AKIAIOSFODNN7EXAMPLE here", "<REDACTED:aws_key>", "AKIAIOSFODNN7EXAMPLE"),
    ],
)
def test_redaction_strips_secrets(text, must_contain, must_not_contain):
    out = redact_text(text)
    assert must_contain in out
    assert must_not_contain not in out


def test_redaction_preserves_iocs_for_extraction():
    # The over-redaction failure direction: IPs, hashes, domains that the
    # extractor needs must SURVIVE redaction.
    text = "conn from 203.0.113.9 to evil.example sha256 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    out = redact_text(text)
    assert "203.0.113.9" in out
    assert "evil.example" in out
    assert "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" in out


def test_redaction_pan_luhn():
    assert _luhn_ok("4111111111111111")  # test Visa, valid Luhn
    assert not _luhn_ok("4111111111111112")
    out = redact_text("card 4111 1111 1111 1111 on file")
    assert "<REDACTED:pan>" in out
    # A random 16-digit non-Luhn number is not treated as a card.
    assert redact_text("id 1234567890123456") == "id 1234567890123456"


def test_redaction_none_and_empty():
    assert redact_text(None) is None
    assert redact_text("") == ""


@pytest.mark.parametrize(
    "text,secret",
    [
        # Bypass cases the adversarial review found (commit 414eb8d).
        ('{"password":"hunter2"}', "hunter2"),
        ("'api_key': 'AKIAZZ1234'", "AKIAZZ1234"),
        ("client_secret=abc123def456", "abc123def456"),
        ("db-password=s3cr3t", "s3cr3t"),
        ("Authorization: Basic dXNlcjpwYXNzd29yZA==", "dXNlcjpwYXNzd29yZA=="),
        ('config { "client_secret" : "topsecret" }', "topsecret"),
    ],
)
def test_redaction_covers_json_and_compound_keys(text, secret):
    assert secret not in redact_text(text)


# --------------------------------------------------------------------- template


def test_template_hash_stable_across_variables():
    a = template_hash("Failed password for admin from 10.0.0.1 port 22 at 2026-07-09T10:00:00Z")
    b = template_hash("Failed password for admin from 192.168.1.9 port 2222 at 2026-07-09T11:30:00Z")
    assert a == b, "same shape (only IP/port/ts vary) must hash identically"
    c = template_hash("Accepted publickey for admin from 10.0.0.1")
    assert a != c


def test_template_hash_none():
    assert template_hash(None) is None
    assert template_hash("") is None


# --------------------------------------------------------------------- schema


def test_batch_schema_version_default_and_additive():
    b = IngestBatch(tenant_id="00000000-0000-0000-0000-000000000000", events=[])
    assert b.schema_version == 1  # missing defaults to 1
    b2 = IngestBatch(tenant_id="00000000-0000-0000-0000-000000000000", events=[], schema_version=2, batch_seq=5)
    assert b2.schema_version == 2 and b2.batch_seq == 5


def test_event_v2_fields_optional():
    # A v1-shaped event (no entities/mitre/etc.) still validates.
    ev = AdapterEvent(source_event_id="x", severity=9)
    assert ev.entities == []
    assert ev.mitre is None
    assert SCHEMA_VERSION == 2


async def test_adapter_query_uses_keyset_search_after():
    """The indexer query must sort by (@timestamp, id) and use search_after
    when a tie-breaker id is present — the fix for the same-timestamp
    paging livelock."""
    import soctalk_adapter.main as m

    captured = {}

    class _FakeResp:
        def raise_for_status(self): ...
        def json(self): return {"hits": {"hits": []}}

    class _FakeClient:
        async def post(self, url, **kw):
            captured.update(kw["json"])
            return _FakeResp()

    await m._query_alerts(_FakeClient(), "2026-07-09T10:00:00.000Z", "wz-42", 100)
    assert captured["sort"] == [
        {"@timestamp": {"order": "asc"}}, {"id": {"order": "asc"}}
    ]
    assert captured["search_after"] == ["2026-07-09T10:00:00.000Z", "wz-42"]

    # No tie-breaker id → no search_after (first page).
    captured.clear()
    await m._query_alerts(_FakeClient(), "2026-07-09T10:00:00.000Z", None, 100)
    assert "search_after" not in captured


def test_template_hash_secret_free_and_stable():
    """Hashing redacted text: same shape with different secrets hashes
    identically, and no secret substring leaks into the fingerprint."""
    from soctalk_wire import redact_text
    a = template_hash(redact_text("auth password=hunter2 for user bob"))
    b = template_hash(redact_text("auth password=correcthorsebatterystaple for user bob"))
    assert a == b


def test_adapter_hit_to_event_extracts_and_redacts():
    from soctalk_adapter.main import _hit_to_event

    hit = {
        "_id": "abc123",
        "_source": {
            "id": "wz-1",
            "@timestamp": "2026-07-09T10:00:00.000Z",
            "rule": {
                "id": "5710", "level": 10, "description": "sshd auth failure",
                "groups": ["authentication_failed", "sshd"],
                "mitre": {"id": ["T1110"], "tactic": ["Credential Access"], "technique": ["Brute Force"]},
            },
            "agent": {"id": "001", "name": "bastion-01"},
            "data": {"srcuser": "root", "srcip": "203.0.113.9"},
            "decoder": {"name": "sshd"},
            "full_log": "Failed password for root from 203.0.113.9 port 22 password=leaked",
        },
    }
    ev = _hit_to_event(hit)
    assert ev["source_event_id"] == "wz-1"
    assert ev["mitre"]["ids"] == ["T1110"]
    assert "authentication_failed" in ev["rule_groups"]
    assert ev["decoder"] == "sshd"
    assert ev["redaction_version"] == REDACTION_VERSION
    assert ev["observed_at"] is not None
    # redaction ran: password stripped, but the IOC IP survived
    assert "leaked" not in ev["full_log"]
    assert "203.0.113.9" in ev["full_log"]
    # typed entities from decoder fields
    types = {(e["type"], e["role"]) for e in ev["entities"]}
    assert ("user", "actor") in types
    assert ("ip", "src") in types
    # IOC still extracted from raw
    assert any(i["value"] == "203.0.113.9" for i in ev["initial_iocs"])
