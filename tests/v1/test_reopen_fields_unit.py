"""DB-free unit tests for the reopen-signature builder (#15).

These run in the SKIP_INTEGRATION=1 CI unit pass, so the Tier-1 fix has
coverage even when Postgres integration tests are skipped.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from soctalk.core.ir.events import ioc_fingerprint
from soctalk.core.ir.triage import _reopen_fields


def test_reopen_fields_shape_and_window():
    start = datetime(2026, 7, 1, 12, 0, tzinfo=timezone.utc)
    sig_json, reopen_until = _reopen_fields(
        rule_ids=["31151"],
        asset_ids=["agent-101", "web-01"],
        initial_iocs=[{"type": "ip", "value": "192.0.2.77"}],
        window_start=start,
        reopen_window_days=30,
    )
    sig = json.loads(sig_json)

    assert sig["rule_ids"] == ["31151"]
    assert sig["asset_ids"] == ["agent-101", "web-01"]
    assert sig["ioc_fingerprints"] == [ioc_fingerprint("ip", "192.0.2.77")]
    assert sig["time_window"]["start"] == start.isoformat()
    assert sig["time_window"]["end"] == (start + timedelta(days=30)).isoformat()

    # reopen_window_until is anchored at *now*, not at the alert timestamp —
    # the suppression memory extends from the close, not the first event.
    delta = reopen_until - datetime.now(timezone.utc)
    assert timedelta(days=29) < delta <= timedelta(days=30)


def test_reopen_fields_skips_malformed_iocs():
    sig_json, _ = _reopen_fields(
        rule_ids=[],
        asset_ids=[],
        initial_iocs=[
            {"type": "ip"},            # no value
            {"value": "1.2.3.4"},      # no type
            "not-a-dict",              # wrong shape
            {"type": "domain", "value": "evil.example"},
        ],
        window_start=datetime.now(timezone.utc),
        reopen_window_days=7,
    )
    sig = json.loads(sig_json)
    assert sig["ioc_fingerprints"] == [ioc_fingerprint("domain", "evil.example")]
    assert sig["rule_ids"] == []
    assert sig["asset_ids"] == []


def test_reopen_fields_window_days_honored():
    start = datetime.now(timezone.utc)
    _, until_7 = _reopen_fields(
        rule_ids=["1"], asset_ids=[], initial_iocs=[],
        window_start=start, reopen_window_days=7,
    )
    _, until_90 = _reopen_fields(
        rule_ids=["1"], asset_ids=[], initial_iocs=[],
        window_start=start, reopen_window_days=90,
    )
    # The two now() anchors differ by microseconds — compare with tolerance.
    assert abs((until_90 - until_7) - timedelta(days=83)) < timedelta(seconds=5)
