"""MSSP dashboard tenant-health classification (pure, no DB).

A fresh heartbeat used to be the whole definition of "healthy": the adapter
hard-coded ``health: "ok"`` and the dashboard only looked at heartbeat age, so
a tenant whose every indexer poll failed (bad credentials, TLS, a dropped
query) showed green. The row now also counts the adapter's own
``degraded``/``failing`` report and surfaces its reason codes.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import pytest

from soctalk.core.api.mssp_dashboard import (
    _HEARTBEAT_UNHEALTHY_AGE_SECONDS,
    _classify_tenant_health,
)

NOW = datetime(2026, 11, 2, 12, 0, 0, tzinfo=UTC)


def _row(**kw):
    base = {
        "tenant_id": "00000000-0000-0000-0000-000000000001",
        "slug": "acme",
        "display_name": "Acme",
        "state": "active",
        "last_heartbeat": (NOW - timedelta(seconds=30)).isoformat(),
        "adapter_health": "ok",
        "health_reasons": None,
    }
    base.update(kw)
    return base


def test_fresh_ok_heartbeat_is_healthy():
    row = _classify_tenant_health(_row(), NOW)
    assert row.unhealthy is False
    assert row.heartbeat_age_seconds == 30
    assert row.adapter_health == "ok"
    assert row.adapter_health_reasons == []


@pytest.mark.parametrize("health", ["degraded", "failing"])
def test_adapter_reported_problem_is_unhealthy_despite_fresh_heartbeat(health):
    row = _classify_tenant_health(
        _row(adapter_health=health, health_reasons=json.dumps(["poll_failing"])), NOW
    )
    assert row.unhealthy is True
    assert row.adapter_health == health
    assert row.adapter_health_reasons == ["poll_failing"]


def test_stale_heartbeat_still_unhealthy_even_if_last_report_was_ok():
    stale = NOW - timedelta(seconds=_HEARTBEAT_UNHEALTHY_AGE_SECONDS + 1)
    row = _classify_tenant_health(_row(last_heartbeat=stale.isoformat()), NOW)
    assert row.unhealthy is True


def test_never_heartbeated_is_unhealthy_with_no_adapter_health():
    row = _classify_tenant_health(_row(last_heartbeat=None, adapter_health=None), NOW)
    assert row.unhealthy is True
    assert row.heartbeat_age_seconds is None
    assert row.adapter_health is None


@pytest.mark.parametrize("raw", ["not json", json.dumps({"a": 1}), json.dumps("x")])
def test_malformed_reasons_are_ignored(raw):
    row = _classify_tenant_health(_row(adapter_health="degraded", health_reasons=raw), NOW)
    assert row.adapter_health_reasons == []
    assert row.unhealthy is True


def test_reasons_are_bounded():
    many = json.dumps([f"r{i}" + "x" * 100 for i in range(20)])
    row = _classify_tenant_health(_row(adapter_health="failing", health_reasons=many), NOW)
    assert len(row.adapter_health_reasons) == 8
    assert all(len(r) <= 64 for r in row.adapter_health_reasons)


@pytest.mark.parametrize("state", ["pending", "provisioning", "degraded"])
def test_non_running_states_unhealthy(state):
    assert _classify_tenant_health(_row(state=state), NOW).unhealthy is True
