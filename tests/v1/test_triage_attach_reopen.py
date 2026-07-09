"""Integration tests for duplicate-alert attach (#14) and FP reopen (#15).

Covers the triage_event coalescing ladder:
  merge ``new`` → attach live ``promoted`` → reopen closed-FP → promote

Requires Postgres with migrations applied (same contract as
test_ir_integration.py). Skipped under SKIP_INTEGRATION=1.
"""

from __future__ import annotations

import asyncio
import os
from datetime import datetime, timezone
from uuid import uuid4

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from soctalk.core.ir.review_events import record_human_decision_received
from soctalk.core.ir.triage import triage_event

SKIP_INTEGRATION = os.getenv("SKIP_INTEGRATION", "0") == "1"

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        SKIP_INTEGRATION,
        reason="SKIP_INTEGRATION set; triage integration tests need Postgres",
    ),
]


def _event_kwargs(*, source_event_id: str, ts: datetime | None = None) -> dict:
    return {
        "source": "wazuh",
        "rule_id": "31151",
        "severity": 9,
        "asset_ids": ["agent-777", "web-09.test.local"],
        "initial_iocs": [{"type": "ip", "value": "198.51.100.99"}],
        "source_event_id": source_event_id,
        "ts": ts or datetime.now(timezone.utc),
        "description": "test alert",
    }


async def _count(session: AsyncSession, sql: str, tenant_id) -> int:
    return (
        await session.execute(text(sql), {"t": str(tenant_id)})
    ).scalar_one()


async def test_duplicate_after_promotion_attaches(
    mssp_session: AsyncSession, seed_two_tenants
):
    """A same-signature event after promotion attaches to the existing
    investigation: no second investigation, no second run."""
    tenant_a, _ = seed_two_tenants
    ts = datetime.now(timezone.utc)

    r1 = await triage_event(
        mssp_session, tenant_id=tenant_a.tenant_id,
        **_event_kwargs(source_event_id="attach-evt-1", ts=ts),
    )
    await mssp_session.commit()
    assert r1["action"] == "promoted"

    r2 = await triage_event(
        mssp_session, tenant_id=tenant_a.tenant_id,
        **_event_kwargs(source_event_id="attach-evt-2", ts=ts),
    )
    await mssp_session.commit()

    assert r2["action"] == "attached"
    assert r2["investigation_id"] == r1["investigation_id"]
    assert r2["event_count"] == 2

    n_inv = await _count(
        mssp_session,
        "SELECT count(*) FROM investigations WHERE tenant_id = :t",
        tenant_a.tenant_id,
    )
    n_runs = await _count(
        mssp_session,
        "SELECT count(*) FROM investigation_runs WHERE tenant_id = :t",
        tenant_a.tenant_id,
    )
    n_alerts = await _count(
        mssp_session,
        "SELECT count(*) FROM alerts WHERE tenant_id = :t",
        tenant_a.tenant_id,
    )
    assert n_inv == 1, "duplicate must not create a second investigation"
    assert n_runs == 1, "duplicate must not start a second run"
    assert n_alerts == 1, "duplicate must merge into the promoted alert row"

    # Attach visibility: the investigation inbox records the recurrence.
    n_events = (
        await mssp_session.execute(
            text(
                "SELECT count(*) FROM investigation_events "
                "WHERE investigation_id = :c AND kind = 'alert_ingested'"
            ),
            {"c": r1["investigation_id"]},
        )
    ).scalar_one()
    assert n_events >= 2, "attach must append an alert_ingested event"


async def test_concurrent_duplicate_ingests_single_investigation(
    mssp_engine, seed_two_tenants, mssp_session: AsyncSession
):
    """Two concurrent same-signature ingests produce exactly one
    alert/investigation/run (advisory-lock serialization)."""
    tenant_a, _ = seed_two_tenants
    ts = datetime.now(timezone.utc)
    sm = async_sessionmaker(mssp_engine, expire_on_commit=False)

    async def ingest(n: int) -> dict:
        async with sm() as s:
            res = await triage_event(
                s, tenant_id=tenant_a.tenant_id,
                **_event_kwargs(source_event_id=f"conc-evt-{n}", ts=ts),
            )
            await s.commit()
            return res

    r1, r2 = await asyncio.gather(ingest(1), ingest(2))
    actions = sorted([r1["action"], r2["action"]])
    assert actions in (["attached", "promoted"], ["merged", "promoted"]), actions

    n_inv = await _count(
        mssp_session,
        "SELECT count(*) FROM investigations WHERE tenant_id = :t",
        tenant_a.tenant_id,
    )
    n_alerts = await _count(
        mssp_session,
        "SELECT count(*) FROM alerts WHERE tenant_id = :t",
        tenant_a.tenant_id,
    )
    n_runs = await _count(
        mssp_session,
        "SELECT count(*) FROM investigation_runs WHERE tenant_id = :t",
        tenant_a.tenant_id,
    )
    assert (n_inv, n_alerts, n_runs) == (1, 1, 1)


async def test_analyst_reject_writes_reopen_fields_and_reopens(
    mssp_session: AsyncSession, seed_two_tenants
):
    """Analyst reject closes as FP with a reopen signature; a matching
    later event resurrects the investigation instead of starting fresh."""
    tenant_a, _ = seed_two_tenants
    ts = datetime.now(timezone.utc)

    r1 = await triage_event(
        mssp_session, tenant_id=tenant_a.tenant_id,
        **_event_kwargs(source_event_id="reject-evt-1", ts=ts),
    )
    await mssp_session.commit()
    inv_id = r1["investigation_id"]

    await record_human_decision_received(
        mssp_session,
        review_id=uuid4(),  # no pending_reviews row needed; UPDATE is a no-op
        investigation_id=inv_id,
        tenant_id=tenant_a.tenant_id,
        decision="reject",
        feedback="known benign scanner",
        reviewer="analyst@test",
    )
    await mssp_session.commit()

    row = (
        await mssp_session.execute(
            text(
                "SELECT status, reopen_signature, reopen_window_until "
                "FROM investigations WHERE id = :c"
            ),
            {"c": inv_id},
        )
    ).mappings().one()
    assert row["status"] == "auto_closed_fp"
    assert row["reopen_signature"] is not None, "#15: reject must write reopen signature"
    assert row["reopen_window_until"] is not None

    sig = row["reopen_signature"]
    assert "agent-777" in sig["asset_ids"]
    assert "31151" in sig["rule_ids"]

    # A matching event later (same assets, new signature bucket) reopens.
    r2 = await triage_event(
        mssp_session, tenant_id=tenant_a.tenant_id,
        **_event_kwargs(source_event_id="reject-evt-2"),
    )
    await mssp_session.commit()
    assert r2["action"] == "reopened"
    assert r2["investigation_id"] == inv_id


async def test_nonmatching_event_still_promotes_fresh(
    mssp_session: AsyncSession, seed_two_tenants
):
    """Unrelated events keep creating their own investigations."""
    tenant_a, _ = seed_two_tenants
    r1 = await triage_event(
        mssp_session, tenant_id=tenant_a.tenant_id,
        source="wazuh", rule_id="11111", severity=9,
        asset_ids=["host-a"], initial_iocs=[],
        source_event_id="fresh-1", ts=datetime.now(timezone.utc),
    )
    r2 = await triage_event(
        mssp_session, tenant_id=tenant_a.tenant_id,
        source="wazuh", rule_id="22222", severity=9,
        asset_ids=["host-b"], initial_iocs=[],
        source_event_id="fresh-2", ts=datetime.now(timezone.utc),
    )
    await mssp_session.commit()
    assert r1["action"] == r2["action"] == "promoted"
    assert r1["investigation_id"] != r2["investigation_id"]
