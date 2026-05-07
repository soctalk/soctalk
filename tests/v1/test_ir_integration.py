"""Integration tests for the native IR subsystem.

Requires the v1_0003_ir_core migration applied. Skipped under
SKIP_INTEGRATION=1 (unit CI job).
"""

from __future__ import annotations

import os
from datetime import datetime, timezone
from uuid import uuid4

import pytest
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError, ProgrammingError
from sqlalchemy.ext.asyncio import AsyncSession


SKIP_INTEGRATION = os.getenv("SKIP_INTEGRATION", "0") == "1"

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        SKIP_INTEGRATION,
        reason="SKIP_INTEGRATION set; IR integration tests need Postgres",
    ),
]


async def test_execution_log_immutable_from_app(
    app_session: AsyncSession, seed_two_tenants
):
    """UPDATE and DELETE on execution_log must fail at the Postgres grant layer."""

    tenant_a, _ = seed_two_tenants
    await app_session.execute(
        text("SELECT set_config('app.current_tenant_id', :t, true)"),
        {"t": str(tenant_a.tenant_id)},
    )
    await app_session.execute(
        text("SELECT set_config('app.current_audience', 'mssp', true)"),
    )

    # Seed an execution log entry (allowed: INSERT).
    log_id = uuid4()
    await app_session.execute(
        text(
            "INSERT INTO execution_log "
            "(log_id, tenant_id, actor_kind, actor_id, kind) "
            "VALUES (:id, :t, 'system', 'test', 'test.kind')"
        ),
        {"id": str(log_id), "t": str(tenant_a.tenant_id)},
    )
    await app_session.commit()

    # Need MSSP audience for the subsequent mutation attempts so we
    # exercise the grant layer, not RLS.
    await app_session.execute(
        text("SELECT set_config('app.current_audience', 'mssp', true)")
    )

    # UPDATE should fail (grant-restricted).
    with pytest.raises(ProgrammingError):
        await app_session.execute(
            text("UPDATE execution_log SET kind = 'changed' WHERE log_id = :id"),
            {"id": str(log_id)},
        )
        await app_session.commit()
    await app_session.rollback()

    # DELETE should fail too.
    with pytest.raises(ProgrammingError):
        await app_session.execute(
            text("DELETE FROM execution_log WHERE log_id = :id"),
            {"id": str(log_id)},
        )
        await app_session.commit()
    await app_session.rollback()


async def test_single_active_run_per_case(
    mssp_session: AsyncSession, seed_two_tenants
):
    from soctalk.core.ir.runtime import start_run

    tenant_a, _ = seed_two_tenants
    # Create a case first.
    case_id = uuid4()
    await mssp_session.execute(
        text(
            "INSERT INTO cases (id, tenant_id, short_id, title, severity) "
            "VALUES (:id, :t, '2026-0001', 'test', 5)"
        ),
        {"id": str(case_id), "t": str(tenant_a.tenant_id)},
    )
    await mssp_session.commit()

    # First run creates fine.
    await start_run(mssp_session, tenant_a.tenant_id, case_id)
    await mssp_session.commit()

    # Second active run must fail (partial unique index).
    with pytest.raises(IntegrityError):
        await start_run(mssp_session, tenant_a.tenant_id, case_id)
        await mssp_session.commit()
    await mssp_session.rollback()


async def test_event_idempotency_silent_dedup(
    mssp_session: AsyncSession, seed_two_tenants
):
    from soctalk.core.ir.events import EventKind, append_event

    tenant_a, _ = seed_two_tenants
    case_id = uuid4()
    await mssp_session.execute(
        text(
            "INSERT INTO cases (id, tenant_id, short_id, title, severity) "
            "VALUES (:id, :t, '2026-0002', 'test', 5)"
        ),
        {"id": str(case_id), "t": str(tenant_a.tenant_id)},
    )
    await mssp_session.commit()

    payload = {"body": "some message"}
    e1 = await append_event(
        mssp_session,
        tenant_id=tenant_a.tenant_id,
        case_id=case_id,
        run_id=None,
        kind=EventKind.ANALYST_MESSAGE,
        payload=payload,
        producer="test",
    )
    # Same payload + same producer → same key → same event returned.
    e2 = await append_event(
        mssp_session,
        tenant_id=tenant_a.tenant_id,
        case_id=case_id,
        run_id=None,
        kind=EventKind.ANALYST_MESSAGE,
        payload=payload,
        producer="test",
    )
    assert e1 == e2


async def test_proposal_idempotency_on_duplicate(
    mssp_session: AsyncSession, seed_two_tenants
):
    from soctalk.core.ir.runtime import create_proposal, start_run

    tenant_a, _ = seed_two_tenants
    case_id = uuid4()
    await mssp_session.execute(
        text(
            "INSERT INTO cases (id, tenant_id, short_id, title, severity) "
            "VALUES (:id, :t, '2026-0003', 'test', 5)"
        ),
        {"id": str(case_id), "t": str(tenant_a.tenant_id)},
    )
    await mssp_session.commit()
    run_id = await start_run(mssp_session, tenant_a.tenant_id, case_id)
    await mssp_session.commit()

    p1 = await create_proposal(
        mssp_session,
        tenant_id=tenant_a.tenant_id,
        case_id=case_id,
        run_id=run_id,
        action_type="block_ip",
        params={"ip": "1.2.3.4", "ttl_days": 30},
        rationale="test",
        capability_class="write_external",
    )
    p2 = await create_proposal(
        mssp_session,
        tenant_id=tenant_a.tenant_id,
        case_id=case_id,
        run_id=run_id,
        action_type="block_ip",
        params={"ttl_days": 30, "ip": "1.2.3.4"},  # reordered, same semantic
        rationale="test-duplicate",
        capability_class="write_external",
    )
    assert p1 == p2


async def test_customer_audience_cannot_read_mssp_only(
    app_session: AsyncSession, seed_two_tenants
):
    """A session configured as customer audience cannot see mssp_only rows."""

    from soctalk.core.ir.events import EventKind, append_event

    tenant_a, _ = seed_two_tenants

    # Seed via MSSP: create a case + mssp_only event.
    await app_session.execute(
        text("SELECT set_config('app.current_tenant_id', :t, true)"),
        {"t": str(tenant_a.tenant_id)},
    )
    await app_session.execute(
        text("SELECT set_config('app.current_audience', 'mssp', true)"),
    )
    case_id = uuid4()
    await app_session.execute(
        text(
            "INSERT INTO cases (id, tenant_id, short_id, title, severity, visibility) "
            "VALUES (:id, :t, '2026-0004', 'mssp-only case', 5, 'mssp_only')"
        ),
        {"id": str(case_id), "t": str(tenant_a.tenant_id)},
    )
    await app_session.commit()

    # Now switch to customer audience (same tenant).
    await app_session.execute(
        text("SELECT set_config('app.current_audience', 'customer', true)"),
    )
    count = (
        await app_session.execute(
            text("SELECT count(*) FROM cases WHERE id = :id"),
            {"id": str(case_id)},
        )
    ).scalar_one()
    assert count == 0, "customer audience must not see mssp_only rows"


async def test_reducer_replay_matches_live(
    mssp_session: AsyncSession, seed_two_tenants
):
    from soctalk.core.ir.events import EventKind, append_event
    from soctalk.core.ir.reducer import load_facts, replay
    from soctalk.core.ir.runtime import consume_new_events

    tenant_a, _ = seed_two_tenants
    case_id = uuid4()
    await mssp_session.execute(
        text(
            "INSERT INTO cases (id, tenant_id, short_id, title, severity) "
            "VALUES (:id, :t, '2026-0005', 'replay test', 5)"
        ),
        {"id": str(case_id), "t": str(tenant_a.tenant_id)},
    )
    await mssp_session.commit()

    # Append a handful of events.
    await append_event(
        mssp_session,
        tenant_id=tenant_a.tenant_id,
        case_id=case_id,
        run_id=None,
        kind=EventKind.ALERT_INGESTED,
        payload={"rule_id": "5720", "severity": 8, "ai_confidence": 0.8,
                 "initial_hypothesis": "phishing"},
        producer="test",
    )
    await append_event(
        mssp_session,
        tenant_id=tenant_a.tenant_id,
        case_id=case_id,
        run_id=None,
        kind=EventKind.HYPOTHESIS_UPDATED,
        payload={"id": "root", "confidence": 0.9, "rationale": "more evidence"},
        producer="test",
    )
    await append_event(
        mssp_session,
        tenant_id=tenant_a.tenant_id,
        case_id=case_id,
        run_id=None,
        kind=EventKind.DIRECTIVE_ADDED,
        payload={"id": "d1", "text": "always check SPF"},
        producer="test",
    )
    await mssp_session.commit()

    # Live consume.
    await consume_new_events(mssp_session, tenant_a.tenant_id, case_id)
    live = await load_facts(mssp_session, case_id)
    await mssp_session.commit()

    # Full replay (drop projection + reapply) should match.
    rebuilt = await replay(mssp_session, tenant_a.tenant_id, case_id)
    await mssp_session.commit()

    assert live.as_dict() == rebuilt.as_dict()
    assert rebuilt.hypotheses[0]["confidence"] == 0.9
    assert any(d["id"] == "d1" for d in rebuilt.active_directives)
