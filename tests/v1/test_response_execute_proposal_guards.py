"""execute_proposal drain guards (#49 phase 2, Codex review) — DB-backed.

The atomic approved-claim is the single point that authorizes an approved-proposal
execution. These tests pin its guards: a non-approved proposal never executes, a
re-drain after execution never re-POSTs, a cross-tenant/action-mismatched outbox
row is refused, and a genuine non-response proposal is delegated to core.ir.
"""

from __future__ import annotations

import os
from uuid import uuid4

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from soctalk.core.ir.events import canonical_json
from soctalk.core.ir.runtime import create_proposal, execute_one
from soctalk.response.executor import RESPONSE_KINDS, response_handlers

SKIP_INTEGRATION = os.getenv("SKIP_INTEGRATION", "0") == "1"

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(SKIP_INTEGRATION, reason="needs Postgres"),
]

POST_CALLS = "n"


def _no_post(monkeypatch):
    calls = {POST_CALLS: 0}

    async def fake_post(self, *a, **k):
        calls[POST_CALLS] += 1
        raise AssertionError("must not POST")

    monkeypatch.setattr("httpx.AsyncClient.post", fake_post)
    return calls


async def _enqueue_execute_proposal(db, *, tenant_id, proposal_id, action_type, params):
    await db.execute(
        text(
            "INSERT INTO investigation_outbox "
            "(id, tenant_id, kind, idempotency_key, payload, status) "
            "VALUES (:id, :t, 'execute_proposal', :ik, CAST(:p AS JSONB), 'pending')"
        ),
        {"id": str(uuid4()), "t": str(tenant_id), "ik": f"proposal:{proposal_id}:{uuid4()}",
         "p": canonical_json({"proposal_id": str(proposal_id), "action_type": action_type,
                              "params": params, "capability_class": "write_external"})},
    )


async def _drain(db):
    return await execute_one(db, "test-exec", response_handlers(), kinds=RESPONSE_KINDS)


async def _make_response_proposal(db, tenant_id, *, status="proposed"):
    """A response external_action proposal in the given status (via create_proposal
    with run_id=None), returning its id."""
    inv = uuid4()
    # A cases row so scope checks / FKs resolve.
    await db.execute(
        text("INSERT INTO investigations (id, tenant_id, short_id, title, status, severity) "
             "VALUES (:c, :t, :s, 'x', 'active', 5)"),
        {"c": str(inv), "t": str(tenant_id), "s": f"C-{str(inv)[:8]}"},
    )
    payload = {
        "envelope": {"version": 1, "tenant_id": str(tenant_id),
                     "investigation_id": str(inv), "run_id": str(uuid4()),
                     "disposition": "escalate"},
        "playbook": {"id": "p", "version": 1},
        "capability": "external_action",
        "params": {"endpoint": "soar", "action": "isolate_host"},
        "delivery": f"response:{uuid4()}:p@1:0",
    }
    pid = await create_proposal(
        db, tenant_id=tenant_id, investigation_id=inv, run_id=None,
        action_type="external_action", params=payload, rationale="r",
        capability_class="write_external",
    )
    if status != "proposed":
        await db.execute(
            text("UPDATE proposals SET status = :s WHERE id = :id"),
            {"s": status, "id": str(pid)},
        )
    return pid, inv, payload


async def test_non_approved_proposal_never_executes(
    mssp_session: AsyncSession, seed_two_tenants, monkeypatch
):
    tenant_a, _ = seed_two_tenants
    calls = _no_post(monkeypatch)
    pid, _inv, payload = await _make_response_proposal(
        mssp_session, tenant_a.tenant_id, status="proposed"
    )
    await _enqueue_execute_proposal(
        mssp_session, tenant_id=tenant_a.tenant_id, proposal_id=pid,
        action_type="external_action", params=payload,
    )
    await mssp_session.commit()
    await _drain(mssp_session)
    await mssp_session.commit()

    assert calls[POST_CALLS] == 0
    status = (
        await mssp_session.execute(
            text("SELECT status FROM proposals WHERE id = :id"), {"id": str(pid)}
        )
    ).scalar_one()
    assert status == "proposed", "a non-approved proposal must not transition or execute"


async def test_redrain_after_executed_does_not_repost(
    mssp_session: AsyncSession, seed_two_tenants, monkeypatch
):
    tenant_a, _ = seed_two_tenants
    calls = _no_post(monkeypatch)
    # Proposal already 'executed' — a stale execute_proposal redelivery must no-op.
    pid, _inv, payload = await _make_response_proposal(
        mssp_session, tenant_a.tenant_id, status="executed"
    )
    await _enqueue_execute_proposal(
        mssp_session, tenant_id=tenant_a.tenant_id, proposal_id=pid,
        action_type="external_action", params=payload,
    )
    await mssp_session.commit()
    did = await _drain(mssp_session)
    await mssp_session.commit()

    assert did is True  # the row was claimed and handled (as a no-op)
    assert calls[POST_CALLS] == 0
    row = (
        await mssp_session.execute(
            text("SELECT status, external_ref FROM investigation_outbox "
                 "WHERE tenant_id = :t AND kind = 'execute_proposal'"),
            {"t": str(tenant_a.tenant_id)},
        )
    ).mappings().one()
    assert row["status"] == "succeeded"
    assert str(row["external_ref"]).startswith("noop:")


async def test_cross_tenant_execute_proposal_refused(
    mssp_session: AsyncSession, seed_two_tenants, monkeypatch
):
    tenant_a, tenant_b = seed_two_tenants
    calls = _no_post(monkeypatch)
    # An APPROVED proposal in tenant B, but the outbox row claims tenant A.
    pid, _inv, payload = await _make_response_proposal(
        mssp_session, tenant_b.tenant_id, status="approved"
    )
    await _enqueue_execute_proposal(
        mssp_session, tenant_id=tenant_a.tenant_id, proposal_id=pid,
        action_type="external_action", params=payload,
    )
    await mssp_session.commit()
    await _drain(mssp_session)
    await mssp_session.commit()

    assert calls[POST_CALLS] == 0
    status = (
        await mssp_session.execute(
            text("SELECT status FROM proposals WHERE id = :id"), {"id": str(pid)}
        )
    ).scalar_one()
    assert status == "approved", "tenant-A row must not touch tenant-B's proposal"


async def test_action_mismatch_refused(
    mssp_session: AsyncSession, seed_two_tenants, monkeypatch
):
    tenant_a, _ = seed_two_tenants
    calls = _no_post(monkeypatch)
    pid, _inv, payload = await _make_response_proposal(
        mssp_session, tenant_a.tenant_id, status="approved"
    )
    # Outbox payload action disagrees with the proposal's stored action_type.
    await _enqueue_execute_proposal(
        mssp_session, tenant_id=tenant_a.tenant_id, proposal_id=pid,
        action_type="annotate_investigation", params=payload,
    )
    await mssp_session.commit()
    await _drain(mssp_session)
    await mssp_session.commit()

    assert calls[POST_CALLS] == 0
    status = (
        await mssp_session.execute(
            text("SELECT status FROM proposals WHERE id = :id"), {"id": str(pid)}
        )
    ).scalar_one()
    assert status == "approved"


async def test_non_response_proposal_is_delegated(
    mssp_session: AsyncSession, seed_two_tenants
):
    """A genuine core.ir tool proposal (action_type not a response capability) is
    delegated to the core.ir handler and executes via the tool registry stub."""
    tenant_a, _ = seed_two_tenants
    inv = uuid4()
    await mssp_session.execute(
        text("INSERT INTO investigations (id, tenant_id, short_id, title, status, severity) "
             "VALUES (:c, :t, :s, 'x', 'active', 5)"),
        {"c": str(inv), "t": str(tenant_a.tenant_id), "s": f"C-{str(inv)[:8]}"},
    )
    pid = await create_proposal(
        mssp_session, tenant_id=tenant_a.tenant_id, investigation_id=inv, run_id=None,
        action_type="investigation.list_iocs",
        params={"investigation_id": str(inv)}, rationale="r",
        capability_class="read_local",
    )
    from soctalk.core.ir.runtime import approve_proposal

    await approve_proposal(
        mssp_session, proposal_id=pid, approver_user_id=uuid4(), reason="ok"
    )
    await mssp_session.commit()
    assert await _drain(mssp_session)
    await mssp_session.commit()

    status = (
        await mssp_session.execute(
            text("SELECT status FROM proposals WHERE id = :id"), {"id": str(pid)}
        )
    ).scalar_one()
    assert status == "executed", "non-response proposal must execute via core.ir path"
