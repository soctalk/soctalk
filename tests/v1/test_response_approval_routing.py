"""Approval routing for gated response capabilities (#49 phase 2) — DB-backed.

A non-AUTONOMOUS response capability is no longer refused by the executor; it is
ROUTED to the core.ir approval plane as a proposal a human must approve. These
tests pin the routing invariants against a real DB: the drain succeeds (no
retry), the proposal is `proposed` with a NULL run_id (the terminal
response-origin run is never flipped to waiting_on_gate), a re-drain is
idempotent, and scope checks still reject before any proposal is created.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime
from uuid import UUID, uuid4

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from soctalk.core.ir.models import CapabilityClass
from soctalk.core.ir.runtime import active_run_for_case, execute_one
from soctalk.core.ir.tools import ApprovalPolicy
from soctalk.core.ir.triage import triage_event
from soctalk.response import capabilities as caps
from soctalk.response.dispatch import RESPONSE_OUTBOX_KIND, dispatch_for_completed_run
from soctalk.response.executor import RESPONSE_KINDS, response_handlers
from soctalk.response.registry import reset_registry_cache

SKIP_INTEGRATION = os.getenv("SKIP_INTEGRATION", "0") == "1"

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(SKIP_INTEGRATION, reason="needs Postgres"),
]

GATED_CAP = "isolate_host_test"

GATED_PLAYBOOK = f"""
id: resp-gated
version: 1
status: active
applies_to:
  rule_groups: [sudo]
response:
  on_escalate:
    - capability: {GATED_CAP}
      params: {{host: prod-web-01}}
"""


async def _fired() -> str | None:
    # A handler that must NEVER run for a gated capability during routing —
    # if the executor ever calls it, the test's proposal assertions fail loudly
    # because a side effect happened instead of a routed proposal.
    raise AssertionError("gated capability handler must not execute during routing")


@pytest.fixture
def gated_registry(tmp_path, monkeypatch):
    """Register a gated (non-autonomous) capability + an active playbook that
    uses it. The capability's handler raises if ever invoked, proving routing
    never executes it."""
    spec = caps.ResponseCapability(
        name=GATED_CAP,
        capability_class=CapabilityClass.WRITE_EXTERNAL,
        approval=ApprovalPolicy.TYPED_REASON,
        description="test-only gated capability",
        handler=lambda db, t, p: _fired(),
    )
    monkeypatch.setitem(caps.RESPONSE_CAPABILITIES, GATED_CAP, spec)
    (tmp_path / "gated.yaml").write_text(GATED_PLAYBOOK)
    monkeypatch.setenv("SOCTALK_RESPONSE_PLAYBOOK_DIR", str(tmp_path))
    reset_registry_cache()
    yield
    reset_registry_cache()


async def _promoted(db, tenant_id, *, tag):
    result = await triage_event(
        db, tenant_id=tenant_id,
        source="wazuh", rule_id="5710", severity=12, asset_ids=[f"gate-{tag}"],
        initial_iocs=[], source_event_id=f"gate-{tag}-1", ts=datetime.now(UTC),
        description="sudo for gated-routing test",
        evidence={"rule_groups": ["sudo"], "schema_version": 2},
    )
    assert result["action"] == "promoted"
    inv = UUID(result["investigation_id"])
    run = await active_run_for_case(db, inv)
    await db.commit()
    return inv, run


async def _dispatch(db, tenant_id, inv, run):
    return await dispatch_for_completed_run(
        db, tenant_id=tenant_id, investigation_id=inv, run_id=run,
        worker_disposition="escalate", effective_disposition="escalate",
        server_floor_veto=None, verdict_summary="v", verdict_confidence=0.9,
        enrichments={},
    )


async def _drain(db):
    return await execute_one(db, "test-exec", response_handlers(), kinds=RESPONSE_KINDS)


async def _proposals(db, tenant_id, inv):
    rows = (
        await db.execute(
            text(
                "SELECT id, action_type, status, run_id, capability_class, params "
                "FROM proposals WHERE tenant_id = :t AND investigation_id = :c"
            ),
            {"t": str(tenant_id), "c": str(inv)},
        )
    ).mappings().all()
    return [dict(r) for r in rows]


async def test_gated_capability_routes_to_proposal_not_refused(
    mssp_session: AsyncSession, seed_two_tenants, gated_registry
):
    tenant_a, _ = seed_two_tenants
    inv, run = await _promoted(mssp_session, tenant_a.tenant_id, tag="route")
    await _dispatch(mssp_session, tenant_a.tenant_id, inv, run)
    await mssp_session.commit()

    did = await _drain(mssp_session)
    await mssp_session.commit()
    assert did is True

    # Outbox row SUCCEEDED (routed), not failed/retried.
    row = (
        await mssp_session.execute(
            text(
                "SELECT status, external_ref, attempts FROM investigation_outbox "
                "WHERE tenant_id = :t AND kind = :k"
            ),
            {"t": str(tenant_a.tenant_id), "k": RESPONSE_OUTBOX_KIND},
        )
    ).mappings().one()
    assert row["status"] == "succeeded"
    assert row["attempts"] == 0, "routing must not retry"
    assert str(row["external_ref"]).startswith("proposal:")

    # Exactly one proposal, proposed, run_id NULL, carrying the full payload.
    props = await _proposals(mssp_session, tenant_a.tenant_id, inv)
    assert len(props) == 1
    p = props[0]
    assert p["action_type"] == GATED_CAP
    assert p["status"] == "proposed"
    assert p["run_id"] is None, "terminal response-origin run must not be gated"
    assert p["capability_class"] == CapabilityClass.WRITE_EXTERNAL.value
    assert p["params"]["capability"] == GATED_CAP
    assert p["params"]["envelope"]["investigation_id"] == str(inv)

    # Ledger records the routed outcome.
    ledger = (
        await mssp_session.execute(
            text(
                "SELECT kind, after FROM execution_log "
                "WHERE tenant_id = :t AND subject_type = 'response_action'"
            ),
            {"t": str(tenant_a.tenant_id)},
        )
    ).mappings().all()
    assert any(r["kind"] == "response_action.routed" for r in ledger)


async def test_completed_run_stays_completed(
    mssp_session: AsyncSession, seed_two_tenants, gated_registry
):
    tenant_a, _ = seed_two_tenants
    inv, run = await _promoted(mssp_session, tenant_a.tenant_id, tag="term")
    # Terminalize the run the way complete_run does before dispatch.
    await mssp_session.execute(
        text("UPDATE investigation_runs SET status = 'completed', ended_at = now() "
             "WHERE id = :r"),
        {"r": str(run)},
    )
    await _dispatch(mssp_session, tenant_a.tenant_id, inv, run)
    await mssp_session.commit()
    await _drain(mssp_session)
    await mssp_session.commit()

    status = (
        await mssp_session.execute(
            text("SELECT status FROM investigation_runs WHERE id = :r"), {"r": str(run)}
        )
    ).scalar_one()
    assert status == "completed", "routing must never reopen a terminal run"


async def test_redrain_is_idempotent_single_proposal(
    mssp_session: AsyncSession, seed_two_tenants, gated_registry
):
    tenant_a, _ = seed_two_tenants
    inv, run = await _promoted(mssp_session, tenant_a.tenant_id, tag="idem")
    await _dispatch(mssp_session, tenant_a.tenant_id, inv, run)
    await mssp_session.commit()

    # Drain once, then force the outbox row back to pending and drain again —
    # simulating a lease-expiry re-delivery. Must resolve to the SAME proposal.
    await _drain(mssp_session)
    await mssp_session.commit()
    await mssp_session.execute(
        text("UPDATE investigation_outbox SET status = 'pending', claimed_at = NULL, "
             "claimed_by = NULL WHERE tenant_id = :t AND kind = :k"),
        {"t": str(tenant_a.tenant_id), "k": RESPONSE_OUTBOX_KIND},
    )
    await mssp_session.commit()
    await _drain(mssp_session)
    await mssp_session.commit()

    props = await _proposals(mssp_session, tenant_a.tenant_id, inv)
    assert len(props) == 1, "re-drain must not create a duplicate proposal"


async def test_scope_mismatch_rejects_before_proposal(
    mssp_session: AsyncSession, seed_two_tenants, gated_registry
):
    """A payload whose envelope tenant/investigation disagrees with the outbox
    row is rejected before any proposal is created (the phase-1 scope guard runs
    ahead of the approval branch)."""
    from soctalk.core.ir.events import canonical_json

    tenant_a, tenant_b = seed_two_tenants
    inv, run = await _promoted(mssp_session, tenant_b.tenant_id, tag="scope")

    payload = {
        "envelope": {
            "version": 1, "tenant_id": str(tenant_b.tenant_id),
            "investigation_id": str(inv), "run_id": str(run),
            "disposition": "escalate",
        },
        "playbook": {"id": "evil", "version": 1},
        "capability": GATED_CAP,
        "params": {"host": "x"},
        "delivery": f"response:{uuid4()}:evil@1:0",
    }
    # Row tenant A, envelope tenant B → mismatch.
    await mssp_session.execute(
        text("INSERT INTO investigation_outbox "
             "(id, tenant_id, kind, idempotency_key, payload, status) "
             "VALUES (:id, :t, :k, :ik, CAST(:p AS JSONB), 'pending')"),
        {"id": str(uuid4()), "t": str(tenant_a.tenant_id), "k": RESPONSE_OUTBOX_KIND,
         "ik": payload["delivery"], "p": canonical_json(payload)},
    )
    await mssp_session.commit()
    await _drain(mssp_session)
    await mssp_session.commit()

    props = (
        await mssp_session.execute(
            text("SELECT count(*) FROM proposals WHERE action_type = :a"),
            {"a": GATED_CAP},
        )
    ).scalar_one()
    assert props == 0, "scope mismatch must reject before creating a proposal"
