"""Authored response playbooks (#49 phase 2) — DB-backed persistence + dispatch.

CRUD/activate/deactivate lifecycle, tenant isolation, fail-closed validation, and
the load-bearing bit: an ACTIVE authored playbook governs response dispatch LIVE
(the L1 dispatcher merges DB rows with the file registry), a SHADOW one only audits.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime
from uuid import UUID

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from soctalk.core.ir.runtime import active_run_for_case
from soctalk.core.ir.triage import triage_event
from soctalk.response.authoring import (
    ResponsePlaybookValidationError,
    get_authored,
    list_authored,
    load_dispatchable,
    set_authored_status,
    upsert_authored,
)
from soctalk.response.dispatch import (
    DISPATCH_AUDIT_ACTION,
    RESPONSE_OUTBOX_KIND,
    dispatch_for_completed_run,
)
from soctalk.response.registry import reset_registry_cache

SKIP_INTEGRATION = os.getenv("SKIP_INTEGRATION", "0") == "1"

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(SKIP_INTEGRATION, reason="needs Postgres"),
]

DEF = {
    "id": "authored-sudo",
    "version": 1,
    "applies_to": {"rule_groups": ["sudo"]},
    "response": {
        "on_escalate": [
            {"capability": "annotate_investigation", "params": {"body": "authored fired"}}
        ]
    },
}


@pytest.fixture(autouse=True)
def _no_files(monkeypatch):
    # Isolate from any file registry so the DB is the only source.
    monkeypatch.delenv("SOCTALK_RESPONSE_PLAYBOOK_DIR", raising=False)
    reset_registry_cache()
    yield
    reset_registry_cache()


async def test_upsert_pins_tenant_and_lists(mssp_session: AsyncSession, seed_two_tenants):
    a, _ = seed_two_tenants
    r = await upsert_authored(mssp_session, tenant_id=a.tenant_id, definition=DEF)
    assert r["response_playbook_id"] == "authored-sudo"
    assert r["definition"]["tenant"] == str(a.tenant_id), "tenant pinned, never '*'"
    rows = await list_authored(mssp_session, tenant_id=a.tenant_id)
    assert [x["response_playbook_id"] for x in rows] == ["authored-sudo"]
    assert rows[0]["status"] == "shadow"


async def test_validation_fails_closed(mssp_session: AsyncSession, seed_two_tenants):
    a, _ = seed_two_tenants
    with pytest.raises(ResponsePlaybookValidationError):
        await upsert_authored(
            mssp_session, tenant_id=a.tenant_id,
            definition={"id": "bad", "response": {"on_escalate": [{"capability": "rm"}]}},
        )


async def test_tenant_isolation(mssp_session: AsyncSession, seed_two_tenants):
    a, b = seed_two_tenants
    await upsert_authored(mssp_session, tenant_id=a.tenant_id, definition=DEF)
    await mssp_session.commit()
    assert await get_authored(
        mssp_session, tenant_id=b.tenant_id, response_playbook_id="authored-sudo"
    ) is None


async def _promoted(db, tenant_id, *, tag):
    r = await triage_event(
        db, tenant_id=tenant_id, source="wazuh", rule_id="5710", severity=12,
        asset_ids=[f"auth-{tag}"], initial_iocs=[], source_event_id=f"auth-{tag}-1",
        ts=datetime.now(UTC), description="sudo authored dispatch",
        evidence={"rule_groups": ["sudo"], "schema_version": 2},
    )
    assert r["action"] == "promoted"
    inv = UUID(r["investigation_id"])
    run = await active_run_for_case(db, inv)
    return inv, run


async def _dispatch(db, tenant_id, inv, run):
    return await dispatch_for_completed_run(
        db, tenant_id=tenant_id, investigation_id=inv, run_id=run,
        worker_disposition="escalate", effective_disposition="escalate",
        server_floor_veto=None, verdict_summary="v", verdict_confidence=0.9,
        enrichments={},
    )


async def test_active_authored_dispatches_shadow_does_not(
    mssp_session: AsyncSession, seed_two_tenants
):
    a, _ = seed_two_tenants
    await upsert_authored(mssp_session, tenant_id=a.tenant_id, definition=DEF)
    await mssp_session.commit()

    # SHADOW: matched + audited, but nothing enqueued.
    assert not await load_dispatchable(mssp_session, tenant_id=a.tenant_id, status="active")
    inv, run = await _promoted(mssp_session, a.tenant_id, tag="shadow")
    await mssp_session.commit()
    n = await _dispatch(mssp_session, a.tenant_id, inv, run)
    await mssp_session.commit()
    assert n == 0

    # ACTIVATE -> governs live.
    await set_authored_status(
        mssp_session, tenant_id=a.tenant_id, response_playbook_id="authored-sudo",
        status="active",
    )
    await mssp_session.commit()
    active = await load_dispatchable(mssp_session, tenant_id=a.tenant_id, status="active")
    assert [pb.id for pb in active] == ["authored-sudo"]

    inv2, run2 = await _promoted(mssp_session, a.tenant_id, tag="active")
    await mssp_session.commit()
    n2 = await _dispatch(mssp_session, a.tenant_id, inv2, run2)
    await mssp_session.commit()
    assert n2 == 1, "active authored playbook must dispatch live"

    rows = (
        await mssp_session.execute(
            text("SELECT count(*) FROM investigation_outbox "
                 "WHERE tenant_id = :t AND kind = :k"),
            {"t": str(a.tenant_id), "k": RESPONSE_OUTBOX_KIND},
        )
    ).scalar_one()
    assert rows == 1
    audits = (
        await mssp_session.execute(
            text("SELECT count(*) FROM audit_log WHERE tenant_id = :t AND action = :a"),
            {"t": str(a.tenant_id), "a": DISPATCH_AUDIT_ACTION},
        )
    ).scalar_one()
    assert audits >= 1


async def test_stored_definition_is_shadow_for_export(
    mssp_session: AsyncSession, seed_two_tenants
):
    """The stored definition is always status:shadow (Codex ph2 incr3 finding 3),
    so an export of a shadow row can't carry status:active and self-activate on a
    file rollout — even after the row is ACTIVATED (row status != definition
    status)."""
    a, _ = seed_two_tenants
    r = await upsert_authored(
        mssp_session, tenant_id=a.tenant_id,
        definition={**DEF, "status": "active"},  # author tries to force active
    )
    assert r["definition"]["status"] == "shadow"
    await set_authored_status(
        mssp_session, tenant_id=a.tenant_id, response_playbook_id="authored-sudo",
        status="active",
    )
    row = await get_authored(
        mssp_session, tenant_id=a.tenant_id, response_playbook_id="authored-sudo"
    )
    assert row["status"] == "active"  # row lifecycle
    assert row["definition"]["status"] == "shadow"  # exported bytes stay shadow


async def test_db_shadow_suppresses_file_active_same_id(
    mssp_session: AsyncSession, seed_two_tenants, tmp_path, monkeypatch
):
    """DB is the override layer (Codex ph2 incr3 finding 1): a file-active playbook
    and a DB row of the SAME id must be governed only by the DB row's status. A DB
    SHADOW row turns the file-active one OFF."""
    from soctalk.response.dispatch import _matched
    from soctalk.response.registry import reset_registry_cache as _reset

    a, _ = seed_two_tenants
    (tmp_path / "f.yaml").write_text(
        "id: authored-sudo\nversion: 1\nstatus: active\n"
        "applies_to: {rule_groups: [sudo]}\n"
        "response: {on_escalate: [{capability: annotate_investigation}]}\n"
    )
    monkeypatch.setenv("SOCTALK_RESPONSE_PLAYBOOK_DIR", str(tmp_path))
    _reset()
    try:
        # DB row of the same id, left SHADOW.
        await upsert_authored(mssp_session, tenant_id=a.tenant_id, definition=DEF)
        await mssp_session.commit()
        ids = frozenset({str(a.tenant_id)})
        active = await _matched(
            mssp_session, a.tenant_id, rule_groups={"sudo"}, rule_ids=set(),
            identifiers=ids, status="active",
        )
        assert [p.id for p in active] == [], (
            "a DB shadow row must suppress the file-active row of the same id"
        )
        shadow = await _matched(
            mssp_session, a.tenant_id, rule_groups={"sudo"}, rule_ids=set(),
            identifiers=ids, status="shadow",
        )
        assert [p.id for p in shadow] == ["authored-sudo"]
    finally:
        _reset()


async def test_deactivate_stops_dispatch(mssp_session: AsyncSession, seed_two_tenants):
    a, _ = seed_two_tenants
    await upsert_authored(mssp_session, tenant_id=a.tenant_id, definition=DEF)
    await set_authored_status(
        mssp_session, tenant_id=a.tenant_id, response_playbook_id="authored-sudo",
        status="active",
    )
    await set_authored_status(
        mssp_session, tenant_id=a.tenant_id, response_playbook_id="authored-sudo",
        status="shadow",
    )
    await mssp_session.commit()
    assert not await load_dispatchable(mssp_session, tenant_id=a.tenant_id, status="active")
