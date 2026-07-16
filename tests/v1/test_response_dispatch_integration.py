"""Response-playbook dispatch + executor (issue #49) — DB-backed.

Covers the #49 invariants end-to-end at the DB layer: enqueue happens with the
effective disposition (idempotent on replay), shadow playbooks audit and never
enqueue, the kill switch stops enqueue, and the executor drains the outbox
writing the per-action execution_log ledger. The HTTP surface (complete_run
route → dispatch) is exercised by the live e2e verify pass.
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
from soctalk.response.dispatch import (
    DISPATCH_AUDIT_ACTION,
    RESPONSE_OUTBOX_KIND,
    SHADOW_AUDIT_ACTION,
    dispatch_for_completed_run,
)
from soctalk.response.executor import response_handlers
from soctalk.response.registry import reset_registry_cache

SKIP_INTEGRATION = os.getenv("SKIP_INTEGRATION", "0") == "1"

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(SKIP_INTEGRATION, reason="needs Postgres"),
]

ACTIVE_PLAYBOOK = """
id: resp-int-sudo
version: 1
status: active
applies_to:
  rule_groups: [sudo]
response:
  on_escalate:
    - capability: annotate_investigation
      params: {body: "escalation handled by response playbook"}
  on_close:
    - capability: annotate_investigation
      params: {body: "close annotated"}
"""

SHADOW_PLAYBOOK = """
id: resp-int-shadow
version: 1
applies_to:
  rule_groups: [sudo]
response:
  on_escalate:
    - capability: notify_webhook
"""


@pytest.fixture
def playbook_dir(tmp_path, monkeypatch):
    (tmp_path / "active.yaml").write_text(ACTIVE_PLAYBOOK)
    (tmp_path / "shadow.yaml").write_text(SHADOW_PLAYBOOK)
    monkeypatch.setenv("SOCTALK_RESPONSE_PLAYBOOK_DIR", str(tmp_path))
    reset_registry_cache()
    yield tmp_path
    reset_registry_cache()


async def _promoted_investigation_and_run(
    db: AsyncSession, tenant_id, *, tag: str
) -> tuple[UUID, UUID]:
    """A real promoted investigation (sudo rule groups on the source event)
    plus an active run — the same evidence-store shape the envelope query
    reads in production."""
    result = await triage_event(
        db, tenant_id=tenant_id,
        source="wazuh", rule_id="5710", severity=12, asset_ids=[f"resp-{tag}"],
        initial_iocs=[], source_event_id=f"resp-{tag}-1", ts=datetime.now(UTC),
        description="sudo session for response dispatch test",
        evidence={
            "rule_groups": ["sudo", "pam"],
            "entities": [{"type": "host", "value": f"resp-{tag}", "role": "target"}],
            "mitre": {"id": ["T1078"]},
            "schema_version": 2,
        },
    )
    assert result["action"] == "promoted"
    investigation_id = UUID(result["investigation_id"])
    # Promotion already started the investigation's single active run.
    run_id = await active_run_for_case(db, investigation_id)
    assert run_id is not None
    await db.commit()
    return investigation_id, run_id


async def _dispatch(db, tenant_id, investigation_id, run_id, disposition="escalate"):
    return await dispatch_for_completed_run(
        db,
        tenant_id=tenant_id,
        investigation_id=investigation_id,
        run_id=run_id,
        worker_disposition=disposition,
        effective_disposition=disposition,
        server_floor_veto=None,
        verdict_summary="test verdict",
        verdict_confidence=0.9,
        enrichments={},
    )


async def _outbox_rows(db, tenant_id):
    rows = (
        await db.execute(
            text(
                "SELECT kind, idempotency_key, status, payload FROM investigation_outbox "
                "WHERE tenant_id = :t ORDER BY created_at"
            ),
            {"t": str(tenant_id)},
        )
    ).mappings().all()
    return [dict(r) for r in rows]


async def test_dispatch_enqueues_idempotently_and_audits(
    mssp_session: AsyncSession, seed_two_tenants, playbook_dir
):
    tenant_a, _ = seed_two_tenants
    inv, run = await _promoted_investigation_and_run(
        mssp_session, tenant_a.tenant_id, tag="enq"
    )

    n = await _dispatch(mssp_session, tenant_a.tenant_id, inv, run)
    await mssp_session.commit()
    assert n == 1

    rows = await _outbox_rows(mssp_session, tenant_a.tenant_id)
    assert len(rows) == 1
    row = rows[0]
    assert row["kind"] == RESPONSE_OUTBOX_KIND
    assert row["idempotency_key"] == f"response:{run}:resp-int-sudo@1:0"
    envelope = row["payload"]["envelope"]
    assert envelope["disposition"] == "escalate"
    assert "sudo" in envelope["rule"]["groups"]
    assert envelope["severity"] == 12

    # Replayed completion → ON CONFLICT no-op, still one row.
    await _dispatch(mssp_session, tenant_a.tenant_id, inv, run)
    await mssp_session.commit()
    assert len(await _outbox_rows(mssp_session, tenant_a.tenant_id)) == 1

    audits = (
        await mssp_session.execute(
            text(
                "SELECT action FROM audit_log WHERE tenant_id = :t AND action IN (:d, :s)"
            ),
            {"t": str(tenant_a.tenant_id), "d": DISPATCH_AUDIT_ACTION,
             "s": SHADOW_AUDIT_ACTION},
        )
    ).scalars().all()
    assert DISPATCH_AUDIT_ACTION in audits
    assert SHADOW_AUDIT_ACTION in audits, (
        "the shadow playbook matched the same envelope and must leave its audit trail"
    )


async def test_shadow_playbook_never_enqueues(
    mssp_session: AsyncSession, seed_two_tenants, tmp_path, monkeypatch
):
    (tmp_path / "shadow.yaml").write_text(SHADOW_PLAYBOOK)
    monkeypatch.setenv("SOCTALK_RESPONSE_PLAYBOOK_DIR", str(tmp_path))
    reset_registry_cache()
    try:
        tenant_a, _ = seed_two_tenants
        inv, run = await _promoted_investigation_and_run(
            mssp_session, tenant_a.tenant_id, tag="shdw"
        )
        n = await _dispatch(mssp_session, tenant_a.tenant_id, inv, run)
        await mssp_session.commit()
        assert n == 0
        assert not await _outbox_rows(mssp_session, tenant_a.tenant_id)
    finally:
        reset_registry_cache()


async def test_kill_switch_blocks_enqueue(
    mssp_session: AsyncSession, seed_two_tenants, playbook_dir, monkeypatch
):
    monkeypatch.setenv("SOCTALK_RESPONSE_DISPATCH_KILL", "1")
    tenant_a, _ = seed_two_tenants
    inv, run = await _promoted_investigation_and_run(
        mssp_session, tenant_a.tenant_id, tag="kill"
    )
    n = await _dispatch(mssp_session, tenant_a.tenant_id, inv, run)
    await mssp_session.commit()
    assert n == 0
    assert not await _outbox_rows(mssp_session, tenant_a.tenant_id)


async def test_executor_drains_annotation_and_writes_ledger(
    mssp_session: AsyncSession, seed_two_tenants, playbook_dir
):
    tenant_a, _ = seed_two_tenants
    inv, run = await _promoted_investigation_and_run(
        mssp_session, tenant_a.tenant_id, tag="exec"
    )
    await _dispatch(mssp_session, tenant_a.tenant_id, inv, run)
    await mssp_session.commit()

    from soctalk.core.ir.runtime import execute_one

    did = await execute_one(mssp_session, "test-executor", response_handlers())
    await mssp_session.commit()
    assert did is True

    rows = await _outbox_rows(mssp_session, tenant_a.tenant_id)
    assert rows[0]["status"] == "succeeded"

    note = (
        await mssp_session.execute(
            text(
                "SELECT body, author_kind, author_id FROM notes "
                "WHERE tenant_id = :t AND investigation_id = :c"
            ),
            {"t": str(tenant_a.tenant_id), "c": str(inv)},
        )
    ).mappings().first()
    assert note is not None
    assert "escalation handled by response playbook" in note["body"]
    assert note["author_kind"] == "system"
    assert note["author_id"] == "response:resp-int-sudo"

    ledger = (
        await mssp_session.execute(
            text(
                "SELECT kind, subject_id, after, versions FROM execution_log "
                "WHERE tenant_id = :t AND subject_type = 'response_action'"
            ),
            {"t": str(tenant_a.tenant_id)},
        )
    ).mappings().all()
    assert len(ledger) == 1
    entry = dict(ledger[0])
    assert entry["kind"] == "response_action.executed"
    assert entry["subject_id"] == f"response:{run}:resp-int-sudo@1:0"
    assert entry["versions"]["response_playbook"] == "resp-int-sudo@1"
    assert entry["after"]["capability"] == "annotate_investigation"


async def test_executor_webhook_posts_signed_envelope(
    mssp_session: AsyncSession, seed_two_tenants, tmp_path, monkeypatch
):
    (tmp_path / "hook.yaml").write_text(
        """
id: resp-int-hook
version: 1
status: active
applies_to: {rule_groups: [sudo]}
response:
  on_escalate:
    - capability: notify_webhook
"""
    )
    monkeypatch.setenv("SOCTALK_RESPONSE_PLAYBOOK_DIR", str(tmp_path))
    reset_registry_cache()
    try:
        tenant_a, _ = seed_two_tenants
        from soctalk.core.ir.policies import set_tenant_policy

        await set_tenant_policy(
            mssp_session, tenant_a.tenant_id,
            "response_webhook_url", "https://soar.example/hook",
        )
        await set_tenant_policy(
            mssp_session, tenant_a.tenant_id, "response_webhook_secret", "s3cret"
        )
        inv, run = await _promoted_investigation_and_run(
            mssp_session, tenant_a.tenant_id, tag="hook"
        )
        await _dispatch(mssp_session, tenant_a.tenant_id, inv, run)
        await mssp_session.commit()

        captured: dict = {}

        async def fake_post(self, url, content=None, headers=None, **kw):
            captured["url"] = url
            captured["content"] = content
            captured["headers"] = headers or {}

            class _Resp:
                status_code = 202
                headers = {"X-Request-Id": "remote-42"}

            return _Resp()

        monkeypatch.setattr("httpx.AsyncClient.post", fake_post)

        from soctalk.core.ir.runtime import execute_one

        assert await execute_one(mssp_session, "test-executor", response_handlers())
        await mssp_session.commit()

        assert captured["url"] == "https://soar.example/hook"
        from soctalk.response.capabilities import (
            SIGNATURE_HEADER,
            sign_webhook_body,
        )

        assert captured["headers"][SIGNATURE_HEADER] == sign_webhook_body(
            "s3cret", captured["content"]
        ), "signature must verify over the exact bytes sent"

        row = (
            await mssp_session.execute(
                text(
                    "SELECT status, external_ref FROM investigation_outbox "
                    "WHERE tenant_id = :t AND kind = :k"
                ),
                {"t": str(tenant_a.tenant_id), "k": RESPONSE_OUTBOX_KIND},
            )
        ).mappings().first()
        assert row["status"] == "succeeded"
        assert row["external_ref"] == "remote-42"
    finally:
        reset_registry_cache()
