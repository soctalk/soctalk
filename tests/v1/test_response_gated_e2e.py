"""Full gated response flow (#49 phase 2) — DB-backed, end to end.

playbook dispatches external_action -> routed to a proposal -> human approves ->
L1 executor drains the approved proposal -> signed POST to the operator endpoint
-> proposal executed + external_ref ledgered. Also proves the executor delegates
a non-response execute_proposal row to the core.ir tool path.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime
from uuid import UUID, uuid4

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from soctalk.core.ir.policies import set_tenant_policy
from soctalk.core.ir.runtime import (
    active_run_for_case,
    approve_proposal,
    execute_one,
)
from soctalk.core.ir.triage import triage_event
from soctalk.response.dispatch import dispatch_for_completed_run
from soctalk.response.executor import RESPONSE_KINDS, response_handlers
from soctalk.response.registry import reset_registry_cache

SKIP_INTEGRATION = os.getenv("SKIP_INTEGRATION", "0") == "1"

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(SKIP_INTEGRATION, reason="needs Postgres"),
]

EXTERNAL_PLAYBOOK = """
id: resp-external
version: 1
status: active
applies_to:
  rule_groups: [sudo]
response:
  on_escalate:
    - capability: external_action
      params: {endpoint: soar-primary, action: isolate_host, host: prod-web-01}
"""


@pytest.fixture
def external_registry(tmp_path, monkeypatch):
    (tmp_path / "ext.yaml").write_text(EXTERNAL_PLAYBOOK)
    monkeypatch.setenv("SOCTALK_RESPONSE_PLAYBOOK_DIR", str(tmp_path))
    reset_registry_cache()
    yield
    reset_registry_cache()


async def _promoted(db, tenant_id, *, tag):
    r = await triage_event(
        db, tenant_id=tenant_id, source="wazuh", rule_id="5710", severity=12,
        asset_ids=[f"ext-{tag}"], initial_iocs=[], source_event_id=f"ext-{tag}-1",
        ts=datetime.now(UTC), description="sudo for external-action e2e",
        evidence={"rule_groups": ["sudo"], "schema_version": 2},
    )
    assert r["action"] == "promoted"
    inv = UUID(r["investigation_id"])
    run = await active_run_for_case(db, inv)
    await db.commit()
    return inv, run


async def _drain(db):
    return await execute_one(db, "test-exec", response_handlers(), kinds=RESPONSE_KINDS)


async def test_external_action_full_gated_flow(
    mssp_session: AsyncSession, seed_two_tenants, external_registry, monkeypatch
):
    tenant_a, _ = seed_two_tenants
    # Operator configures the named endpoint (id -> url/secret). Playbook never
    # sees a URL; it named 'soar-primary'.
    await set_tenant_policy(
        mssp_session, tenant_a.tenant_id, "response_action_endpoints",
        {"soar-primary": {"url": "https://soar.example/act", "secret": "sek"}},
    )
    await mssp_session.commit()

    inv, run = await _promoted(mssp_session, tenant_a.tenant_id, tag="flow")
    await dispatch_for_completed_run(
        mssp_session, tenant_id=tenant_a.tenant_id, investigation_id=inv, run_id=run,
        worker_disposition="escalate", effective_disposition="escalate",
        server_floor_veto=None, verdict_summary="v", verdict_confidence=0.9,
        enrichments={},
    )
    await mssp_session.commit()

    # Drain the response_action row -> routes to a proposal (no POST yet).
    posted: dict = {}

    async def fake_post(self, url, content=None, headers=None, **kw):
        posted["url"] = url
        posted["content"] = content
        posted["headers"] = headers or {}

        class _R:
            status_code = 202
            headers = {"X-Request-Id": "soar-778"}

        return _R()

    # SSRF guard must see a routable address for the fake host.
    monkeypatch.setattr(
        "socket.getaddrinfo", lambda *a, **k: [(2, 1, 6, "", ("93.184.216.34", 443))]
    )
    monkeypatch.setattr("httpx.AsyncClient.post", fake_post)

    assert await _drain(mssp_session)
    await mssp_session.commit()
    assert not posted, "gated action must NOT post before approval"

    prop = (
        await mssp_session.execute(
            text("SELECT id, status FROM proposals WHERE tenant_id = :t "
                 "AND action_type = 'external_action'"),
            {"t": str(tenant_a.tenant_id)},
        )
    ).mappings().one()
    assert prop["status"] == "proposed"

    # Human approves -> enqueues execute_proposal.
    await approve_proposal(
        mssp_session, proposal_id=UUID(str(prop["id"])),
        approver_user_id=uuid4(), reason="approved for containment",
    )
    await mssp_session.commit()

    # Drain the execute_proposal row -> runs the handler -> signed POST.
    assert await _drain(mssp_session)
    await mssp_session.commit()

    assert posted["url"] == "https://soar.example/act"
    from soctalk.response.capabilities import SIGNATURE_HEADER, sign_webhook_body

    assert posted["headers"][SIGNATURE_HEADER] == sign_webhook_body(
        "sek", posted["content"]
    )
    import json as _json

    body = _json.loads(posted["content"])
    assert body["action"] == "isolate_host"
    assert body["params"]["host"] == "prod-web-01"
    assert "endpoint" not in body["params"] and "action" not in body["params"]

    # Proposal executed; ledger carries the remote ref.
    status = (
        await mssp_session.execute(
            text("SELECT status FROM proposals WHERE id = :id"),
            {"id": str(prop["id"])},
        )
    ).scalar_one()
    assert status == "executed"
    ledger = (
        await mssp_session.execute(
            text("SELECT kind, after FROM execution_log WHERE tenant_id = :t "
                 "AND subject_type = 'response_action'"),
            {"t": str(tenant_a.tenant_id)},
        )
    ).mappings().all()
    assert any(
        r["kind"] == "response_action.executed"
        and (r["after"] or {}).get("external_ref") == "soar-778"
        for r in ledger
    )


async def test_external_action_missing_endpoint_fails_not_posts(
    mssp_session: AsyncSession, seed_two_tenants, external_registry, monkeypatch
):
    """No endpoint configured → the approved execution fails (retry/ledger),
    never a POST to an unconfigured/blank target."""
    tenant_a, _ = seed_two_tenants
    inv, run = await _promoted(mssp_session, tenant_a.tenant_id, tag="noep")
    await dispatch_for_completed_run(
        mssp_session, tenant_id=tenant_a.tenant_id, investigation_id=inv, run_id=run,
        worker_disposition="escalate", effective_disposition="escalate",
        server_floor_veto=None, verdict_summary="v", verdict_confidence=0.9,
        enrichments={},
    )
    await mssp_session.commit()
    await _drain(mssp_session)
    await mssp_session.commit()

    prop = (
        await mssp_session.execute(
            text("SELECT id FROM proposals WHERE tenant_id = :t "
                 "AND action_type = 'external_action'"),
            {"t": str(tenant_a.tenant_id)},
        )
    ).scalar_one()
    await approve_proposal(
        mssp_session, proposal_id=UUID(str(prop)), approver_user_id=uuid4(),
        reason="approve",
    )
    await mssp_session.commit()

    posted = {"n": 0}

    async def fake_post(self, *a, **k):
        posted["n"] += 1
        raise AssertionError("must not POST without a configured endpoint")

    monkeypatch.setattr("httpx.AsyncClient.post", fake_post)
    await _drain(mssp_session)
    await mssp_session.commit()
    assert posted["n"] == 0

    status = (
        await mssp_session.execute(
            text("SELECT status FROM proposals WHERE id = :id"), {"id": str(prop)}
        )
    ).scalar_one()
    assert status == "failed"
