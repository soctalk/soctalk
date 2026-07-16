"""Durable AuthorizationFact store (v1_0034): schema round-trip, tenant filtering, soft-delete."""

from __future__ import annotations

import os
from datetime import datetime, timezone

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from soctalk.core.ir.authorization_store import (
    _columns,
    get_fact,
    list_current_facts,
    revoke_fact,
    store_fact,
)
from soctalk.models.authorization import (
    AUTHORIZATION_FACT_ADAPTER,
    AuthorizationEntityKind,
    AuthorizationTrack,
    ChangeFreezeFact,
    EntityContextFact,
    FactScope,
    FreezeScope,
    GrantClass,
    GrantFact,
    PolicyApplicability,
    ProhibitionFact,
    RecurringWindow,
)

SKIP_INTEGRATION = os.getenv("SKIP_INTEGRATION", "0") == "1"
integration = pytest.mark.skipif(SKIP_INTEGRATION, reason="needs Postgres")


def _sample_facts() -> list:
    """One valid fact of each kind (account track)."""
    return [
        GrantFact(
            id="G1",
            track=AuthorizationTrack.ACCOUNT,
            grant_class=GrantClass.CHANGE_TICKET,
            scope=FactScope(
                subject="svc-deploy", target="db-01", action="sudo-exec",
                recurring_window=RecurringWindow(start="01:00", end="04:00"),
            ),
            valid_until=datetime(2026, 7, 31, tzinfo=timezone.utc),
        ),
        ProhibitionFact(
            id="P1",
            track=AuthorizationTrack.ACCOUNT,
            forbid_action="sudo-exec",
            applies_to=PolicyApplicability(data_class=["pci"], env=["prod"]),
            break_glass_exception=True,
        ),
        ChangeFreezeFact(
            id="F1",
            track=AuthorizationTrack.ACCOUNT,
            freeze_scope=FreezeScope(envs=["prod"]),
            start=datetime(2026, 7, 10, tzinfo=timezone.utc),
            end=datetime(2026, 7, 12, tzinfo=timezone.utc),
        ),
        EntityContextFact(
            id="E1",
            track=AuthorizationTrack.ACCOUNT,
            entity_type=AuthorizationEntityKind.ASSET,
            name="db-01",
            data_classification="pci",
            environment="prod",
        ),
    ]


def test_columns_and_body_roundtrip_all_kinds():
    """DB-free: the lifted columns are correct and body round-trips through the schema."""
    for fact in _sample_facts():
        cols = _columns(fact)
        assert cols["fact_id"] == fact.id
        assert cols["kind"] == fact.kind
        assert cols["track"] == fact.track.value
        # body must reconstruct an identical typed fact
        back = AUTHORIZATION_FACT_ADAPTER.validate_python(cols["body"])
        assert back == fact
    # scope/entity columns are lifted for lookup
    g, p, f, e = _sample_facts()
    assert _columns(g)["subject"] == "svc-deploy" and _columns(g)["target"] == "db-01"
    assert _columns(e)["entity_name"] == "db-01"


@integration
async def test_store_lists_and_isolates_by_tenant(mssp_session: AsyncSession, seed_two_tenants):
    a, b = seed_two_tenants
    for fact in _sample_facts():
        await store_fact(mssp_session, tenant_id=a.tenant_id, fact=fact)
    await mssp_session.commit()

    got = await list_current_facts(mssp_session, tenant_id=a.tenant_id)
    assert {f.id for f in got} == {"G1", "P1", "F1", "E1"}
    assert {f.kind for f in got} == {"grant", "prohibition", "change_freeze", "entity_context"}
    # a different tenant sees none of them
    assert await list_current_facts(mssp_session, tenant_id=b.tenant_id) == []


@integration
async def test_revoke_soft_deletes_and_survives(mssp_session: AsyncSession, seed_two_tenants):
    a, _ = seed_two_tenants
    for fact in _sample_facts():
        await store_fact(mssp_session, tenant_id=a.tenant_id, fact=fact)
    await mssp_session.commit()

    ok = await revoke_fact(
        mssp_session, tenant_id=a.tenant_id, fact_id="G1",
        revoked_by=a.admin_user_id, reason="ticket expired",
    )
    await mssp_session.commit()
    assert ok is True

    live = {f.id for f in await list_current_facts(mssp_session, tenant_id=a.tenant_id)}
    assert live == {"P1", "F1", "E1"}  # revoked fact drops out

    row = await get_fact(mssp_session, tenant_id=a.tenant_id, fact_id="G1")
    assert row is not None and row["revoked_at"] is not None
    assert row["revoke_reason"] == "ticket expired"  # audit metadata survives

    # revoking an already-revoked fact is a no-op
    again = await revoke_fact(
        mssp_session, tenant_id=a.tenant_id, fact_id="G1", revoked_by=None, reason=None
    )
    assert again is False


@integration
async def test_context_for_alert_binds_store_facts(mssp_session: AsyncSession, seed_two_tenants):
    """Store-primary consumption: the claim-time helper builds an AuthorizationContext from the
    stored facts + the activity extracted from the alert's entities."""
    from datetime import datetime, timezone

    from soctalk.core.ir.authz_shadow import authorization_context_for_alert

    a, _ = seed_two_tenants
    for fact in _sample_facts():
        await store_fact(mssp_session, tenant_id=a.tenant_id, fact=fact)
    await mssp_session.commit()

    ctx = await authorization_context_for_alert(
        mssp_session,
        tenant_id=a.tenant_id,
        source="wazuh",
        rule_id="5402",
        entities=[{"type": "host", "value": "db-01"}, {"type": "user", "value": "svc-deploy"}],
        ts=datetime.now(timezone.utc),
    )
    assert ctx is not None
    assert ctx["activity"]["host"] == "db-01"
    assert ctx["activity"]["account"] == "svc-deploy"
    assert ctx["activity"]["action"] == "5402"
    assert {f["id"] for f in ctx["facts"]} == {"G1", "P1", "F1", "E1"}

    # no host entity -> no activity -> None (the fixture path applies instead)
    none_ctx = await authorization_context_for_alert(
        mssp_session, tenant_id=a.tenant_id, source="wazuh", rule_id="r",
        entities=[{"type": "user", "value": "x"}], ts=datetime.now(timezone.utc),
    )
    assert none_ctx is None


@integration
async def test_resubmit_upserts_and_unrevokes(mssp_session: AsyncSession, seed_two_tenants):
    a, _ = seed_two_tenants
    fact = _sample_facts()[0]  # G1
    await store_fact(mssp_session, tenant_id=a.tenant_id, fact=fact)
    await revoke_fact(mssp_session, tenant_id=a.tenant_id, fact_id="G1", revoked_by=None, reason="x")
    await mssp_session.commit()
    assert "G1" not in {f.id for f in await list_current_facts(mssp_session, tenant_id=a.tenant_id)}

    # re-submitting the fact clears the revocation (the latest assertion wins)
    await store_fact(mssp_session, tenant_id=a.tenant_id, fact=fact)
    await mssp_session.commit()
    assert "G1" in {f.id for f in await list_current_facts(mssp_session, tenant_id=a.tenant_id)}


@integration
async def test_review_gate_hides_pending_tenant_facts(
    mssp_session: AsyncSession, seed_two_tenants
):
    """The load-bearing safety gate (Phase 2b): a tenant-asserted fact lands 'pending' and is
    INVISIBLE to the engine's read (list_current_facts) until an MSSP analyst approves it; a
    rejected one never becomes visible."""
    from soctalk.core.ir.authorization_store import list_facts_with_status, set_review_status
    from soctalk.models.authorization import AuthorizationSourceType, TRUST_TIER

    a, _ = seed_two_tenants

    def _tenant_grant(fid: str, target: str) -> GrantFact:
        g = GrantFact(
            id=fid, track=AuthorizationTrack.ACCOUNT, grant_class=GrantClass.STANDING_BASELINE,
            scope=FactScope(subject="svc", target=target, action="sudo-exec"),
        )
        g.source_type = AuthorizationSourceType.TENANT_ASSERTED
        g.trust = TRUST_TIER[g.source_type]
        return g

    # pending: invisible to the engine, visible to the review queue
    await store_fact(
        mssp_session, tenant_id=a.tenant_id, fact=_tenant_grant("ta:x", "db-01"),
        review_status="pending",
    )
    await mssp_session.commit()
    assert await list_current_facts(mssp_session, tenant_id=a.tenant_id) == []
    pending = await list_facts_with_status(
        mssp_session, tenant_id=a.tenant_id, statuses=("pending",)
    )
    assert len(pending) == 1 and pending[0]["review_status"] == "pending"
    assert pending[0]["source_type"] == "tenant_asserted" and pending[0]["trust"] == 20

    # reject -> still invisible to the engine
    assert await set_review_status(
        mssp_session, tenant_id=a.tenant_id, fact_id="ta:x", status="rejected", reviewed_by=None
    )
    await mssp_session.commit()
    assert await list_current_facts(mssp_session, tenant_id=a.tenant_id) == []

    # a second pending fact, approved -> now live to the engine
    await store_fact(
        mssp_session, tenant_id=a.tenant_id, fact=_tenant_grant("ta:y", "db-02"),
        review_status="pending",
    )
    await mssp_session.commit()
    assert await set_review_status(
        mssp_session, tenant_id=a.tenant_id, fact_id="ta:y", status="approved", reviewed_by=None
    )
    await mssp_session.commit()
    live = await list_current_facts(mssp_session, tenant_id=a.tenant_id)
    assert [f.id for f in live] == ["ta:y"]
