"""Canonical entity model (#24): identity, vocabulary, graph writer/readers."""

from __future__ import annotations

import os
from datetime import datetime, timezone

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from soctalk.core.ir.graph import entity_history, land_alert_entities, mitre_coverage
from soctalk_entities import (
    EntityType,
    RelationVerb,
    entity_id,
    export_json_schema,
    is_pair_allowed,
)
from soctalk_entities.model import model_fingerprint

SKIP_INTEGRATION = os.getenv("SKIP_INTEGRATION", "0") == "1"


# ------------------------------------------------------------------ pure unit


def test_identity_deterministic_and_alias_stable():
    # Same natural key across case/whitespace churn => same id.
    a = entity_id(EntityType.HOST, "  WEB-01 ")
    b = entity_id(EntityType.HOST, "web-01")
    assert a == b
    # Distinct values differ; type is part of identity.
    assert entity_id(EntityType.HOST, "web-02") != a
    assert entity_id(EntityType.USER, "web-01") != a


def test_allowed_pair_matrix():
    assert is_pair_allowed(RelationVerb.HAS_IP, EntityType.HOST, EntityType.IP)
    assert not is_pair_allowed(RelationVerb.HAS_IP, EntityType.HOST, EntityType.HOST)
    assert not is_pair_allowed(RelationVerb.RESOLVED_TO, EntityType.IP, EntityType.DOMAIN)
    # Permissive for observation verbs not in the matrix.
    assert is_pair_allowed(RelationVerb.TOUCHED, EntityType.ALERT, EntityType.HOST)


def test_schema_export_matches_committed_artifact():
    import json
    from pathlib import Path

    committed = json.loads(
        (Path(__file__).resolve().parents[2] / "src" / "soctalk_entities" / "entity_schema.json").read_text()
    )
    live = export_json_schema()
    # The committed artifact must track the registry (additive-only CI gate).
    assert committed["fingerprint"] == model_fingerprint()
    assert committed["fingerprint"] == live["fingerprint"]
    assert set(committed["type_registry"]) == set(live["type_registry"])


# ----------------------------------------------------------------- integration

pytestmark_int = [
    pytest.mark.integration,
    pytest.mark.skipif(SKIP_INTEGRATION, reason="needs Postgres"),
]


@pytest.mark.integration
@pytest.mark.skipif(SKIP_INTEGRATION, reason="needs Postgres")
async def test_land_entities_and_read_history(
    mssp_session: AsyncSession, seed_two_tenants
):
    from uuid import uuid4
    tenant_a, _ = seed_two_tenants
    now = datetime.now(timezone.utc)

    # Land two alerts touching the same host with a MITRE technique.
    for seid in ("g1", "g2"):
        alert_id = uuid4()
        await mssp_session.execute(
            text("INSERT INTO alerts (id, tenant_id, source, rule_id, severity, "
                 "signature, first_event_at, last_event_at, event_count, status, visibility) "
                 "VALUES (:id, :t, 'wazuh', '5710', 9, :sig, now(), now(), 1, 'new', 'mssp_only')"),
            {"id": str(alert_id), "t": str(tenant_a.tenant_id), "sig": seid},
        )
        counts = await land_alert_entities(
            mssp_session, tenant_id=tenant_a.tenant_id, alert_id=alert_id,
            investigation_id=None,
            entities=[{"type": "host", "value": "srv-9", "role": "target"},
                      {"type": "user", "value": "root", "role": "actor"}],
            mitre={"ids": ["T1110"]}, occurred_at=now, source_event_id=seid,
        )
        assert counts == {"entities": 2, "techniques": 1}
    await mssp_session.commit()

    # "What else touched this host": both alerts show up.
    hist = await entity_history(
        mssp_session, tenant_id=tenant_a.tenant_id, entity_type="host", value="srv-9"
    )
    assert hist["entity"]["type"] == "host"
    assert hist["touch_count"] == 2

    # MITRE coverage: T1110 seen twice.
    cov = await mitre_coverage(mssp_session, tenant_id=tenant_a.tenant_id)
    assert {"technique": "T1110", "alert_count": 2} in cov


@pytest.mark.integration
@pytest.mark.skipif(SKIP_INTEGRATION, reason="needs Postgres")
async def test_entity_upsert_merges_first_last_seen(
    mssp_session: AsyncSession, seed_two_tenants
):
    from uuid import uuid4
    tenant_a, _ = seed_two_tenants
    a1 = uuid4()
    await mssp_session.execute(
        text("INSERT INTO alerts (id, tenant_id, source, rule_id, severity, signature, "
             "first_event_at, last_event_at, event_count, status, visibility) "
             "VALUES (:id, :t, 'wazuh', '1', 9, 's', now(), now(), 1, 'new', 'mssp_only')"),
        {"id": str(a1), "t": str(tenant_a.tenant_id)},
    )
    t_early = datetime(2026, 1, 1, tzinfo=timezone.utc)
    t_late = datetime(2026, 6, 1, tzinfo=timezone.utc)
    await land_alert_entities(mssp_session, tenant_id=tenant_a.tenant_id, alert_id=a1,
                              investigation_id=None,
                              entities=[{"type": "host", "value": "dup-host"}],
                              mitre={}, occurred_at=t_late, source_event_id="x1")
    await land_alert_entities(mssp_session, tenant_id=tenant_a.tenant_id, alert_id=a1,
                              investigation_id=None,
                              entities=[{"type": "host", "value": "dup-host"}],
                              mitre={}, occurred_at=t_early, source_event_id="x2")
    await mssp_session.commit()
    # One entity node; first_seen = earliest, last_seen = latest.
    row = (await mssp_session.execute(
        text("SELECT first_seen, last_seen FROM entities "
             "WHERE id = :e AND tenant_id = :t"),
        {"e": entity_id(EntityType.HOST, "dup-host"), "t": str(tenant_a.tenant_id)},
    )).mappings().one()
    assert row["first_seen"] == t_early
    assert row["last_seen"] == t_late
