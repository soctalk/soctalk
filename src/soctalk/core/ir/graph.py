"""Entity-graph writer + readers (issue #24).

Lands an alert's typed entities as ``entities`` nodes (deterministic id,
upserted first/last seen) and its participation as ``entity_relationships``
observation edges (the alert TOUCHED each entity, with the entity's role and
an evidence ref to the #17 source event). Derived edges (host HAS_IP,
alert MAPS_TO_TECHNIQUE) are written with provenance + confidence.

Readers answer the questions the product promises: what else touched this
host, has this account done this before, MITRE coverage.
"""

from __future__ import annotations

from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from soctalk_entities import (
    EntityType,
    Role,
    TYPE_REGISTRY,
    canonical_value,
    entity_id,
    is_pair_allowed,
)
from soctalk_entities.model import RelationClass, RelationVerb, SourceReliability

# adapter entity type string -> our EntityType
_TYPE_MAP = {
    "host": EntityType.HOST, "user": EntityType.USER, "ip": EntityType.IP,
    "domain": EntityType.DOMAIN, "url": EntityType.URL, "hash": EntityType.HASH,
    "file": EntityType.FILE, "process": EntityType.PROCESS, "port": EntityType.PORT,
}
_ROLE_MAP = {r.value: r for r in Role}


async def _upsert_entity(
    db: AsyncSession, *, tenant_id: UUID, et: EntityType, value: str,
    occurred_at, attributes: dict[str, Any] | None = None,
) -> str:
    eid = entity_id(et, value)
    spec = TYPE_REGISTRY[et]
    await db.execute(
        text(
            """
            INSERT INTO entities
              (id, tenant_id, entity_type, canonical_value, attributes,
               retention_class, visibility, first_seen, last_seen)
            VALUES (:id, :t, :et, :cv, CAST(:attr AS JSONB), :ret, :vis,
                    CAST(:occ AS timestamptz), CAST(:occ AS timestamptz))
            ON CONFLICT (id, tenant_id) DO UPDATE SET
                last_seen = GREATEST(entities.last_seen, EXCLUDED.last_seen),
                first_seen = LEAST(entities.first_seen, EXCLUDED.first_seen)
            """
        ),
        {
            "id": eid, "t": str(tenant_id), "et": et.value,
            "cv": canonical_value(et, value),
            "attr": _json(attributes or {}),
            "ret": spec.retention_class.value,
            "vis": spec.default_audience.value,
            "occ": occurred_at,
        },
    )
    return eid


async def _add_relationship(
    db: AsyncSession, *, tenant_id: UUID, src_id: str, dst_id: str,
    verb: RelationVerb, relation_class: RelationClass,
    role: Role | None = None, occurred_at=None,
    reliability: SourceReliability = SourceReliability.TELEMETRY,
    asserter: str | None = None, confidence_score: int | None = None,
    source_event_id: str | None = None, investigation_id: UUID | None = None,
) -> None:
    await db.execute(
        text(
            """
            INSERT INTO entity_relationships
              (id, tenant_id, src_id, dst_id, verb, role, relation_class,
               occurred_at, recorded_at, reliability, asserter,
               confidence_score, source_event_id, investigation_id)
            VALUES (:id, :t, :s, :d, :v, :r, :rc,
                    CAST(:occ AS timestamptz), now(), :rel, :ast,
                    :conf, :seid, :inv)
            """
        ),
        {
            "id": str(uuid4()), "t": str(tenant_id), "s": src_id, "d": dst_id,
            "v": verb.value, "r": role.value if role else None,
            "rc": relation_class.value, "occ": occurred_at,
            "rel": reliability.value, "ast": asserter, "conf": confidence_score,
            "seid": source_event_id, "inv": str(investigation_id) if investigation_id else None,
        },
    )


async def land_alert_entities(
    db: AsyncSession, *, tenant_id: UUID, alert_id: UUID,
    investigation_id: UUID | None, entities: list[dict[str, Any]],
    mitre: dict[str, Any] | None, occurred_at, source_event_id: str | None,
) -> dict[str, int]:
    """Write the alert node, its typed entities, and observation edges.

    Returns counts for logging/tests. Idempotent-ish: entity upserts are
    ON CONFLICT; observation edges are append-only (one per occurrence).
    """
    alert_node = await _upsert_entity(
        db, tenant_id=tenant_id, et=EntityType.ALERT, value=str(alert_id),
        occurred_at=occurred_at,
    )

    n_entities = 0
    for e in entities or []:
        if not isinstance(e, dict):
            continue
        et = _TYPE_MAP.get(e.get("type"))
        val = e.get("value")
        if et is None or not val:
            continue
        node = await _upsert_entity(
            db, tenant_id=tenant_id, et=et, value=str(val), occurred_at=occurred_at,
            attributes={"source_field": e.get("source_field")} if e.get("source_field") else None,
        )
        role = _ROLE_MAP.get(e.get("role") or "")
        # The alert TOUCHED this entity, in the entity's stated role.
        await _add_relationship(
            db, tenant_id=tenant_id, src_id=alert_node, dst_id=node,
            verb=RelationVerb.TOUCHED, relation_class=RelationClass.OBSERVED,
            role=role, occurred_at=occurred_at, source_event_id=source_event_id,
            investigation_id=investigation_id,
        )
        n_entities += 1

    # Derived: alert MAPS_TO_TECHNIQUE for each MITRE technique on the rule.
    n_tech = 0
    for tech in (mitre or {}).get("ids", []) or (mitre or {}).get("techniques", []):
        tnode = await _upsert_entity(
            db, tenant_id=tenant_id, et=EntityType.TECHNIQUE, value=str(tech),
            occurred_at=occurred_at,
        )
        if is_pair_allowed(RelationVerb.MAPS_TO_TECHNIQUE, EntityType.ALERT, EntityType.TECHNIQUE):
            await _add_relationship(
                db, tenant_id=tenant_id, src_id=alert_node, dst_id=tnode,
                verb=RelationVerb.MAPS_TO_TECHNIQUE, relation_class=RelationClass.DERIVED,
                occurred_at=occurred_at, reliability=SourceReliability.EXTRACTION,
                asserter="component:triage@1", confidence_score=80,
                source_event_id=source_event_id, investigation_id=investigation_id,
            )
            n_tech += 1

    return {"entities": n_entities, "techniques": n_tech}


# ------------------------------------------------------------------- readers


async def entity_history(
    db: AsyncSession, *, tenant_id: UUID, entity_type: str, value: str,
) -> dict[str, Any]:
    """"What else touched this host / has this account done this before" —
    the alerts and investigations that touched an entity, over time."""
    et = _TYPE_MAP.get(entity_type)
    if et is None:
        return {"entity": None, "touches": []}
    eid = entity_id(et, value)
    rows = (await db.execute(
        text(
            """
            SELECT r.occurred_at, r.investigation_id, r.role, r.src_id
            FROM entity_relationships r
            WHERE r.tenant_id = :t AND r.dst_id = :e AND r.verb = 'touched'
            ORDER BY r.occurred_at DESC
            LIMIT 200
            """
        ),
        {"t": str(tenant_id), "e": eid},
    )).mappings().all()
    node = (await db.execute(
        text("SELECT first_seen, last_seen FROM entities WHERE id = :e AND tenant_id = :t"),
        {"e": eid, "t": str(tenant_id)},
    )).mappings().first()
    return {
        "entity": {"id": eid, "type": et.value, "value": value,
                   "first_seen": node["first_seen"].isoformat() if node else None,
                   "last_seen": node["last_seen"].isoformat() if node else None},
        "touch_count": len(rows),
        "touches": [
            {"occurred_at": r["occurred_at"].isoformat() if r["occurred_at"] else None,
             "investigation_id": str(r["investigation_id"]) if r["investigation_id"] else None,
             "role": r["role"]}
            for r in rows
        ],
    }


async def mitre_coverage(db: AsyncSession, *, tenant_id: UUID) -> list[dict[str, Any]]:
    """Techniques seen in this tenant's alerts, with counts — the coverage
    surface (which ATT&CK techniques the environment actually exercises)."""
    rows = (await db.execute(
        text(
            """
            SELECT e.canonical_value AS technique, count(*) AS alert_count
            FROM entity_relationships r
            JOIN entities e ON e.id = r.dst_id AND e.tenant_id = r.tenant_id
            WHERE r.tenant_id = :t AND r.verb = 'maps_to_technique'
              AND e.entity_type = 'technique'
            GROUP BY e.canonical_value
            ORDER BY alert_count DESC
            """
        ),
        {"t": str(tenant_id)},
    )).mappings().all()
    return [{"technique": r["technique"], "alert_count": int(r["alert_count"])} for r in rows]


def _json(obj: Any) -> str:
    import json
    return json.dumps(obj, separators=(",", ":"), sort_keys=True)
