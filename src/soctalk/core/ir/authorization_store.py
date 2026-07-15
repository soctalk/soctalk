"""Durable AuthorizationFact store (tenant-scoped, RLS-enforced).

Typed facts (``models.authorization``) written by the ingest API, HIL answers, and
connectors. ``store_fact`` upserts by (tenant, fact_id). ``list_current_facts`` returns
every non-revoked, non-superseded fact for a tenant; the reasoning engine does the precise
activity matching, so expired or out-of-window facts are passed through deliberately (that
is what makes a stale ticket read as CONTRADICTED rather than ABSENT). ``revoke_fact`` is a
soft delete — the row survives for the audit trail. All calls run inside a
``tenant_context`` so RLS scopes them; ``tenant_id`` is passed explicitly as belt and
suspenders. Paired with alembic ``v1_0034_authorization_facts``.
"""

from __future__ import annotations

import json
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from soctalk.models.authorization import AUTHORIZATION_FACT_ADAPTER, AuthorizationFact


def _columns(fact: AuthorizationFact) -> dict[str, Any]:
    """Lift the queryable envelope fields out of a typed fact."""
    scope = fact.scope
    return {
        "fact_id": fact.id,
        "kind": fact.kind,
        "track": fact.track.value,
        "source_type": fact.source_type.value,
        "trust": int(fact.trust),
        "subject": scope.subject,
        "target": scope.target,
        "action": scope.action,
        "entity_name": getattr(fact, "name", None),
        "valid_from": fact.valid_from,
        "valid_until": fact.valid_until,
        "superseded_by": fact.superseded_by,
        "created_by": fact.created_by or "",
        "body": AUTHORIZATION_FACT_ADAPTER.dump_python(fact, mode="json"),
    }


async def store_fact(db: AsyncSession, *, tenant_id: UUID, fact: AuthorizationFact) -> None:
    """Insert a typed fact, or replace an existing one with the same (tenant, fact_id).

    A re-submit un-revokes the row (the latest assertion wins) — revocation is a distinct,
    explicit action via ``revoke_fact``.
    """
    c = _columns(fact)
    await db.execute(
        text(
            """
            INSERT INTO authorization_facts
              (id, tenant_id, fact_id, kind, track, source_type, trust,
               subject, target, action, entity_name, valid_from, valid_until,
               superseded_by, created_by, body)
            VALUES
              (:id, :t, :fid, :kind, :track, :st, :trust,
               :subject, :target, :action, :entity, :vf, :vu,
               :sup, :cby, CAST(:body AS jsonb))
            ON CONFLICT (tenant_id, fact_id) DO UPDATE SET
                kind = EXCLUDED.kind,
                track = EXCLUDED.track,
                source_type = EXCLUDED.source_type,
                trust = EXCLUDED.trust,
                subject = EXCLUDED.subject,
                target = EXCLUDED.target,
                action = EXCLUDED.action,
                entity_name = EXCLUDED.entity_name,
                valid_from = EXCLUDED.valid_from,
                valid_until = EXCLUDED.valid_until,
                superseded_by = EXCLUDED.superseded_by,
                body = EXCLUDED.body,
                revoked_at = NULL,
                revoked_by = NULL,
                revoke_reason = NULL
            """
        ),
        {
            "id": str(uuid4()),
            "t": str(tenant_id),
            "fid": c["fact_id"],
            "kind": c["kind"],
            "track": c["track"],
            "st": c["source_type"],
            "trust": c["trust"],
            "subject": c["subject"],
            "target": c["target"],
            "action": c["action"],
            "entity": c["entity_name"],
            "vf": c["valid_from"],
            "vu": c["valid_until"],
            "sup": c["superseded_by"],
            "cby": c["created_by"],
            "body": json.dumps(c["body"]),
        },
    )


async def list_current_facts(db: AsyncSession, *, tenant_id: UUID) -> list[AuthorizationFact]:
    """All non-revoked, non-superseded facts for the tenant, as typed facts."""
    rows = (
        await db.execute(
            text(
                "SELECT body FROM authorization_facts "
                "WHERE tenant_id = :t AND revoked_at IS NULL AND superseded_by IS NULL"
            ),
            {"t": str(tenant_id)},
        )
    ).mappings().all()
    return [AUTHORIZATION_FACT_ADAPTER.validate_python(r["body"]) for r in rows]


async def get_fact(db: AsyncSession, *, tenant_id: UUID, fact_id: str) -> dict[str, Any] | None:
    """The full row (including lifecycle columns) for one fact, or None."""
    row = (
        await db.execute(
            text("SELECT * FROM authorization_facts WHERE tenant_id = :t AND fact_id = :f"),
            {"t": str(tenant_id), "f": fact_id},
        )
    ).mappings().first()
    return dict(row) if row is not None else None


async def revoke_fact(
    db: AsyncSession,
    *,
    tenant_id: UUID,
    fact_id: str,
    revoked_by: UUID | None,
    reason: str | None,
) -> bool:
    """Soft-delete a fact. Returns True if a live fact was revoked, False if none matched."""
    res = await db.execute(
        text(
            "UPDATE authorization_facts "
            "SET revoked_at = now(), revoked_by = :by, revoke_reason = :r "
            "WHERE tenant_id = :t AND fact_id = :f AND revoked_at IS NULL"
        ),
        {
            "t": str(tenant_id),
            "f": fact_id,
            "by": str(revoked_by) if revoked_by else None,
            "r": reason,
        },
    )
    return (res.rowcount or 0) > 0
