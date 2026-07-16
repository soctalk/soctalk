"""The typed effective-disposition envelope (issue #49).

Built server-side in ``complete_run()``'s transaction — the only place the
disposition is post-floor and committed. The envelope is a PUBLIC, versioned
contract: it selects response playbooks, feeds their ``when:`` conditions, and
is the exact payload the webhook connector hands to an external SOAR. Field
additions are API decisions; renames/removals bump ``ENVELOPE_VERSION``.
"""

from __future__ import annotations

from typing import Any
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from soctalk.response.models import ENVELOPE_VERSION


async def build_envelope(
    db: AsyncSession,
    *,
    tenant_id: UUID,
    investigation_id: UUID,
    run_id: UUID,
    worker_disposition: str | None,
    effective_disposition: str | None,
    server_floor_veto: str | None,
    verdict_summary: str | None,
    verdict_confidence: float | None,
    enrichments: dict[str, Any] | None,
) -> dict[str, Any]:
    """Assemble the envelope from the completion payload plus the evidence
    store (same LATERAL pattern as ``claim_run`` — rule semantics live on the
    alert's source events, and a later empty v1 event must not hide them)."""

    rows = (
        await db.execute(
            text(
                """
                SELECT a.rule_id, a.severity, a.initial_iocs,
                       se.mitre AS mitre, se.rule_groups AS rule_groups,
                       se.entities AS entities
                FROM alerts a
                LEFT JOIN LATERAL (
                    SELECT mitre, rule_groups, entities
                    FROM alert_source_events
                    WHERE alert_id = a.id
                    ORDER BY (mitre <> '{}'::jsonb OR entities <> '[]'::jsonb) DESC,
                             ingested_at DESC
                    LIMIT 1
                ) se ON true
                WHERE a.investigation_id = :c
                ORDER BY a.severity DESC, a.first_event_at DESC
                """
            ),
            {"c": str(investigation_id)},
        )
    ).mappings().all()

    rule_ids: list[str] = []
    rule_groups: list[str] = []
    techniques: list[str] = []
    entities: list[Any] = []
    iocs: list[Any] = []
    severity = 0
    for a in rows:
        severity = max(severity, int(a["severity"] or 0))
        if a["rule_id"] and str(a["rule_id"]) not in rule_ids:
            rule_ids.append(str(a["rule_id"]))
        for g in a["rule_groups"] or []:
            g = str(g).lower()
            if g not in rule_groups:
                rule_groups.append(g)
        mitre = a["mitre"] or {}
        if isinstance(mitre, dict):
            for t in mitre.get("id") or mitre.get("technique_ids") or []:
                if str(t) not in techniques:
                    techniques.append(str(t))
        for e in a["entities"] or []:
            if e not in entities:
                entities.append(e)
        for i in a["initial_iocs"] or []:
            if i not in iocs:
                iocs.append(i)

    # Worker-plane floor vetoes ride the enrichments blob (runs_worker/main.py
    # writes {"safety_floor": {"vetoes": [...]}} when its client-side floor
    # flipped the close). Server veto arrives as its own argument.
    worker_vetoes: list[str] = []
    safety_floor = (enrichments or {}).get("safety_floor")
    if isinstance(safety_floor, dict):
        worker_vetoes = [str(v) for v in safety_floor.get("vetoes") or []]

    return {
        "version": ENVELOPE_VERSION,
        "tenant_id": str(tenant_id),
        "investigation_id": str(investigation_id),
        "run_id": str(run_id),
        "disposition": effective_disposition,
        "worker_disposition": worker_disposition,
        "floor": {
            "server_veto": server_floor_veto,
            "worker_vetoes": worker_vetoes,
        },
        "verdict": {
            "summary": verdict_summary,
            "confidence": verdict_confidence,
        },
        "severity": severity,
        "rule": {"ids": rule_ids, "groups": rule_groups},
        "mitre": {"techniques": techniques},
        "entities": entities[:64],
        "iocs": iocs[:64],
    }


def condition_context(envelope: dict[str, Any]) -> dict[str, Any]:
    """Project the envelope onto the RESPONSE_STATE_CONTRACT surface for
    condition evaluation. Only declared fields appear — a condition cannot
    reach envelope internals the contract doesn't publish."""
    floor = envelope.get("floor") or {}
    verdict = envelope.get("verdict") or {}
    return {
        "disposition": envelope.get("disposition"),
        "worker_disposition": envelope.get("worker_disposition"),
        "floor_vetoed": bool(
            floor.get("server_veto") or floor.get("worker_vetoes")
        ),
        "verdict_confidence": verdict.get("confidence"),
        "severity": envelope.get("severity"),
        "rule": {
            "groups": (envelope.get("rule") or {}).get("groups") or [],
            "ids": (envelope.get("rule") or {}).get("ids") or [],
        },
        "mitre": {
            "techniques": (envelope.get("mitre") or {}).get("techniques") or [],
        },
    }
