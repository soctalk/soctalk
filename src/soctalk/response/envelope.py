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

    # Join EVERY source event (not one representative): the envelope UNIONs MITRE,
    # rule groups, and entities across all of an alert's events (Codex ph2 MITRE
    # finding 2). Picking one event could let a later entity-only event hide an
    # earlier MITRE-bearing one, and a MITRE-only response playbook would then
    # never fire. Per-facet dedup happens in the aggregation loop below.
    rows = (
        await db.execute(
            text(
                """
                SELECT a.rule_id, a.severity, a.initial_iocs,
                       se.mitre AS mitre, se.rule_groups AS rule_groups,
                       se.entities AS entities
                FROM alerts a
                LEFT JOIN alert_source_events se ON se.alert_id = a.id
                WHERE a.investigation_id = :c
                ORDER BY a.severity DESC, a.first_event_at DESC
                """
            ),
            {"c": str(investigation_id)},
        )
    ).mappings().all()

    rule_ids: list[str] = []
    rule_groups: list[str] = []
    # ATT&CK, normalized to the codebase convention (core/ir/triage.py): the
    # MATCHABLE identifiers are the canonical Txxxx technique ids and the tactic
    # refs — NEVER the human-readable technique names, which are display-only and
    # unstable. So envelope.mitre.techniques carries the Txxxx ids (from
    # WireMitre.ids), .tactics carries the tactic refs, and .technique_names is
    # kept for the outbound payload but stays OUT of the condition/match contract.
    mitre_techniques: list[str] = []  # Txxxx ids
    mitre_tactics: list[str] = []
    mitre_names: list[str] = []
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
        # Stored evidence is WireMitre: {ids=Txxxx, tactics, techniques=names}.
        # Read the plural keys AND the legacy singular ones (id/tactic/technique)
        # some sources still emit (Codex ph2 MITRE finding 3), and tolerate scalar
        # (non-list) values without crashing. Tactics are matched as the source
        # provides them — Wazuh emits tactic NAMES (e.g. "Lateral Movement"), not
        # TA refs — so envelope.mitre.tactics carries those strings verbatim.
        mitre = a["mitre"] or {}
        if isinstance(mitre, dict):
            for target, keys in (
                (mitre_techniques, ("ids", "id")),
                (mitre_tactics, ("tactics", "tactic")),
                (mitre_names, ("techniques", "technique")),
            ):
                for key in keys:
                    raw = mitre.get(key)
                    if raw is None:
                        continue
                    vals = raw if isinstance(raw, list) else [raw]
                    for t in vals:
                        s = str(t)
                        if s and s not in target:
                            target.append(s)
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
        "mitre": {
            "techniques": mitre_techniques,  # Txxxx ids — matchable
            "tactics": mitre_tactics,  # tactic refs — matchable
            "technique_names": mitre_names,  # display only, NOT in the contract
        },
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
            "tactics": (envelope.get("mitre") or {}).get("tactics") or [],
        },
    }
