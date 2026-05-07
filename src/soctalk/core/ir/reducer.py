"""Deterministic reducer over investigation_events → investigation_facts projection.

Contract (see ``docs/v1/P2-implementation-plan.md`` §b):

- Input: ordered stream of events for an investigation.
- Output: projected facts (hypotheses, directives, policies, timeline).
- Pure: given `(state, event) → state'`. Re-applying all events from
  seq 0 must produce the same final state (replay-safe).
- Atomic: the event append and projection update run in one
  transaction in the runtime.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from soctalk.core.ir.events import EventKind


@dataclass
class Facts:
    """In-memory shape of the investigation_facts projection."""

    hypotheses: list[dict[str, Any]] = field(default_factory=list)
    active_directives: list[dict[str, Any]] = field(default_factory=list)
    active_policies: list[dict[str, Any]] = field(default_factory=list)
    timeline_summary: list[dict[str, Any]] = field(default_factory=list)
    applied_seq: int = 0

    def as_dict(self) -> dict[str, Any]:
        return {
            "hypotheses": self.hypotheses,
            "active_directives": self.active_directives,
            "active_policies": self.active_policies,
            "timeline_summary": self.timeline_summary,
            "applied_seq": self.applied_seq,
        }


# ---------------------------------------------------------------------------
# Reducer
# ---------------------------------------------------------------------------


def apply_event(state: Facts, kind: str, payload: dict[str, Any], seq: int) -> Facts:
    """Apply a single event to the facts state.

    Pure function. Returns a NEW state — does not mutate input.
    """

    s = copy.deepcopy(state)
    s.applied_seq = max(s.applied_seq, seq)

    try:
        ek = EventKind(kind)
    except ValueError:
        return s  # unknown kind, no-op (forward-compat)

    if ek == EventKind.ALERT_INGESTED:
        # Seed the first hypothesis if none exists.
        if not s.hypotheses:
            rule = payload.get("rule_id")
            s.hypotheses.append(
                {
                    "id": "root",
                    "label": payload.get("initial_hypothesis", "unknown"),
                    "confidence": payload.get("ai_confidence", 0.5),
                    "rationale": f"seeded from rule={rule}",
                }
            )

    elif ek == EventKind.HYPOTHESIS_UPDATED:
        bid = payload["id"]
        replaced = False
        for h in s.hypotheses:
            if h["id"] == bid:
                h.update({
                    k: v for k, v in payload.items() if k in {
                        "label", "confidence", "rationale", "parent"
                    }
                })
                replaced = True
                break
        if not replaced:
            s.hypotheses.append(
                {
                    "id": bid,
                    "label": payload.get("label", ""),
                    "confidence": payload.get("confidence", 0.5),
                    "rationale": payload.get("rationale", ""),
                    "parent": payload.get("parent"),
                }
            )

    elif ek == EventKind.CONFIDENCE_RECALIBRATED:
        for h in s.hypotheses:
            updated = payload.get("confidences", {}).get(h["id"])
            if updated is not None:
                h["confidence"] = updated

    elif ek == EventKind.TIMELINE_ENTRY:
        entry = {
            "seq": seq,
            "ts": payload.get("ts"),
            "summary": payload.get("summary", ""),
            "source_event_id": payload.get("source_event_id"),
        }
        s.timeline_summary.append(entry)
        # Keep the timeline bounded in the projection; full log is audit.
        if len(s.timeline_summary) > 100:
            s.timeline_summary = s.timeline_summary[-100:]

    elif ek == EventKind.DIRECTIVE_ADDED:
        did = payload["id"]
        if not any(d["id"] == did for d in s.active_directives):
            s.active_directives.append(
                {"id": did, "text": payload.get("text", ""), "scope": payload.get("scope")}
            )

    elif ek == EventKind.DIRECTIVE_REMOVED:
        did = payload["id"]
        s.active_directives = [d for d in s.active_directives if d["id"] != did]

    elif ek == EventKind.POLICY_BOUND:
        pid = payload["id"]
        if not any(p["id"] == pid for p in s.active_policies):
            s.active_policies.append(
                {"id": pid, "version": payload.get("version")}
            )

    elif ek == EventKind.ANALYST_CORRECTION:
        # Targeted override: {path: "hypotheses.<id>.confidence", value: 0.3}
        # Simple dotted-path setter.
        path = payload.get("path", "")
        value = payload.get("value")
        _apply_correction(s, path, value)

    # REOPENED / AUTO_CLOSED / STATUS_CHANGED / IOC_* / ASSET_* are
    # captured in the investigation row / investigation_iocs / investigation_assets tables, not
    # in facts. Leave them to the investigation-state side.

    return s


def _apply_correction(state: Facts, path: str, value: Any) -> None:
    """Apply a dotted path correction. Supports the subset we need in MVP.

    Recognized paths:
      hypotheses.<id>.{label,confidence,rationale}
      directives.<id>.text
    """

    parts = path.split(".")
    if len(parts) == 3 and parts[0] == "hypotheses":
        bid = parts[1]
        field_name = parts[2]
        for h in state.hypotheses:
            if h["id"] == bid and field_name in {"label", "confidence", "rationale"}:
                h[field_name] = value
                return
    if len(parts) == 3 and parts[0] == "directives" and parts[2] == "text":
        bid = parts[1]
        for d in state.active_directives:
            if d["id"] == bid:
                d["text"] = value
                return
    # Silent no-op for unrecognized paths (forward-compat).


# ---------------------------------------------------------------------------
# DB integration
# ---------------------------------------------------------------------------


async def load_facts(db: AsyncSession, investigation_id: UUID) -> Facts:
    row = (
        await db.execute(
            text(
                "SELECT hypotheses, active_directives, active_policies, "
                "       timeline_summary, applied_seq "
                "FROM investigation_facts WHERE investigation_id = :c"
            ),
            {"c": str(investigation_id)},
        )
    ).mappings().first()
    if row is None:
        return Facts()
    return Facts(
        hypotheses=list(row["hypotheses"] or []),
        active_directives=list(row["active_directives"] or []),
        active_policies=list(row["active_policies"] or []),
        timeline_summary=list(row["timeline_summary"] or []),
        applied_seq=row["applied_seq"] or 0,
    )


async def save_facts(
    db: AsyncSession, tenant_id: UUID, investigation_id: UUID, facts: Facts
) -> None:
    """Upsert the projection row."""

    await db.execute(
        text(
            """
            INSERT INTO investigation_facts
              (investigation_id, tenant_id, hypotheses, active_directives,
               active_policies, timeline_summary, applied_seq, updated_at)
            VALUES
              (:investigation_id, :tenant_id,
               CAST(:hypotheses AS JSONB), CAST(:directives AS JSONB),
               CAST(:policies AS JSONB), CAST(:timeline AS JSONB),
               :applied_seq, now())
            ON CONFLICT (investigation_id) DO UPDATE SET
              hypotheses       = EXCLUDED.hypotheses,
              active_directives = EXCLUDED.active_directives,
              active_policies  = EXCLUDED.active_policies,
              timeline_summary = EXCLUDED.timeline_summary,
              applied_seq      = EXCLUDED.applied_seq,
              updated_at       = now()
            """
        ),
        {
            "investigation_id": str(investigation_id),
            "tenant_id": str(tenant_id),
            "hypotheses": _json_dumps(facts.hypotheses),
            "directives": _json_dumps(facts.active_directives),
            "policies": _json_dumps(facts.active_policies),
            "timeline": _json_dumps(facts.timeline_summary),
            "applied_seq": facts.applied_seq,
        },
    )


async def replay(db: AsyncSession, tenant_id: UUID, investigation_id: UUID) -> Facts:
    """Drop + re-apply. Used by the replay-safety test and rare rebuilds."""

    rows = (
        await db.execute(
            text(
                "SELECT seq, kind, payload FROM investigation_events "
                "WHERE investigation_id = :c ORDER BY seq ASC"
            ),
            {"c": str(investigation_id)},
        )
    ).mappings().all()

    state = Facts()
    for row in rows:
        state = apply_event(state, row["kind"], dict(row["payload"]), row["seq"])
    await save_facts(db, tenant_id, investigation_id, state)
    return state


def _json_dumps(obj: Any) -> str:
    import json

    return json.dumps(obj, default=str)


__all__ = [
    "Facts",
    "apply_event",
    "load_facts",
    "replay",
    "save_facts",
]
