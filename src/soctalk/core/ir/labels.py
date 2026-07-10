"""Correlation label capture (issue #30 substrate).

Analyst grouping judgments — the supervised signal the future learned
scorer will train on. Captured now so labels accumulate before the scorer
exists. The scorer itself (embeddings, pgvector, tier-0 adjudicator) is
gated behind a labeled offline spike and is NOT built here.

- merge: two investigations were the same incident (a false SPLIT — the
  deterministic predicate should have grouped them). Alerts from ``other``
  move into ``keep``; ``other`` is closed as merged.
- detach: an alert didn't belong (a false ATTACH — the predicate
  over-grouped). The alert is moved to a fresh investigation.
- confirm: the grouping was correct (a positive label).

All are tenant-scoped and audited.
"""

from __future__ import annotations

from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from soctalk.core.observability.audit import log_audit

# Statuses from which an investigation can no longer transition.
TERMINAL_STATUSES = (
    "closed",
    "auto_closed_fp",
    "closed_fp",
    "closed_tp",
    "cancelled",
)


async def cancel_investigation(
    db: AsyncSession, *, tenant_id: UUID, investigation_id: UUID,
    reason: str | None = None, actor: str = "analyst",
) -> str:
    """Analyst cancels an investigation — a terminal transition.

    Sets status to ``cancelled``, terminates the live run so no worker
    claims an orphan (the claim query also guards on investigation status),
    and appends a ``STATUS_CHANGED`` event for the timeline.

    Assumes the caller has established the correct tenant scope (the
    BYPASSRLS MSSP session, or an app session inside ``tenant_context``) —
    same contract as :func:`merge_investigations`.

    Raises ``LookupError`` if the investigation is absent in scope, and
    ``ValueError`` if it is already in a terminal state.
    """
    from soctalk.core.ir.events import EventKind, append_event
    from soctalk.core.ir.runtime import consume_new_events

    current = (
        await db.execute(
            text(
                "SELECT status FROM investigations "
                "WHERE id = :id AND tenant_id = :t"
            ),
            {"id": str(investigation_id), "t": str(tenant_id)},
        )
    ).scalar_one_or_none()
    if current is None:
        raise LookupError("investigation not found")
    if current in TERMINAL_STATUSES:
        raise ValueError(f"already {current}")

    await db.execute(
        text(
            "UPDATE investigations SET status = 'cancelled', closed_at = now(), "
            "close_reason = COALESCE(:reason, close_reason, 'cancelled by analyst'), "
            "updated_at = now() WHERE id = :id AND tenant_id = :t"
        ),
        {"reason": reason, "id": str(investigation_id), "t": str(tenant_id)},
    )
    await db.execute(
        text(
            "UPDATE investigation_runs SET status = 'failed', ended_at = now(), "
            "last_error = 'investigation cancelled' "
            "WHERE tenant_id = :t AND investigation_id = :id "
            "  AND status IN ('active','paused','waiting_on_gate','halted_budget')"
        ),
        {"t": str(tenant_id), "id": str(investigation_id)},
    )
    await append_event(
        db, tenant_id=tenant_id, investigation_id=investigation_id, run_id=None,
        kind=EventKind.STATUS_CHANGED,
        payload={"status": "cancelled", "reason": reason, "actor": actor},
        producer=actor,
    )
    # Advance the projection past the event we just wrote.
    await consume_new_events(db, tenant_id, investigation_id)
    await log_audit(
        db, action="ir.investigation.cancel", actor_principal="analyst",
        actor_id=actor, tenant_id=tenant_id,
        resource_type="investigation", resource_id=str(investigation_id),
        notes=reason,
    )
    return "cancelled"


async def _record_label(
    db: AsyncSession, *, tenant_id: UUID, label: str,
    investigation_id: UUID | None = None,
    other_investigation_id: UUID | None = None,
    alert_id: UUID | None = None,
    reviewer: str | None = None, note: str | None = None,
) -> None:
    await db.execute(
        text(
            """
            INSERT INTO correlation_labels
              (id, tenant_id, label, investigation_id, other_investigation_id,
               alert_id, reviewer, note)
            VALUES (:id, :t, :lb, :inv, :oinv, :al, :rev, :note)
            """
        ),
        {
            "id": str(uuid4()), "t": str(tenant_id), "lb": label,
            "inv": str(investigation_id) if investigation_id else None,
            "oinv": str(other_investigation_id) if other_investigation_id else None,
            "al": str(alert_id) if alert_id else None,
            "rev": reviewer, "note": note,
        },
    )


async def merge_investigations(
    db: AsyncSession, *, tenant_id: UUID, keep_id: UUID, other_id: UUID,
    reviewer: str | None = None, note: str | None = None,
) -> dict[str, Any]:
    """Analyst merges two investigations (false split). Moves ``other``'s
    alerts + entity keys into ``keep``, closes ``other`` as merged, records
    a merge label."""
    await db.execute(
        text("UPDATE alerts SET investigation_id = :keep "
             "WHERE tenant_id = :t AND investigation_id = :other"),
        {"keep": str(keep_id), "t": str(tenant_id), "other": str(other_id)},
    )
    await db.execute(
        text("UPDATE alert_entity_keys SET investigation_id = :keep "
             "WHERE tenant_id = :t AND investigation_id = :other"),
        {"keep": str(keep_id), "t": str(tenant_id), "other": str(other_id)},
    )
    await db.execute(
        text("UPDATE investigations SET status = 'closed', closed_at = now(), "
             "close_reason = COALESCE(close_reason, 'merged into ' || :keep), "
             "updated_at = now() WHERE id = :other AND tenant_id = :t"),
        {"keep": str(keep_id), "other": str(other_id), "t": str(tenant_id)},
    )
    # Cancel the merged-away investigation's live run so no worker claims it
    # (review finding #4) — the claim query also now guards on investigation
    # status, but terminate the run explicitly for a clean lifecycle.
    await db.execute(
        text("UPDATE investigation_runs SET status = 'failed', ended_at = now(), "
             "last_error = 'investigation merged' "
             "WHERE tenant_id = :t AND investigation_id = :other "
             "  AND status IN ('active','paused','waiting_on_gate','halted_budget')"),
        {"t": str(tenant_id), "other": str(other_id)},
    )
    await _record_label(
        db, tenant_id=tenant_id, label="merge",
        investigation_id=keep_id, other_investigation_id=other_id,
        reviewer=reviewer, note=note,
    )
    await log_audit(
        db, action="ir.correlation.merge", actor_principal="analyst",
        actor_id=reviewer or "analyst", tenant_id=tenant_id,
        resource_type="investigation", resource_id=str(keep_id),
        notes=f"merged {other_id} into {keep_id}",
    )
    return {"kept": str(keep_id), "merged": str(other_id)}


async def detach_alert(
    db: AsyncSession, *, tenant_id: UUID, alert_id: UUID,
    reviewer: str | None = None, note: str | None = None,
) -> dict[str, Any]:
    """Analyst detaches an alert from its investigation (false attach). The
    alert is moved to a fresh investigation; a detach label is recorded."""
    from soctalk.core.ir.triage import next_short_id

    new_inv = uuid4()
    short_id = await next_short_id(db, tenant_id)
    row = (await db.execute(
        text("SELECT severity, investigation_id FROM alerts "
             "WHERE id = :a AND tenant_id = :t"),
        {"a": str(alert_id), "t": str(tenant_id)},
    )).mappings().first()
    if row is None:
        raise ValueError("alert not found")
    old_inv = row["investigation_id"]

    await db.execute(
        text(
            "INSERT INTO investigations (id, tenant_id, short_id, title, status, "
            "severity, opened_at, visibility) "
            "VALUES (:id, :t, :sid, 'Detached alert', 'active', :sev, now(), 'mssp_only')"
        ),
        {"id": str(new_inv), "t": str(tenant_id), "sid": short_id,
         "sev": int(row["severity"] or 0)},
    )
    await db.execute(
        text("UPDATE alerts SET investigation_id = :new WHERE id = :a AND tenant_id = :t"),
        {"new": str(new_inv), "a": str(alert_id), "t": str(tenant_id)},
    )
    await db.execute(
        text("UPDATE alert_entity_keys SET investigation_id = :new "
             "WHERE tenant_id = :t AND alert_id = :a"),
        {"new": str(new_inv), "t": str(tenant_id), "a": str(alert_id)},
    )
    # Start a run so the detached alert actually gets triaged (review #4 —
    # a fresh investigation with no run would never be looked at).
    from soctalk.core.ir.runtime import start_run

    await start_run(db, tenant_id, new_inv)
    await _record_label(
        db, tenant_id=tenant_id, label="detach",
        investigation_id=old_inv, alert_id=alert_id,
        reviewer=reviewer, note=note,
    )
    await log_audit(
        db, action="ir.correlation.detach", actor_principal="analyst",
        actor_id=reviewer or "analyst", tenant_id=tenant_id,
        resource_type="alert", resource_id=str(alert_id),
        notes=f"detached from {old_inv} to {new_inv}",
    )
    return {"alert_id": str(alert_id), "new_investigation_id": str(new_inv)}


async def confirm_grouping(
    db: AsyncSession, *, tenant_id: UUID, investigation_id: UUID,
    reviewer: str | None = None, note: str | None = None,
) -> dict[str, Any]:
    """Analyst confirms an investigation's grouping is correct (positive label)."""
    await _record_label(
        db, tenant_id=tenant_id, label="confirm",
        investigation_id=investigation_id, reviewer=reviewer, note=note,
    )
    return {"investigation_id": str(investigation_id), "label": "confirm"}
