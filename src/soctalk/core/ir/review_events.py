"""Event-sourced HIL review writes against the V1 multi-tenant schema.

Background
----------
The legacy projector in ``soctalk.persistence.projector`` is coupled to
``InvestigationReadModel`` (SQLModel) which declares columns the V1
``investigations`` table does not have (``phase``, ``max_severity``,
``alert_count``, ``malicious_count``, ``verdict_decision``, ...). The
two share the table name but diverged in shape. Running the legacy
projector against the V1 DB would issue ``UPDATE investigations SET
phase = ...`` and error with "column does not exist".

This module is the V1-equivalent of the legacy projector for the two
HIL events:

* ``HUMAN_REVIEW_REQUESTED`` — emitted when an investigation needs an
  analyst gate. Appended to ``events`` (audit trail), the pending
  review row is created in ``pending_reviews`` and the source case is
  bumped to critical severity.
* ``HUMAN_DECISION_RECEIVED`` — emitted when the analyst acts. Updates
  the pending review status and, for reject, closes the case as
  ``auto_closed_fp``.

Audit trail invariant: the events table is the single source of truth.
The side-effect writes here are an alternate projection targeting V1
shape — equivalent to running a second projector subscribed to the
same event stream.
"""

from __future__ import annotations

import json
from typing import Any
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from soctalk.persistence.events import EventType


async def _append_event_v1(
    session: AsyncSession,
    *,
    aggregate_id: UUID,
    tenant_id: UUID,
    event_type: EventType,
    data: dict[str, Any],
) -> None:
    """V1-shape append: includes tenant_id (legacy ORM model omits it).

    The legacy ``EventStore.append()`` uses SQLModel that doesn't declare
    ``tenant_id`` — the column was added in a V1 migration but the model
    wasn't updated. RLS then rejects the insert because the new row's
    ``tenant_id`` is NULL while the session's ``app.current_tenant_id``
    is set. Raw INSERT lets us pass tenant_id without touching the
    shared model and breaking other call sites.
    """
    row = (
        await session.execute(
            text(
                "SELECT COALESCE(MAX(version), 0) AS v "
                "FROM events WHERE aggregate_id = :a"
            ),
            {"a": str(aggregate_id)},
        )
    ).mappings().first()
    next_version = int(row["v"]) + 1
    await session.execute(
        text(
            """
            INSERT INTO events (
                id, aggregate_id, aggregate_type, event_type, version,
                timestamp, data, event_metadata, tenant_id
            ) VALUES (
                gen_random_uuid(), :a, 'Investigation', :et, :v,
                now(), CAST(:d AS jsonb), '{}'::jsonb, :t
            )
            """
        ),
        {
            "a": str(aggregate_id),
            "et": event_type.value,
            "v": next_version,
            "d": json.dumps(data),
            "t": str(tenant_id),
        },
    )


_DECISION_TO_REVIEW_STATUS = {
    "approve": "approved",
    "reject": "rejected",
    "more_info": "info_requested",
}


async def record_human_review_requested(
    session: AsyncSession,
    *,
    investigation_id: UUID,
    tenant_id: UUID,
    reason: str | None,
    verdict_decision: str,
    verdict_confidence: float | None,
    findings: list[str] | None = None,
    enrichments: dict[str, Any] | None = None,
) -> None:
    """Persist a HIL review request: append the event + create the queue row.

    Idempotent on (investigation_id, status='pending') — re-invoking
    with an existing pending row is a no-op for the queue write but
    still appends the event (history is the truth).
    """
    findings_list = list(findings or [])
    enrichments_dict = dict(enrichments or {})

    # 1. Audit trail. Single source of truth.
    await _append_event_v1(
        session,
        aggregate_id=investigation_id,
        tenant_id=tenant_id,
        event_type=EventType.HUMAN_REVIEW_REQUESTED,
        data={
            "reason": reason,
            "verdict_decision": verdict_decision,
            "verdict_confidence": verdict_confidence,
            "findings": findings_list,
            "enrichments": enrichments_dict,
        },
    )

    # 2. Side effect: bump severity for escalate verdicts so the case
    #    sorts to the top of the MSSP queue.
    if verdict_decision == "escalate":
        await session.execute(
            text(
                """
                UPDATE investigations
                   SET severity = GREATEST(severity, 12),
                       summary = COALESCE(:reason, summary),
                       updated_at = now()
                 WHERE id = :id AND tenant_id = :t AND status = 'active'
                """
            ),
            {
                "reason": reason,
                "id": str(investigation_id),
                "t": str(tenant_id),
            },
        )

    # 3. Side effect: create the review queue row.
    await session.execute(
        text(
            """
            INSERT INTO pending_reviews (
                id, investigation_id, status, title, description,
                max_severity, alert_count, malicious_count, suspicious_count,
                clean_count, findings, enrichments, ai_decision, ai_confidence,
                ai_assessment, ai_recommendation, timeout_seconds, created_at,
                tenant_id
            )
            SELECT
                gen_random_uuid(), i.id, 'pending', i.title,
                COALESCE(:reason, 'Routed to HIL — analyst review.'),
                CASE WHEN i.severity >= 12 THEN 'critical'
                     WHEN i.severity >= 10 THEN 'high'
                     WHEN i.severity >= 7  THEN 'medium'
                     ELSE 'low' END,
                1, 0, 0, 0,
                CAST(:findings AS text[]), CAST(:enrichments AS jsonb),
                :decision, :confidence, :reason, :reason,
                3600, now(), i.tenant_id
            FROM investigations i
            WHERE i.id = :id AND i.tenant_id = :t
              AND NOT EXISTS (
                  SELECT 1 FROM pending_reviews pr
                  WHERE pr.investigation_id = i.id
                    AND pr.status = 'pending'
              )
            """
        ),
        {
            "reason": reason,
            "decision": verdict_decision,
            "confidence": verdict_confidence,
            "findings": findings_list,
            "enrichments": json.dumps(enrichments_dict),
            "id": str(investigation_id),
            "t": str(tenant_id),
        },
    )


async def record_human_decision_received(
    session: AsyncSession,
    *,
    review_id: UUID,
    investigation_id: UUID,
    tenant_id: UUID | None,
    decision: str,
    feedback: str | None,
    reviewer: str | None,
) -> None:
    """Persist an analyst HIL action: append the event + update the queue row.

    ``decision`` is one of ``approve`` | ``reject`` | ``more_info``.
    Side effects:
      - pending_reviews.status flips to approved/rejected/info_requested
      - on reject: investigation closes as ``auto_closed_fp``
    """
    review_status = _DECISION_TO_REVIEW_STATUS.get(decision, decision)

    # 1. Audit trail. We require tenant_id for V1 RLS-safe insert; the
    #    caller resolves it from the analyst's identity.
    if tenant_id is None:
        raise ValueError("tenant_id required for HUMAN_DECISION_RECEIVED")
    await _append_event_v1(
        session,
        aggregate_id=investigation_id,
        tenant_id=tenant_id,
        event_type=EventType.HUMAN_DECISION_RECEIVED,
        data={
            "decision": decision,
            "feedback": feedback,
            "reviewer": reviewer,
        },
    )

    # 2. Update the queue row.
    await session.execute(
        text(
            """
            UPDATE pending_reviews
               SET status = :new_status,
                   feedback = :feedback,
                   reviewer = :reviewer,
                   responded_at = now()
             WHERE id = :rid
            """
        ),
        {
            "new_status": review_status,
            "feedback": feedback,
            "reviewer": reviewer,
            "rid": str(review_id),
        },
    )

    # 3. On reject, close the case as analyst-determined FP.
    if decision == "reject":
        params: dict[str, Any] = {
            "reason": feedback,
            "id": str(investigation_id),
        }
        sql = """
            UPDATE investigations
               SET status = 'auto_closed_fp',
                   closed_at = now(),
                   close_reason = COALESCE(:reason, close_reason),
                   updated_at = now()
             WHERE id = :id
        """
        if tenant_id is not None:
            sql += " AND tenant_id = :t"
            params["t"] = str(tenant_id)
        await session.execute(text(sql), params)
