"""Proposed-action emitter + confirm dispatcher.

Two halves of the same flow:

* :func:`build_proposed_action` — called by the agent loop when the
  model emits a structured action proposal. Validates the payload,
  strips anything URL-shaped (defence in depth — the model is not
  trusted to point at endpoints), and persists as a ``role='action'``
  ``chat_messages`` row.
* :func:`dispatch_confirm` — called by the ``/messages/{msg_id}/confirm``
  endpoint when the analyst clicks Confirm. Loads the action row,
  reads the action verb + target from the *stored* row (NOT the
  client request body — the client never gets to influence which call
  fires), re-runs ownership checks, and routes to the existing
  review-action helpers.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any
from uuid import UUID

import structlog
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession


logger = structlog.get_logger()


# Action verbs the agent is allowed to propose. Each maps to an existing
# event-sourced helper in ``soctalk.core.ir.review_events``. Adding a
# new verb means adding a new (helper, target_kind) entry here AND
# teaching the model about it in the system prompt — both sides of
# the wire must agree.
ALLOWED_ACTIONS: frozenset[str] = frozenset(
    {"approve_review", "reject_review", "expire_review"}
)


def build_proposed_action(
    *,
    action: str,
    target_kind: str,
    target_id: str,
    target_title: str | None,
    reason: str,
    evidence: list[dict[str, Any]] | None,
    confidence: float | None,
    feedback: str | None = None,
) -> dict[str, Any]:
    """Validate + shape a ``proposed_action`` content payload.

    Raises ``ValueError`` if the action verb is unknown or the target
    UUID is malformed. The frontend never sees the raw model output;
    if the model emits garbage this layer drops it. The agent loop
    wraps this in a try/except and surfaces a friendly fallback rather
    than crashing the turn.

    Notable omission: there is no ``endpoint`` or ``body`` field — by
    design. The confirm endpoint derives the call from ``action`` +
    ``target.id`` server-side.
    """
    if action not in ALLOWED_ACTIONS:
        raise ValueError(f"unknown action: {action!r}")
    if target_kind not in {"pending_review", "investigation"}:
        raise ValueError(f"unknown target.kind: {target_kind!r}")
    try:
        UUID(target_id)
    except (TypeError, ValueError) as e:
        raise ValueError(f"target.id is not a UUID: {target_id!r}") from e

    confidence_clamped: float | None = None
    if confidence is not None:
        try:
            confidence_clamped = max(0.0, min(1.0, float(confidence)))
        except (TypeError, ValueError):
            confidence_clamped = None

    payload: dict[str, Any] = {
        "type": "proposed_action",
        "action": action,
        "target": {
            "kind": target_kind,
            "id": target_id,
            "title": target_title,
        },
        "reason": (reason or "").strip()[:512],
        "evidence": evidence or [],
        "confidence": confidence_clamped,
    }
    if feedback:
        payload["feedback"] = feedback[:256]
    return payload


# Maps (action, target.kind) → (helper_module_attr, decision_string).
# Kept here rather than scattered through the dispatcher so the
# allow-list is auditable in one place.
_ACTION_DISPATCH: dict[tuple[str, str], tuple[str, str]] = {
    ("approve_review", "pending_review"): ("record_human_decision_received", "approve"),
    ("reject_review", "pending_review"): ("record_human_decision_received", "reject"),
    ("expire_review", "pending_review"): ("record_human_review_expired", ""),
}


async def dispatch_confirm(
    db: AsyncSession,
    *,
    message_id: UUID,
    conversation_id: UUID,
    reviewer_user_id: UUID,
    reviewer_email: str | None,
) -> dict[str, Any]:
    """Execute the action stored on the given ``role='action'`` row.

    Returns a dict describing what happened (the analyst gets a small
    success toast and the conversation row's content is flipped to
    include the confirmation timestamp).

    Raises ``LookupError`` if the message doesn't exist, isn't an
    action, or doesn't belong to the conversation.
    Raises ``ValueError`` if the action's action+target_kind pair has
    no dispatcher entry (defence against the model emitting an
    obsolete or malformed verb after we tighten the allow-list).
    """
    from soctalk.core.ir import review_events

    row = (
        await db.execute(
            text(
                """
                SELECT id::text, conversation_id::text, tenant_id::text,
                       role, content
                FROM chat_messages
                WHERE id = :id
                """
            ),
            {"id": str(message_id)},
        )
    ).mappings().first()
    if row is None:
        raise LookupError("message not found")
    if row["role"] != "action":
        raise LookupError("message is not an action")
    if row["conversation_id"] != str(conversation_id):
        raise LookupError("message does not belong to conversation")

    content = dict(row["content"] or {})
    if content.get("confirmed_at"):
        # Idempotency — already confirmed; return what's stored.
        return {
            "already_confirmed": True,
            "confirmed_at": content["confirmed_at"],
        }

    action = content.get("action")
    target = content.get("target") or {}
    target_kind = target.get("kind")
    target_id_raw = target.get("id")
    if not action or not target_kind or not target_id_raw:
        raise ValueError("action message missing action/target")

    key = (action, target_kind)
    if key not in _ACTION_DISPATCH:
        raise ValueError(f"no dispatcher for {key!r}")
    helper_name, decision = _ACTION_DISPATCH[key]

    try:
        target_id = UUID(target_id_raw)
    except (TypeError, ValueError) as e:
        raise ValueError(f"target.id not a UUID: {target_id_raw!r}") from e

    # Re-verify ownership via the existing review-action path. We don't
    # bypass RLS here — even if the model emits a UUID the user isn't
    # supposed to see, the helper's UPDATE inside the user's session
    # scope will quietly match zero rows.
    feedback = content.get("feedback") or "AI-suggested; confirmed via chat"

    if helper_name == "record_human_decision_received":
        # Need the investigation_id + tenant_id to call the helper.
        pr = (
            await db.execute(
                text(
                    """
                    SELECT investigation_id::text, tenant_id::text
                    FROM pending_reviews WHERE id = :rid
                    """
                ),
                {"rid": str(target_id)},
            )
        ).mappings().first()
        if pr is None:
            raise LookupError("target pending_review not found")
        await review_events.record_human_decision_received(
            db,
            review_id=target_id,
            investigation_id=UUID(pr["investigation_id"]),
            tenant_id=UUID(pr["tenant_id"]),
            decision=decision,
            feedback=feedback,
            reviewer=reviewer_email,
        )
    elif helper_name == "record_human_review_expired":
        pr = (
            await db.execute(
                text(
                    """
                    SELECT investigation_id::text, tenant_id::text
                    FROM pending_reviews WHERE id = :rid
                    """
                ),
                {"rid": str(target_id)},
            )
        ).mappings().first()
        if pr is None:
            raise LookupError("target pending_review not found")
        await review_events.record_human_review_expired(
            db,
            review_id=target_id,
            investigation_id=UUID(pr["investigation_id"]),
            tenant_id=UUID(pr["tenant_id"]),
            reason=feedback,
            reviewer=reviewer_email,
        )

    # Flip the chat_messages row to record the confirmation. We update
    # in place so the conversation history shows the resolution in the
    # same message — analysts scrolling the chat see the green
    # "confirmed by you at HH:MM" badge inline.
    confirmed_at = datetime.utcnow().isoformat()
    content["confirmed_at"] = confirmed_at
    content["confirmed_by_user_id"] = str(reviewer_user_id)
    await db.execute(
        text(
            "UPDATE chat_messages SET content = CAST(:c AS jsonb) WHERE id = :id"
        ),
        {"c": json.dumps(content, default=str), "id": str(message_id)},
    )

    logger.info(
        "chat_action_confirmed",
        message_id=str(message_id),
        conversation_id=str(conversation_id),
        action=action,
        target_kind=target_kind,
        target_id=str(target_id),
        reviewer_user_id=str(reviewer_user_id),
    )

    return {
        "ok": True,
        "action": action,
        "target_id": str(target_id),
        "confirmed_at": confirmed_at,
    }
