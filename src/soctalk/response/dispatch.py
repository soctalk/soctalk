"""Response dispatch: match playbooks and enqueue actions at complete_run time.

Called from ``complete_run()`` INSIDE the transaction that computed the
effective disposition — the #49 invariant. Lease expiry, a 409 completion, or
a rolled-back close can therefore never leave orphaned response actions: the
enqueue commits or rolls back with the disposition itself. Idempotency key
``response:{run}:{playbook}@{version}:{index}`` makes a replayed completion a
no-op at the outbox.

The floor gates dispatch: the ``SOCTALK_RESPONSE_DISPATCH_KILL`` env (install-
wide) or the ``response_dispatch_kill`` tenant policy (runtime flip, no
rollout) stops every enqueue. Shadow playbooks are audited, never enqueued.
"""

from __future__ import annotations

import os
from typing import Any
from uuid import UUID, uuid4

import structlog
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from soctalk.core.ir.events import canonical_json
from soctalk.core.observability.audit import log_audit
from soctalk.response.envelope import build_envelope, condition_context
from soctalk.response.models import ResponsePlaybook
from soctalk.response.registry import match_response_playbooks, playbook_matches
from soctalk.triage_policy.conditions import evaluate_condition

logger = structlog.get_logger()

RESPONSE_OUTBOX_KIND = "response_action"


async def _matched(
    db: AsyncSession,
    tenant_id: UUID,
    *,
    rule_groups: set[str],
    rule_ids: set[str],
    identifiers: frozenset[str],
    status: str,
) -> list[ResponsePlaybook]:
    """Matching playbooks of a governing status — file registry PLUS DB-authored
    rows (#49 phase 2), deduped by id (an authored row overrides a file row of the
    same id) and priority-sorted. DB-authored playbooks let a tenant activate a
    response playbook live, since the dispatcher runs on L1 with DB access."""
    from soctalk.response.authoring import load_dispatchable

    by_id: dict[str, ResponsePlaybook] = {
        pb.id: pb
        for pb in match_response_playbooks(
            rule_groups=rule_groups, rule_ids=rule_ids,
            tenant_identifiers=identifiers, status=status,
        )
    }
    for pb in await load_dispatchable(db, tenant_id=tenant_id, status=status):
        if playbook_matches(
            pb, rule_groups=rule_groups, rule_ids=rule_ids,
            tenant_identifiers=identifiers,
        ):
            by_id[pb.id] = pb
    return sorted(by_id.values(), key=lambda p: p.priority)

SHADOW_AUDIT_ACTION = "ir.response_playbook.shadow"
DISPATCH_AUDIT_ACTION = "ir.response_playbook.dispatched"
KILLED_AUDIT_ACTION = "ir.response_playbook.dispatch_killed"


def response_dispatch_killed(policy: dict[str, Any] | None = None) -> bool:
    """Install-wide env or per-tenant policy kill switch — same discipline as
    the auto-close kill (#46). The policy flag must be a real boolean True."""
    if os.getenv("SOCTALK_RESPONSE_DISPATCH_KILL", "").lower() in ("1", "true", "yes"):
        return True
    return bool(policy) and policy.get("response_dispatch_kill") is True


def _idempotency_key(run_id: UUID, pb: ResponsePlaybook, index: int) -> str:
    return f"response:{run_id}:{pb.id}@{pb.version}:{index}"


def _selected_actions(
    pb: ResponsePlaybook, disposition: str, ctx: dict[str, Any]
) -> list[tuple[int, Any]]:
    """(index, action) pairs whose ``when`` holds. The index is positional in
    the playbook's phase list so the idempotency key is stable across loads."""
    return [
        (i, action)
        for i, action in enumerate(pb.actions_for(disposition))
        if action.when is None or evaluate_condition(action.when, ctx)
    ]


async def _tenant_identifiers(db: AsyncSession, tenant_id: UUID) -> frozenset[str]:
    slug = (
        await db.execute(
            text("SELECT slug FROM tenants WHERE id = :t"), {"t": str(tenant_id)}
        )
    ).scalar_one_or_none()
    ids = {str(tenant_id)}
    if slug:
        ids.add(str(slug))
    return frozenset(ids)


async def dispatch_for_completed_run(
    db: AsyncSession,
    *,
    tenant_id: UUID,
    investigation_id: UUID,
    run_id: UUID,
    worker_disposition: str | None,
    effective_disposition: str,
    server_floor_veto: str | None,
    verdict_summary: str | None,
    verdict_confidence: float | None,
    enrichments: dict[str, Any] | None,
) -> int:
    """Match + enqueue response actions for one completed run. Returns the
    number of outbox rows enqueued. Runs inside complete_run's transaction —
    the caller wraps it in a SAVEPOINT so a dispatch failure can never poison
    the completion itself."""

    envelope = await build_envelope(
        db,
        tenant_id=tenant_id,
        investigation_id=investigation_id,
        run_id=run_id,
        worker_disposition=worker_disposition,
        effective_disposition=effective_disposition,
        server_floor_veto=server_floor_veto,
        verdict_summary=verdict_summary,
        verdict_confidence=verdict_confidence,
        enrichments=enrichments,
    )
    ctx = condition_context(envelope)
    rule_groups = set((envelope.get("rule") or {}).get("groups") or [])
    rule_ids = set((envelope.get("rule") or {}).get("ids") or [])
    identifiers = await _tenant_identifiers(db, tenant_id)

    # Shadow first, and regardless of the kill switch: the audit trail of what
    # WOULD have fired is exactly what an operator reads before activating.
    for pb in await _matched(
        db, tenant_id, rule_groups=rule_groups, rule_ids=rule_ids,
        identifiers=identifiers, status="shadow",
    ):
        selected = _selected_actions(pb, effective_disposition, ctx)
        if not selected:
            continue
        await log_audit(
            db,
            action=SHADOW_AUDIT_ACTION,
            actor_principal="system",
            actor_id="response_dispatch",
            tenant_id=tenant_id,
            resource_type="investigation",
            resource_id=str(investigation_id),
            notes=canonical_json(
                {
                    "playbook": f"{pb.id}@{pb.version}",
                    "run_id": str(run_id),
                    "disposition": effective_disposition,
                    "actions": [a.capability for _, a in selected],
                }
            )[:4096],
        )

    active = await _matched(
        db, tenant_id, rule_groups=rule_groups, rule_ids=rule_ids,
        identifiers=identifiers, status="active",
    )
    if not active:
        return 0

    from soctalk.core.ir.policies import effective_policy

    if response_dispatch_killed(await effective_policy(db, tenant_id)):
        await log_audit(
            db,
            action=KILLED_AUDIT_ACTION,
            actor_principal="system",
            actor_id="response_dispatch",
            tenant_id=tenant_id,
            resource_type="investigation",
            resource_id=str(investigation_id),
            notes=canonical_json(
                {"run_id": str(run_id), "playbooks": [pb.id for pb in active]}
            )[:4096],
        )
        return 0

    enqueued = 0
    for pb in active:
        selected = _selected_actions(pb, effective_disposition, ctx)
        inserted_for_pb = 0
        for index, action in selected:
            delivery = _idempotency_key(run_id, pb, index)
            result = await db.execute(
                text(
                    """
                    INSERT INTO investigation_outbox
                      (id, tenant_id, investigation_id, kind, idempotency_key,
                       payload, external_system, status)
                    VALUES
                      (:id, :t, :c, :k, :ik, CAST(:p AS JSONB), :xs, 'pending')
                    ON CONFLICT (idempotency_key) DO NOTHING
                    """
                ),
                {
                    "id": str(uuid4()),
                    "t": str(tenant_id),
                    "c": str(investigation_id),
                    "k": RESPONSE_OUTBOX_KIND,
                    "ik": delivery,
                    "p": canonical_json(
                        {
                            "envelope": envelope,
                            "playbook": {"id": pb.id, "version": pb.version},
                            "capability": action.capability,
                            "params": action.params,
                            "delivery": delivery,
                        }
                    ),
                    "xs": "webhook" if action.capability == "notify_webhook" else None,
                },
            )
            # ON CONFLICT DO NOTHING: a replayed completion inserts nothing
            # and must not report/audit an enqueue that didn't happen.
            inserted_for_pb += result.rowcount or 0
        enqueued += inserted_for_pb
        if inserted_for_pb:
            await log_audit(
                db,
                action=DISPATCH_AUDIT_ACTION,
                actor_principal="system",
                actor_id="response_dispatch",
                tenant_id=tenant_id,
                resource_type="investigation",
                resource_id=str(investigation_id),
                notes=canonical_json(
                    {
                        "playbook": f"{pb.id}@{pb.version}",
                        "run_id": str(run_id),
                        "disposition": effective_disposition,
                        "actions": [a.capability for _, a in selected],
                    }
                )[:4096],
            )
    if enqueued:
        logger.info(
            "response_actions_enqueued",
            run_id=str(run_id),
            investigation_id=str(investigation_id),
            tenant_id=str(tenant_id),
            disposition=effective_disposition,
            count=enqueued,
        )
    return enqueued
