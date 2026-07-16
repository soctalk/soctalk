"""Response executor: drains ``response_action`` rows from the outbox (issue #49).

Runs on the L1 plane as a lifespan background task (same precedent as the
provisioning worker) — NEVER in the runs-worker, which holds only a
tenant-bound completion token. Reuses the generic outbox machinery
(``core.ir.runtime``): leases, SKIP LOCKED claims, backoff retries, terminal
failure after ``max_attempts``. Multiple API replicas drain safely.

Every executed action writes an ``execution_log`` row carrying the playbook
id@version, the envelope version, the idempotency key, and the external
reference — the durable per-action ledger the #49 review demanded (NOT
``audit_log.notes``).
"""

from __future__ import annotations

import asyncio
import os
import socket
from typing import Any
from uuid import UUID, uuid4

import structlog
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from soctalk.core.ir.runtime import execute_one
from soctalk.core.ir.tools import ApprovalPolicy
from soctalk.core.tenancy.context import tenant_context
from soctalk.response.capabilities import RESPONSE_CAPABILITIES
from soctalk.response.dispatch import RESPONSE_OUTBOX_KIND
from soctalk.response.models import ENVELOPE_VERSION

logger = structlog.get_logger()

DEFAULT_POLL_INTERVAL_SECONDS = 2.0


async def _write_execution_log(
    db: AsyncSession,
    *,
    tenant_id: UUID,
    payload: dict[str, Any],
    status: str,
    external_ref: str | None,
    error: str | None,
) -> None:
    envelope = payload.get("envelope") or {}
    playbook = payload.get("playbook") or {}
    # investigation_id/run_id carry FKs; the ledger must stay writable for a
    # MALFORMED payload too (that is exactly when it matters most), so scrub
    # dangling references to NULL via subselects instead of aborting the
    # transaction on an FK violation.
    await db.execute(
        text(
            """
            INSERT INTO execution_log
              (log_id, tenant_id, investigation_id, run_id, actor_kind, actor_id,
               kind, subject_type, subject_id, after, versions)
            VALUES
              (:id, :t,
               (SELECT id FROM investigations
                 WHERE id = CAST(NULLIF(:c, '') AS UUID)),
               (SELECT id FROM investigation_runs
                 WHERE id = CAST(NULLIF(:r, '') AS UUID)),
               'executor', 'response_executor',
               :k, 'response_action', :sid, CAST(:after AS JSONB),
               CAST(:versions AS JSONB))
            """
        ),
        {
            "id": str(uuid4()),
            "t": str(tenant_id),
            "c": _uuid_or_empty(envelope.get("investigation_id")),
            "r": _uuid_or_empty(envelope.get("run_id")),
            "k": f"response_action.{status}",
            "sid": str(payload.get("delivery") or "")[:128],
            "after": _json(
                {
                    "capability": payload.get("capability"),
                    "external_ref": external_ref,
                    "error": (error or "")[:500] or None,
                }
            ),
            "versions": _json(
                {
                    "response_playbook": f"{playbook.get('id')}@{playbook.get('version')}",
                    "envelope": envelope.get("version", ENVELOPE_VERSION),
                }
            ),
        },
    )


def _json(obj: dict[str, Any]) -> str:
    from soctalk.core.ir.events import canonical_json

    return canonical_json(obj)


def _uuid_or_empty(value: Any) -> str:
    """A UUID string, or '' (→ SQL NULL via NULLIF) for anything else — the
    ledger insert must be total over hostile payload shapes."""
    try:
        return str(UUID(str(value)))
    except (ValueError, TypeError, AttributeError):
        return ""


async def handle_response_action(
    db: AsyncSession, outbox_row: dict[str, Any]
) -> str | None:
    """Outbox handler for ``kind='response_action'``.

    Fail closed on an unknown capability. An AUTONOMOUS (tier-0) capability
    executes here directly; a gated (non-autonomous) capability is ROUTED to
    the approval plane as a proposal (#49 phase 2) — routed, not refused, and
    the outbox row succeeds so the drain never retries into duplicate
    proposals. Raise only on genuine failure so the outbox retries per its
    budget; the execution_log row records every outcome (routed/executed/
    failed/rejected).
    """
    payload = dict(outbox_row.get("payload") or {})
    tenant_id = UUID(str(outbox_row["tenant_id"]))
    name = str(payload.get("capability") or "")
    spec = RESPONSE_CAPABILITIES.get(name)
    envelope = payload.get("envelope") or {}

    async with tenant_context(db, tenant_id):
        # This session may be BYPASSRLS: the payload's tenant/investigation
        # must agree with the outbox row AND the database before any side
        # effect (Codex #49 Medium-5) — a malformed row must not become a
        # cross-tenant write or hand tenant B's envelope to tenant A's hook.
        if str(envelope.get("tenant_id")) != str(tenant_id) or str(
            envelope.get("investigation_id")
        ) != str(outbox_row.get("investigation_id")):
            await _write_execution_log(
                db, tenant_id=tenant_id, payload=payload,
                status="rejected", external_ref=None,
                error="payload envelope does not match outbox row scope",
            )
            raise ValueError("response_action payload/row scope mismatch")
        owned = (
            await db.execute(
                text("SELECT 1 FROM investigations WHERE id = :c AND tenant_id = :t"),
                {"c": str(envelope.get("investigation_id")), "t": str(tenant_id)},
            )
        ).scalar_one_or_none()
        if owned is None:
            await _write_execution_log(
                db, tenant_id=tenant_id, payload=payload,
                status="rejected", external_ref=None,
                error="investigation not owned by row tenant",
            )
            raise ValueError("response_action investigation/tenant mismatch")
        if spec is None:
            await _write_execution_log(
                db, tenant_id=tenant_id, payload=payload,
                status="rejected", external_ref=None,
                error=f"unknown capability {name!r}",
            )
            raise ValueError(f"capability {name!r} is not in the vetted allowlist")
        if spec.approval is not ApprovalPolicy.AUTONOMOUS:
            # A gated capability is ROUTED to the approval plane, not executed
            # and not refused (#49 phase 2). We create a proposal a human must
            # approve; approval later enqueues the real execution. The routing
            # must SUCCEED at the outbox (return, never raise) — raising would
            # retry the drain and create a duplicate proposal each attempt.
            proposal_id = await _route_to_proposal(
                db, tenant_id=tenant_id, payload=payload, spec=spec
            )
            external_ref = f"proposal:{proposal_id}"
            await _write_execution_log(
                db, tenant_id=tenant_id, payload=payload,
                status="routed", external_ref=external_ref, error=None,
            )
            return external_ref
        try:
            # SAVEPOINT around the capability: a SQL error inside a handler
            # must roll back its partial writes WITHOUT aborting the outer
            # transaction — otherwise the failure ledger row and the outbox
            # retry bookkeeping (mark_outbox_failed) can never be written and
            # the row wedges in an abort-retry loop with attempts stuck at 0.
            async with db.begin_nested():
                external_ref = await spec.handler(db, tenant_id, payload)
        except Exception as exc:  # noqa: BLE001 — ledger both outcomes, then re-raise
            await _write_execution_log(
                db, tenant_id=tenant_id, payload=payload,
                status="failed", external_ref=None, error=str(exc),
            )
            raise
        await _write_execution_log(
            db, tenant_id=tenant_id, payload=payload,
            status="executed", external_ref=external_ref, error=None,
        )
        return external_ref


async def _route_to_proposal(
    db: AsyncSession,
    *,
    tenant_id: UUID,
    payload: dict[str, Any],
    spec: Any,
) -> UUID:
    """Create a human-approval proposal for a gated response action (#49 ph2).

    Reuses the core.ir proposal plane. Two invariants make this safe on a
    response-origin action:

    - ``run_id=None`` — the originating run is already TERMINAL (complete_run
      marked it before dispatch), so it must never be flipped to
      ``waiting_on_gate``. ``create_proposal`` only transitions when run_id is
      set.
    - the response ``delivery`` key rides in ``params`` — ``create_proposal``
      keys idempotency on (investigation_id, action_type, canonical(params)),
      so a re-drained outbox row resolves to the SAME proposal instead of
      spawning duplicates, and two distinct actions of the same capability do
      not collapse into one.

    ``action_type`` is the response capability name, which is self-identifying:
    the approved-proposal executor (#49 ph2 increment 2) routes it back to the
    response capability handler by looking it up in RESPONSE_CAPABILITIES rather
    than the core.ir tool registry.
    """
    from soctalk.core.ir.runtime import create_proposal

    envelope = payload.get("envelope") or {}
    playbook = payload.get("playbook") or {}
    return await create_proposal(
        db,
        tenant_id=tenant_id,
        investigation_id=UUID(str(envelope["investigation_id"])),
        run_id=None,
        action_type=str(payload.get("capability") or ""),
        params=payload,
        rationale=(
            f"response playbook {playbook.get('id')}@v{playbook.get('version')} "
            f"on {envelope.get('disposition')}"
        )[:512],
        capability_class=spec.capability_class.value,
    )


RESPONSE_KINDS: tuple[str, ...] = (RESPONSE_OUTBOX_KIND,)


def response_handlers() -> dict[str, Any]:
    """The executor's kind → handler map — response_action ONLY. Claims are
    scoped to RESPONSE_KINDS (Codex #49 High-2): this loop must never claim
    (and terminally fail) rows owned by other executors, present or future."""
    return {RESPONSE_OUTBOX_KIND: handle_response_action}


class ResponseExecutor:
    """Poll loop draining the outbox. Caller owns the sessionmaker; one
    session per claim so transactions stay short (provisioning-worker
    pattern)."""

    def __init__(
        self,
        session_factory: Any,
        *,
        worker_id: str | None = None,
        poll_interval: float = DEFAULT_POLL_INTERVAL_SECONDS,
    ) -> None:
        self._sf = session_factory
        self._worker_id = worker_id or f"response:{socket.gethostname()}:{os.getpid()}"
        self._poll_interval = poll_interval
        self._stop_event = asyncio.Event()

    def stop(self) -> None:
        self._stop_event.set()

    async def run_forever(self) -> None:
        logger.info("response_executor_started", worker_id=self._worker_id)
        handlers = response_handlers()
        while not self._stop_event.is_set():
            did_work = False
            try:
                async with self._sf() as db:
                    did_work = await execute_one(
                        db, self._worker_id, handlers, kinds=RESPONSE_KINDS
                    )
                    await db.commit()
            except Exception as exc:  # noqa: BLE001 — the loop must survive
                logger.warning("response_executor_loop_error", error=str(exc)[:300])
            if not did_work:
                try:
                    await asyncio.wait_for(
                        self._stop_event.wait(), timeout=self._poll_interval
                    )
                except TimeoutError:
                    pass
        logger.info("response_executor_stopped", worker_id=self._worker_id)
