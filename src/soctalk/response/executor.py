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

from soctalk.core.ir.runtime import default_handlers, execute_one
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
    await db.execute(
        text(
            """
            INSERT INTO execution_log
              (log_id, tenant_id, investigation_id, run_id, actor_kind, actor_id,
               kind, subject_type, subject_id, after, versions)
            VALUES
              (:id, :t, :c, :r, 'executor', 'response_executor',
               :k, 'response_action', :sid, CAST(:after AS JSONB),
               CAST(:versions AS JSONB))
            """
        ),
        {
            "id": str(uuid4()),
            "t": str(tenant_id),
            "c": envelope.get("investigation_id"),
            "r": envelope.get("run_id"),
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


async def handle_response_action(
    db: AsyncSession, outbox_row: dict[str, Any]
) -> str | None:
    """Outbox handler for ``kind='response_action'``.

    Fail closed on an unknown capability; enforce the approval gate (phase 1
    registers AUTONOMOUS tier-0 only — anything else must not execute here
    until the proposal-approval plane is wired to this path). Raise to let the
    outbox retry per its budget; the execution_log row records both outcomes.
    """
    payload = dict(outbox_row.get("payload") or {})
    tenant_id = UUID(str(outbox_row["tenant_id"]))
    name = str(payload.get("capability") or "")
    spec = RESPONSE_CAPABILITIES.get(name)

    async with tenant_context(db, tenant_id):
        if spec is None:
            await _write_execution_log(
                db, tenant_id=tenant_id, payload=payload,
                status="rejected", external_ref=None,
                error=f"unknown capability {name!r}",
            )
            raise ValueError(f"capability {name!r} is not in the vetted allowlist")
        if spec.approval is not ApprovalPolicy.AUTONOMOUS:
            await _write_execution_log(
                db, tenant_id=tenant_id, payload=payload,
                status="rejected", external_ref=None,
                error=f"capability {name!r} requires approval ({spec.approval.value})",
            )
            raise ValueError(
                f"capability {name!r} is not autonomous — approval plane not wired"
            )
        try:
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


def response_handlers() -> dict[str, Any]:
    """The executor's kind → handler map: everything the generic outbox knows
    plus this layer's kind."""
    return {**default_handlers(), RESPONSE_OUTBOX_KIND: handle_response_action}


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
                    did_work = await execute_one(db, self._worker_id, handlers)
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
