"""Provisioning worker.

Claims rows from ``provisioning_jobs``, instantiates :class:`TenantController`,
and drives ``provision`` or ``decommission`` to completion. One worker per
replica; rows are claim-locked via ``SELECT ... FOR UPDATE SKIP LOCKED`` so
multiple replicas can run safely in parallel.

Not an investigation-domain outbox. Kept in the provisioning package because the
only thing it knows how to drive is ``TenantController``.
"""

from __future__ import annotations

import asyncio
import os
import socket
from datetime import datetime, timedelta
from typing import TYPE_CHECKING

import structlog
from sqlalchemy import select, update

from soctalk.core.provisioning.controller import (
    ProvisionError,
    TenantController,
    TenantLifecycleError,
)
from soctalk.core.tenancy.models import ProvisioningJob

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

logger = structlog.get_logger()


DEFAULT_POLL_INTERVAL_SECONDS = 2.0
DEFAULT_BACKOFF_BASE_SECONDS = 30.0
DEFAULT_STALE_CLAIM_SECONDS = 900.0  # 15 min — longer than wazuh readiness
DEFAULT_RECLAIM_INTERVAL_SECONDS = 60.0


class ProvisioningWorker:
    """Drives the provisioning job queue end-to-end.

    Caller owns the ``async_sessionmaker``; the worker opens one session
    per claim so transactions stay short.
    """

    def __init__(
        self,
        session_factory: "async_sessionmaker[AsyncSession]",
        *,
        worker_id: str | None = None,
        poll_interval: float = DEFAULT_POLL_INTERVAL_SECONDS,
        backoff_base: float = DEFAULT_BACKOFF_BASE_SECONDS,
        stale_claim_seconds: float = DEFAULT_STALE_CLAIM_SECONDS,
        reclaim_interval_seconds: float = DEFAULT_RECLAIM_INTERVAL_SECONDS,
    ) -> None:
        self._sf = session_factory
        self._worker_id = worker_id or f"{socket.gethostname()}:{os.getpid()}"
        self._poll_interval = poll_interval
        self._backoff_base = backoff_base
        self._stale_claim_seconds = stale_claim_seconds
        self._reclaim_interval_seconds = reclaim_interval_seconds
        self._stop_event = asyncio.Event()
        self._last_reclaim_at = 0.0

    async def run_forever(self) -> None:
        logger.info("provisioning_worker_start", worker_id=self._worker_id)
        while not self._stop_event.is_set():
            # Reclaim before claiming: a crashed worker's in_flight row
            # may be blocking a replacement (partial unique index on the
            # active status set). Cheap — bounded by how many rows went
            # stale since last pass.
            await self._maybe_reclaim_stale()
            claimed = await self._claim_and_run_one()
            if not claimed:
                try:
                    await asyncio.wait_for(
                        self._stop_event.wait(), timeout=self._poll_interval
                    )
                except asyncio.TimeoutError:
                    pass

    async def stop(self) -> None:
        self._stop_event.set()

    async def _maybe_reclaim_stale(self) -> None:
        """Flip ``in_flight`` rows whose claim has gone stale back to
        ``pending`` so a crashed worker doesn't strand a tenant.

        Runs at most every ``reclaim_interval_seconds`` to keep the hot
        path cheap. Does *not* reset ``attempts`` — a stale-reclaim
        counts toward the retry budget, same as any other failure.
        """
        now_monotonic = asyncio.get_event_loop().time()
        if (now_monotonic - self._last_reclaim_at) < self._reclaim_interval_seconds:
            return
        self._last_reclaim_at = now_monotonic

        cutoff = datetime.utcnow() - timedelta(seconds=self._stale_claim_seconds)
        async with self._sf() as session:
            result = await session.execute(
                update(ProvisioningJob)
                .where(ProvisioningJob.status == "in_flight")
                .where(ProvisioningJob.claimed_at < cutoff)
                .values(
                    status="pending",
                    claimed_at=None,
                    claimed_by=None,
                    last_error="reclaimed after stale claim",
                    next_attempt_at=datetime.utcnow(),
                    updated_at=datetime.utcnow(),
                )
                .returning(ProvisioningJob.id)
            )
            reclaimed = result.scalars().all()
            await session.commit()

        if reclaimed:
            logger.warning(
                "provisioning_jobs_reclaimed",
                count=len(reclaimed),
                stale_after_seconds=self._stale_claim_seconds,
            )

    async def _claim_and_run_one(self) -> bool:
        """Try to claim a single due job; run it to completion.

        Returns True if a job was processed (success or failure), False if
        the queue was empty.
        """
        async with self._sf() as session:
            job = await self._claim(session)
            if job is None:
                return False

        # Run outside the claim transaction: the controller manages its
        # own txn boundaries.
        await self._run_job(job)
        return True

    async def _claim(self, session: "AsyncSession") -> ProvisioningJob | None:
        """Atomically claim one due job. Returns None if nothing is due."""
        now = datetime.utcnow()
        # SKIP LOCKED lets multiple workers compete without blocking.
        result = await session.execute(
            select(ProvisioningJob)
            .where(ProvisioningJob.status == "pending")
            .where(ProvisioningJob.next_attempt_at <= now)
            .order_by(ProvisioningJob.next_attempt_at)
            .limit(1)
            .with_for_update(skip_locked=True)
        )
        job = result.scalar_one_or_none()
        if job is None:
            return None

        job.status = "in_flight"
        job.claimed_at = now
        job.claimed_by = self._worker_id
        job.attempts += 1
        job.updated_at = now
        await session.commit()
        logger.info(
            "provisioning_job_claimed",
            job_id=str(job.id),
            tenant_id=str(job.tenant_id),
            kind=job.kind,
            attempt=job.attempts,
        )
        return job

    async def _run_job(self, job: ProvisioningJob) -> None:
        """Execute a claimed job; record outcome in a fresh session."""
        try:
            async with self._sf() as session:
                controller = TenantController(session)
                if job.kind == "tenant.provision":
                    await controller.provision(
                        job.tenant_id,
                        actor_id=f"worker:{self._worker_id}",
                    )
                elif job.kind == "tenant.decommission":
                    await controller.decommission(
                        job.tenant_id,
                        actor_id=f"worker:{self._worker_id}",
                        force=False,
                    )
                else:
                    raise ProvisionError(
                        f"unknown job kind: {job.kind}",
                        step="dispatch",
                    )
        except (ProvisionError, TenantLifecycleError) as e:
            await self._record_failure(job.id, str(e))
            logger.warning(
                "provisioning_job_failed",
                job_id=str(job.id),
                tenant_id=str(job.tenant_id),
                error=str(e),
                step=getattr(e, "step", None),
            )
            return
        except Exception as e:  # noqa: BLE001
            await self._record_failure(job.id, f"unexpected: {e}")
            logger.exception(
                "provisioning_job_unexpected_error",
                job_id=str(job.id),
                tenant_id=str(job.tenant_id),
            )
            return

        await self._record_success(job.id)
        logger.info(
            "provisioning_job_succeeded",
            job_id=str(job.id),
            tenant_id=str(job.tenant_id),
        )

    async def _record_success(self, job_id) -> None:
        async with self._sf() as session:
            await session.execute(
                update(ProvisioningJob)
                .where(ProvisioningJob.id == job_id)
                .values(
                    status="succeeded",
                    last_error=None,
                    updated_at=datetime.utcnow(),
                )
            )
            await session.commit()

    async def _record_failure(self, job_id, error_msg: str) -> None:
        async with self._sf() as session:
            # Fetch to decide terminal vs retriable.
            row = (
                await session.execute(
                    select(ProvisioningJob).where(ProvisioningJob.id == job_id)
                )
            ).scalar_one()

            if row.attempts >= row.max_attempts:
                final_status = "failed"
                next_attempt = row.next_attempt_at
            else:
                final_status = "pending"
                # Capped exponential backoff.
                backoff = self._backoff_base * (2 ** (row.attempts - 1))
                next_attempt = datetime.utcnow() + timedelta(
                    seconds=min(backoff, 1800)
                )

            await session.execute(
                update(ProvisioningJob)
                .where(ProvisioningJob.id == job_id)
                .values(
                    status=final_status,
                    last_error=error_msg[:2000],
                    next_attempt_at=next_attempt,
                    claimed_at=None,
                    claimed_by=None,
                    updated_at=datetime.utcnow(),
                )
            )
            await session.commit()


__all__ = ["ProvisioningWorker"]
