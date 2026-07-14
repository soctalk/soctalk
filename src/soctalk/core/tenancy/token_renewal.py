"""Periodic renewal of tenant agent (adapter + runs-worker) internal tokens.

The adapter (7-day TTL) and runs-worker (30-day TTL) internal-API auth tokens
are HMAC tokens minted at provision time and stored as K8s Secrets in each
tenant namespace. Nothing re-minted them, so once the TTL elapsed a long-lived
tenant's adapter began 401'ing on ``/api/internal/adapter/events`` + heartbeat
and its runs-worker on ``/api/internal/worker/runs/claim`` — silently killing
ALL triage while the tenant still reported ACTIVE (the smoke only checks a
tenant reaches ACTIVE once, so CI never caught it). Observed on the demo:
triage dead ~6 weeks, last successful heartbeat 42 days after onboard.

This loop re-mints both tokens for every active tenant well within the TTL and
rewrites the Secrets in place. The runs-worker re-reads its token file on every
claim and the adapter re-reads on every heartbeat + ingest cycle, so the
renewed token is picked up within seconds with no pod restart.
"""
from __future__ import annotations

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from soctalk.core.tenancy.auth import mint_adapter_token, mint_worker_token
from soctalk.core.tenancy.models import Tenant, TenantState

logger = structlog.get_logger()


async def renew_agent_tokens(session: AsyncSession, k8s) -> int:
    """Re-mint + rewrite the adapter/worker token Secrets for active tenants.

    Returns the number of tenants renewed. Best-effort per tenant: a failure on
    one (e.g. its namespace was deleted between the query and the write, or the
    K8s API blipped) is logged and skipped so one bad tenant never stalls the
    renewal of the rest. Idempotent — ``put_secret`` is create-or-update, so a
    re-mint on every cycle simply rolls the token forward.
    """
    result = await session.execute(
        select(Tenant).where(Tenant.state == TenantState.ACTIVE.value)
    )
    tenants = list(result.scalars().all())
    renewed = 0
    for t in tenants:
        ns = f"tenant-{t.slug}"
        try:
            await k8s.put_secret(
                ns,
                "adapter-token",
                data={"token": mint_adapter_token(t.id)},
                labels={
                    "soctalk.io/secret-purpose": "adapter-token",
                    "managed-by": "soctalk",
                },
            )
            await k8s.put_secret(
                ns,
                "runs-worker-token",
                data={"token": mint_worker_token(t.id)},
                labels={
                    "soctalk.io/secret-purpose": "runs-worker-token",
                    "managed-by": "soctalk",
                },
            )
            renewed += 1
        except Exception as e:  # noqa: BLE001 — one tenant must not stall the rest
            logger.warning(
                "agent_token_renewal_failed",
                tenant=str(t.id),
                namespace=ns,
                error=str(e),
            )
    return renewed
