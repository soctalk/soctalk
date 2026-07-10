"""Verdict memoization (issue #29).

Keys a verdict cache on a STABLE alert shape so a recurring benign pattern
gets its prior high-confidence-FP verdict applied without an LLM run. The
key is (source, decoder, template_hash, template_version) — deliberately
NOT alert_signature, which carries a 5-minute bucket.

Guardrails:
- Only high-confidence close (FP) verdicts are reused; escalate/needs-info
  never memoize (we never auto-suppress something that once escalated).
- A confidence floor gates reuse.
- Memoized closes still audit + stay reopenable (#15) — not silent drops.
- Tenant-scoped by construction (verdict_cache PK includes tenant_id).
"""

from __future__ import annotations

import os
from typing import Any
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession


def shape_key(
    *,
    source: str | None,
    decoder: str | None,
    template_hash: str | None,
    template_version: str | None,
) -> str | None:
    """Stable memoization key, or None if there's no template to key on."""
    if not template_hash:
        return None
    return "|".join(
        [
            (source or "").lower(),
            (decoder or "").lower(),
            template_hash,
            template_version or "",
        ]
    )


def _reuse_confidence_floor() -> float:
    try:
        return float(os.getenv("SOCTALK_MEMOIZE_CONFIDENCE_FLOOR", "0.9"))
    except ValueError:
        return 0.9


async def lookup_memoized_close(
    db: AsyncSession, *, tenant_id: UUID, key: str
) -> dict[str, Any] | None:
    """Return a reusable FP-close verdict for this shape, or None.

    Only returns a row whose cached decision is a high-confidence close.
    """
    row = (
        await db.execute(
            text(
                "SELECT decision, confidence FROM verdict_cache "
                "WHERE tenant_id = :t AND shape_key = :k"
            ),
            {"t": str(tenant_id), "k": key},
        )
    ).mappings().first()
    if row is None:
        return None
    if row["decision"] != "close":
        return None
    if float(row["confidence"]) < _reuse_confidence_floor():
        return None
    return {"decision": row["decision"], "confidence": float(row["confidence"])}


async def record_verdict(
    db: AsyncSession,
    *,
    tenant_id: UUID,
    key: str,
    decision: str,
    confidence: float,
    template_hash: str | None,
) -> None:
    """Upsert the cache with the latest verdict for this shape. Called when
    a run completes with a structured verdict."""
    await db.execute(
        text(
            """
            INSERT INTO verdict_cache
              (tenant_id, shape_key, decision, confidence, template_hash,
               hit_count, last_verdict_at)
            VALUES (:t, :k, :d, :c, :th, 0, now())
            ON CONFLICT (tenant_id, shape_key) DO UPDATE SET
                decision = EXCLUDED.decision,
                confidence = EXCLUDED.confidence,
                template_hash = EXCLUDED.template_hash,
                last_verdict_at = now()
            """
        ),
        {"t": str(tenant_id), "k": key, "d": decision,
         "c": float(confidence), "th": template_hash},
    )


async def bump_hit(db: AsyncSession, *, tenant_id: UUID, key: str) -> None:
    await db.execute(
        text(
            "UPDATE verdict_cache SET hit_count = hit_count + 1 "
            "WHERE tenant_id = :t AND shape_key = :k"
        ),
        {"t": str(tenant_id), "k": key},
    )
