"""Integration test for the durable adapter checkpoint store (#17 T5).

Exercises the same SQL the GET/PUT /api/internal/adapter/checkpoint
handlers run (ON CONFLICT upsert with GREATEST monotonicity), proving
restart-safe cursor persistence without booting the full ASGI app.
"""

from __future__ import annotations

import os

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

SKIP_INTEGRATION = os.getenv("SKIP_INTEGRATION", "0") == "1"

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(SKIP_INTEGRATION, reason="needs Postgres"),
]

_UPSERT = text(
    """
    INSERT INTO adapter_checkpoints
      (tenant_id, source, cursor_ts, cursor_event_id, batch_seq, dropped_total, updated_at)
    VALUES (:t, :s, :cts, :ceid, COALESCE(:bseq, 0), COALESCE(:dropped, 0), now())
    ON CONFLICT (tenant_id, source) DO UPDATE SET
        cursor_ts = EXCLUDED.cursor_ts,
        cursor_event_id = EXCLUDED.cursor_event_id,
        batch_seq = GREATEST(adapter_checkpoints.batch_seq, EXCLUDED.batch_seq),
        dropped_total = GREATEST(adapter_checkpoints.dropped_total, EXCLUDED.dropped_total),
        updated_at = now()
    """
)


async def _put(s: AsyncSession, tid, **kw):
    await s.execute(_UPSERT, {"t": str(tid), "s": "wazuh", **kw})
    await s.commit()


async def _get(s: AsyncSession, tid) -> dict:
    return dict((await s.execute(
        text("SELECT cursor_ts, batch_seq, dropped_total FROM adapter_checkpoints "
             "WHERE tenant_id = :t AND source = 'wazuh'"),
        {"t": str(tid)},
    )).mappings().one())


async def test_checkpoint_persists_and_is_monotonic(
    mssp_session: AsyncSession, seed_two_tenants
):
    tenant_a, _ = seed_two_tenants

    await _put(mssp_session, tenant_a.tenant_id,
               cts="2026-07-09T10:00:00.000Z", ceid=None, bseq=5, dropped=3)
    row = await _get(mssp_session, tenant_a.tenant_id)
    assert row["cursor_ts"] == "2026-07-09T10:00:00.000Z"
    assert row["batch_seq"] == 5
    assert row["dropped_total"] == 3

    # A later cursor with LOWER seq/drops: cursor advances, counters hold.
    await _put(mssp_session, tenant_a.tenant_id,
               cts="2026-07-09T11:00:00.000Z", ceid=None, bseq=2, dropped=1)
    row = await _get(mssp_session, tenant_a.tenant_id)
    assert row["cursor_ts"] == "2026-07-09T11:00:00.000Z"
    assert row["batch_seq"] == 5, "batch_seq must not regress"
    assert row["dropped_total"] == 3, "dropped_total must not regress"


async def test_checkpoint_tenant_isolated(
    mssp_session: AsyncSession, seed_two_tenants
):
    tenant_a, tenant_b = seed_two_tenants
    await _put(mssp_session, tenant_a.tenant_id, cts="A", ceid=None, bseq=1, dropped=0)
    await _put(mssp_session, tenant_b.tenant_id, cts="B", ceid=None, bseq=1, dropped=0)
    assert (await _get(mssp_session, tenant_a.tenant_id))["cursor_ts"] == "A"
    assert (await _get(mssp_session, tenant_b.tenant_id))["cursor_ts"] == "B"
