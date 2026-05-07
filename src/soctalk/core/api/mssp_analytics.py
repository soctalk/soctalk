"""MSSP fleet analytics endpoints.

Three trend-shaped widgets surfaced on the L1 ``/analytics`` page when
the operator is in cross-tenant MSSP scope. Distinct from the
fleet **dashboard** by **time horizon and decision type**: dashboard
answers "where do I look now?" (operational, queue-shaped), analytics
answers "is the practice improving, degrading, or drifting?"
(managerial, longitudinal, distribution-shaped).

  1. trends     — p95 TTV / p95 TTR / escalation rate / alert volume
                  over a rolling window. Bucket auto-scales: hourly
                  for ≤30d horizons, daily for >30d so the chart
                  doesn't degrade into hairline noise at 90d.
  2. ranking    — top worsening tenants for a given metric. Two
                  guard rails: (a) min-sample threshold per tenant
                  per period (e.g. ≥10 closed cases) so a single
                  outlier in a tiny tenant doesn't dominate the
                  list, and (b) "worsening" = absolute Δ in seconds,
                  not relative %, so 60s→90s p95 doesn't outrank
                  4h→6h.
  3. heatmap    — fleet activity (alerts | cases) by day-of-week ×
                  hour-of-day. Surfaces staffing patterns and the
                  "always-on Sunday spike" attention costs.

All three run in MSSP audience (``audience=mssp``, no
``app.current_tenant_id`` set) so the SELECTs span the fleet. Same
role-gating as the dashboard router: mssp_admin / analyst /
platform_admin.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from soctalk.core.tenancy.auth import current_identity
from soctalk.core.tenancy.decorators import require_role
from soctalk.core.tenancy.models import Role


router = APIRouter(
    prefix="/api/mssp/analytics",
    tags=["mssp-analytics"],
    dependencies=[Depends(require_role(Role.MSSP_ADMIN, Role.ANALYST, Role.PLATFORM_ADMIN))],
)


def _db(request: Request) -> AsyncSession:
    s = getattr(request.state, "db", None)
    if s is None:
        raise HTTPException(500, "db session not attached")
    return s


def _require_mssp_scope(request: Request) -> None:
    identity = current_identity(request)
    if identity is None:
        raise HTTPException(401, "authentication required")
    if identity.current_tenant is not None:
        raise HTTPException(
            409,
            "fleet analytics requires cross-tenant scope; clear the "
            "tenant pin first",
        )


def _bucket_for(days: int) -> str:
    """``hour`` ≤30d, ``day`` >30d. Hardcoded threshold matches the
    chart-density limit on the frontend (≤30d → hourly buckets cap at
    720 points; >30d uses daily so 90d caps at 90)."""
    return "hour" if days <= 30 else "day"


# ---------------------------------------------------------------------------
# 1. Trends
# ---------------------------------------------------------------------------


class TrendBucket(BaseModel):
    bucket: str  # ISO8601 — start of the hour or day window
    alert_count: int
    closed_count: int
    escalated_count: int
    p95_ttv_seconds: float | None
    p95_ttr_seconds: float | None


class TrendsResponse(BaseModel):
    days: int
    bucket_size: str  # "hour" | "day"
    buckets: list[TrendBucket]
    # Window-level aggregates so the headline KPI on the frontend
    # doesn't have to median-across-bucket-level p95s — that quirk
    # makes a 1-investigation bucket dominate. Computed across all closed
    # cases in the window, regardless of bucket fill.
    window_p95_ttv_seconds: float | None
    window_p95_ttr_seconds: float | None
    window_alert_total: int
    window_closed_total: int
    window_escalated_total: int


@router.get("/trends", response_model=TrendsResponse)
async def trends(
    request: Request, days: int = Query(7, ge=1, le=180)
) -> TrendsResponse:
    _require_mssp_scope(request)
    db = _db(request)
    bucket = _bucket_for(days)
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=days)

    # TTV = investigation.closed_at - investigation.opened_at over closed investigations.
    # TTR = investigation.opened_at - min(alert.first_event_at) over closed
    #       cases (i.e., how long from earliest signal to investigation birth).
    # Both percentile_cont aggregates run within the bucket window.
    # ``bucket`` is f-string-substituted because asyncpg sees the
    # bound parameter as ``unknown`` and date_trunc has multiple
    # overloads — Postgres can't resolve it. The value is controlled
    # by ``_bucket_for()`` which only returns 'hour' | 'day', so no
    # injection risk.
    rows = (
        await db.execute(
            text(
                f"""
                WITH alert_first AS (
                  SELECT investigation_id, min(first_event_at) AS first_event_at
                  FROM alerts
                  WHERE investigation_id IS NOT NULL
                  GROUP BY investigation_id
                ),
                buckets AS (
                  -- ``CAST(:start AS timestamptz)`` resolves
                  -- ``date_trunc(unknown,unknown)`` ambiguity. Can't
                  -- use ``::`` syntax — asyncpg parses it as a
                  -- parameter-name lead.
                  SELECT generate_series(
                    date_trunc('{bucket}', CAST(:start AS timestamptz)),
                    date_trunc('{bucket}', CAST(:end   AS timestamptz)),
                    interval '1 {bucket}'
                  ) AS ts
                ),
                alerts_b AS (
                  SELECT date_trunc('{bucket}', first_event_at) AS ts,
                         count(*)::int AS n
                  FROM alerts
                  WHERE first_event_at >= :start
                    AND first_event_at <  :end
                  GROUP BY 1
                ),
                closed_b AS (
                  SELECT date_trunc('{bucket}', c.closed_at) AS ts,
                         count(*)::int                                AS n,
                         count(*) FILTER (
                           WHERE c.status IN ('escalated', 'closed_tp')
                         )::int                                       AS escalated,
                         percentile_cont(0.95) WITHIN GROUP (
                           ORDER BY extract(epoch FROM (c.closed_at - c.opened_at))
                         )                                            AS p95_ttv,
                         percentile_cont(0.95) WITHIN GROUP (
                           ORDER BY extract(epoch FROM (c.opened_at - af.first_event_at))
                         ) FILTER (WHERE af.first_event_at IS NOT NULL) AS p95_ttr
                  FROM investigations c
                  LEFT JOIN alert_first af ON af.investigation_id = c.id
                  WHERE c.closed_at IS NOT NULL
                    AND c.closed_at >= c.opened_at -- guard clock skew
                    AND c.closed_at >= :start
                    AND c.closed_at <  :end
                  GROUP BY 1
                )
                SELECT b.ts::text AS bucket,
                       coalesce(a.n, 0)         AS alert_count,
                       coalesce(cl.n, 0)        AS closed_count,
                       coalesce(cl.escalated,0) AS escalated_count,
                       cl.p95_ttv               AS p95_ttv_seconds,
                       cl.p95_ttr               AS p95_ttr_seconds
                FROM buckets b
                LEFT JOIN alerts_b a  ON a.ts  = b.ts
                LEFT JOIN closed_b cl ON cl.ts = b.ts
                ORDER BY b.ts ASC
                """
            ),
            {"start": start, "end": end},
        )
    ).mappings().all()
    # Window-level aggregates. Single round-trip; same cases/alerts
    # base as the bucketed query above.
    win = (
        await db.execute(
            text(
                """
                WITH alert_first AS (
                  SELECT investigation_id, min(first_event_at) AS first_event_at
                  FROM alerts WHERE investigation_id IS NOT NULL GROUP BY investigation_id
                )
                SELECT
                  (SELECT count(*)::int FROM alerts
                     WHERE first_event_at >= :start AND first_event_at < :end)
                    AS alert_total,
                  count(*)::int AS closed_total,
                  count(*) FILTER (
                    WHERE c.status IN ('escalated', 'closed_tp')
                  )::int AS escalated_total,
                  percentile_cont(0.95) WITHIN GROUP (
                    ORDER BY extract(epoch FROM (c.closed_at - c.opened_at))
                  ) AS p95_ttv,
                  percentile_cont(0.95) WITHIN GROUP (
                    ORDER BY extract(epoch FROM (c.opened_at - af.first_event_at))
                  ) FILTER (WHERE af.first_event_at IS NOT NULL) AS p95_ttr
                FROM investigations c
                LEFT JOIN alert_first af ON af.investigation_id = c.id
                WHERE c.closed_at IS NOT NULL
                  AND c.closed_at >= c.opened_at -- skew guard, match bucketed query above
                  AND c.closed_at >= :start
                  AND c.closed_at <  :end
                """
            ),
            {"start": start, "end": end},
        )
    ).mappings().first()

    return TrendsResponse(
        days=days,
        bucket_size=bucket,
        buckets=[TrendBucket(**r) for r in rows],
        window_p95_ttv_seconds=(
            float(win["p95_ttv"]) if win and win["p95_ttv"] is not None else None
        ),
        window_p95_ttr_seconds=(
            float(win["p95_ttr"]) if win and win["p95_ttr"] is not None else None
        ),
        window_alert_total=int(win["alert_total"]) if win else 0,
        window_closed_total=int(win["closed_total"]) if win else 0,
        window_escalated_total=int(win["escalated_total"]) if win else 0,
    )


# ---------------------------------------------------------------------------
# 2. Comparative ranking
# ---------------------------------------------------------------------------


class RankingRow(BaseModel):
    tenant_id: str
    slug: str
    display_name: str
    current_p95_seconds: float
    previous_p95_seconds: float | None
    delta_seconds: float | None  # current - previous
    sample_current: int
    sample_previous: int


class RankingResponse(BaseModel):
    metric: str  # "ttv" | "ttr"
    days: int
    min_sample: int
    fleet_median_seconds: float | None
    rows: list[RankingRow]


@router.get("/ranking", response_model=RankingResponse)
async def ranking(
    request: Request,
    metric: str = Query("ttv", pattern="^(ttv|ttr)$"),
    days: int = Query(30, ge=1, le=180),
    min_sample: int = Query(10, ge=1, le=1000),
    limit: int = Query(20, ge=1, le=200),
) -> RankingResponse:
    _require_mssp_scope(request)
    db = _db(request)

    end = datetime.now(timezone.utc)
    start = end - timedelta(days=days)
    prev_end = start
    prev_start = start - timedelta(days=days)

    # The duration column we're percentile-aggregating differs by
    # metric; rest of the query is identical between current and
    # previous periods. Use a CTE per period.
    duration_sql = (
        "extract(epoch FROM (c.closed_at - c.opened_at))"
        if metric == "ttv"
        else "extract(epoch FROM (c.opened_at - af.first_event_at))"
    )
    join_sql = (
        ""
        if metric == "ttv"
        else (
            "LEFT JOIN ("
            "  SELECT investigation_id, min(first_event_at) AS first_event_at "
            "  FROM alerts WHERE investigation_id IS NOT NULL GROUP BY investigation_id"
            ") af ON af.investigation_id = c.id"
        )
    )
    where_metric = (
        ""
        if metric == "ttv"
        else "AND af.first_event_at IS NOT NULL"
    )

    rows = (
        await db.execute(
            text(
                f"""
                WITH cur AS (
                  SELECT c.tenant_id,
                         percentile_cont(0.95) WITHIN GROUP (
                           ORDER BY {duration_sql}
                         ) AS p95,
                         count(*)::int AS n
                  FROM investigations c
                  {join_sql}
                  WHERE c.closed_at IS NOT NULL
                    AND c.closed_at >= c.opened_at -- guard clock skew
                    AND c.closed_at >= :start
                    AND c.closed_at <  :end
                    {where_metric}
                  GROUP BY c.tenant_id
                ),
                prev AS (
                  SELECT c.tenant_id,
                         percentile_cont(0.95) WITHIN GROUP (
                           ORDER BY {duration_sql}
                         ) AS p95,
                         count(*)::int AS n
                  FROM investigations c
                  {join_sql}
                  WHERE c.closed_at IS NOT NULL
                    AND c.closed_at >= c.opened_at -- skew guard
                    AND c.closed_at >= :prev_start
                    AND c.closed_at <  :prev_end
                    {where_metric}
                  GROUP BY c.tenant_id
                )
                SELECT t.id::text AS tenant_id, t.slug, t.display_name,
                       cur.p95            AS current_p95_seconds,
                       prev.p95           AS previous_p95_seconds,
                       (cur.p95 - prev.p95) AS delta_seconds,
                       cur.n              AS sample_current,
                       coalesce(prev.n, 0) AS sample_previous
                FROM cur
                JOIN tenants t ON t.id = cur.tenant_id
                LEFT JOIN prev ON prev.tenant_id = cur.tenant_id
                WHERE cur.n >= :min_sample
                -- Two-tier sort: tenants with a real Δ (prev period
                -- has data) rank by Δ DESC. Tenants without prior
                -- data fall to the bottom and rank among themselves
                -- by current p95 — they're not "worsening" because
                -- there's nothing to compare to. Coalescing null
                -- prev to 0 (the prior implementation) faked the
                -- delta as the full current value and surfaced
                -- new-tenant noise above genuine drift.
                ORDER BY
                  CASE WHEN prev.p95 IS NULL THEN 1 ELSE 0 END,
                  CASE WHEN prev.p95 IS NULL THEN NULL
                       ELSE (cur.p95 - prev.p95) END DESC NULLS LAST,
                  cur.p95 DESC,
                  -- Stable order on ties (e.g., two tenants with the
                  -- same current p95 and no prior period) — without
                  -- this Postgres returns rows in implementation-
                  -- defined order, and re-renders flicker.
                  t.slug ASC
                LIMIT :limit
                """
            ),
            {
                "start": start,
                "end": end,
                "prev_start": prev_start,
                "prev_end": prev_end,
                "min_sample": min_sample,
                "limit": limit,
            },
        )
    ).mappings().all()

    # Fleet median over the same metric + window (no min-sample filter
    # — the median represents fleet-wide center of mass even for low-
    # volume tenants). Computed in a separate query for readability.
    median_row = (
        await db.execute(
            text(
                f"""
                SELECT percentile_cont(0.50) WITHIN GROUP (
                         ORDER BY {duration_sql}
                       ) AS median
                FROM investigations c
                {join_sql}
                WHERE c.closed_at IS NOT NULL
                  AND c.closed_at >= c.opened_at -- skew guard, match ranking CTEs above
                  AND c.closed_at >= :start
                  AND c.closed_at <  :end
                  {where_metric}
                """
            ),
            {"start": start, "end": end},
        )
    ).first()
    fleet_median = float(median_row[0]) if median_row and median_row[0] is not None else None

    return RankingResponse(
        metric=metric,
        days=days,
        min_sample=min_sample,
        fleet_median_seconds=fleet_median,
        rows=[RankingRow(**dict(r)) for r in rows],
    )


# ---------------------------------------------------------------------------
# 3. Activity heatmap (day-of-week × hour-of-day)
# ---------------------------------------------------------------------------


class HeatmapCell(BaseModel):
    dow: int  # 0=Sunday … 6=Saturday (Postgres extract(dow))
    hour: int  # 0..23
    count: int


class HeatmapResponse(BaseModel):
    dimension: str  # "alerts" | "cases"
    days: int
    cells: list[HeatmapCell]


@router.get("/heatmap", response_model=HeatmapResponse)
async def heatmap(
    request: Request,
    dimension: str = Query("alerts", pattern="^(alerts|cases)$"),
    days: int = Query(30, ge=1, le=180),
) -> HeatmapResponse:
    _require_mssp_scope(request)
    db = _db(request)
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=days)

    if dimension == "alerts":
        sql = """
            SELECT extract(dow  FROM first_event_at)::int AS dow,
                   extract(hour FROM first_event_at)::int AS hour,
                   count(*)::int AS count
            FROM alerts
            WHERE first_event_at >= :start AND first_event_at < :end
            GROUP BY 1, 2
            ORDER BY 1, 2
        """
    else:
        sql = """
            SELECT extract(dow  FROM opened_at)::int AS dow,
                   extract(hour FROM opened_at)::int AS hour,
                   count(*)::int AS count
            FROM investigations
            WHERE opened_at >= :start AND opened_at < :end
            GROUP BY 1, 2
            ORDER BY 1, 2
        """

    rows = (
        await db.execute(text(sql), {"start": start, "end": end})
    ).mappings().all()
    return HeatmapResponse(
        dimension=dimension,
        days=days,
        cells=[HeatmapCell(**r) for r in rows],
    )
