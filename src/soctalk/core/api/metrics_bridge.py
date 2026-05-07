"""Bridge endpoints for the canonical Dashboard.

The legacy SocTalk dashboard expected ``/api/metrics/overview`` and
``/api/metrics/hourly`` against single-tenant Investigation tables.
This module maps V1 ``cases`` + ``investigation_runs`` into those shapes so
the Dashboard renders against the multi-tenant install without a
frontend rewrite.

Tenant scoping is inherited from the session middleware: the
canonical app's queries land with ``app.current_tenant_id`` already
set (or empty + audience='mssp' for cross-tenant MSSP roles). RLS
on cases/investigation_runs does the filtering — same pattern as
``investigations_bridge``.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from soctalk.core.tenancy.auth import current_identity


router = APIRouter(prefix="/api/metrics", tags=["metrics-bridge"])


def _db(request: Request) -> AsyncSession:
    s = getattr(request.state, "db", None)
    if s is None:
        raise HTTPException(500, "db session not attached")
    return s


def _require_authed(request: Request) -> None:
    if current_identity(request) is None:
        raise HTTPException(401, "authentication required")


class MetricsOverview(BaseModel):
    open_investigations: int
    pending_reviews: int
    investigations_created_today: int
    investigations_closed_today: int
    escalations_today: int
    auto_closed_today: int
    avg_time_to_triage_seconds: float | None
    avg_time_to_verdict_seconds: float | None
    total_alerts_today: int
    total_observables_today: int
    malicious_observables_today: int
    severity_breakdown: dict[str, int]
    verdict_breakdown: dict[str, int]


class HourlyMetric(BaseModel):
    hour: str
    investigations_created: int
    investigations_closed: int
    escalations: int
    auto_closed: int
    avg_time_to_verdict_seconds: float | None
    total_alerts: int
    total_observables: int
    malicious_observables: int
    open_wip: int


class HourlyMetricsResponse(BaseModel):
    metrics: list[HourlyMetric]
    start: str
    end: str
    total_hours: int


@router.get("/overview", response_model=MetricsOverview)
async def overview(request: Request) -> MetricsOverview:
    _require_authed(request)
    db = _db(request)

    # Single round-trip rollup. RLS filters to the session's tenant
    # scope; for cross-tenant MSSP audience, no app.current_tenant_id
    # is set and the policies open the gate.
    row = (
        await db.execute(
            text(
                """
                SELECT
                  count(*) FILTER (WHERE c.status = 'active')           AS open_count,
                  count(*) FILTER (WHERE c.status = 'active'
                                   AND EXISTS (
                                     SELECT 1 FROM investigation_runs cr
                                     WHERE cr.investigation_id = c.id
                                       AND cr.last_error IS NOT NULL
                                   ))                                    AS pending_reviews,
                  count(*) FILTER (WHERE c.opened_at >= date_trunc('day', now())) AS opened_today,
                  count(*) FILTER (WHERE c.closed_at IS NOT NULL
                                   AND c.closed_at >= date_trunc('day', now()))   AS closed_today,
                  count(*) FILTER (WHERE c.status = 'auto_closed_fp'
                                   AND c.closed_at >= date_trunc('day', now()))   AS auto_closed_today,
                  -- Escalations = cases whose terminal verdict was
                  -- "escalate" today. The severity KPI alone (>=12)
                  -- includes cases that opened critical but haven't
                  -- been adjudicated, which would falsely show as
                  -- escalated verdicts on the dashboard.
                  count(*) FILTER (WHERE c.status IN ('escalated', 'closed_tp')
                                   AND c.closed_at IS NOT NULL
                                   AND c.closed_at >= date_trunc('day', now()))   AS escalations_today,
                  -- Severity buckets are rendered in the UI as
                  -- "Open by Severity" and divided by open_count, so
                  -- only count cases that are still active. Without
                  -- this filter closed cases inflate the buckets and
                  -- the bars overflow 100%.
                  count(*) FILTER (WHERE c.status = 'active'
                                   AND c.severity >= 12)              AS critical_total,
                  count(*) FILTER (WHERE c.status = 'active'
                                   AND c.severity BETWEEN 8 AND 11)   AS high_total,
                  count(*) FILTER (WHERE c.status = 'active'
                                   AND c.severity BETWEEN 5 AND 7)    AS medium_total,
                  count(*) FILTER (WHERE c.status = 'active'
                                   AND c.severity < 5)                AS low_total
                FROM investigations c
                """
            )
        )
    ).mappings().first()

    alerts_today = (
        await db.execute(
            text(
                """
                SELECT
                  count(*)                                                           AS total_alerts,
                  coalesce(sum(jsonb_array_length(initial_iocs)), 0)::int            AS total_iocs
                FROM alerts
                WHERE first_event_at >= date_trunc('day', now())
                """
            )
        )
    ).mappings().first()

    # Verdict breakdown is rendered on the dashboard as "Verdicts
    # Today" — the UI's labels and bar colors are keyed on the legacy
    # decision names (``escalate``, ``auto_close``, ``close``), and
    # it shows the empty state only when the dict has no entries.
    # Use those keys directly and omit zero-count buckets so a fresh
    # install reads as "No verdicts yet today" instead of "0
    # escalated, 0 auto-closed".
    auto_closed_today = int(row["auto_closed_today"] or 0)
    escalations_today = int(row["escalations_today"] or 0)
    verdicts: dict[str, int] = {}
    if escalations_today:
        verdicts["escalate"] = escalations_today
    if auto_closed_today:
        verdicts["auto_close"] = auto_closed_today

    # Severity buckets: empty dict on a fresh install (or any scope
    # with no open cases) so the dashboard can render its empty
    # state. With four-zero-valued buckets the UI divides by
    # ``open_investigations`` and produces NaN%.
    open_count = int(row["open_count"] or 0)
    if open_count == 0:
        sev: dict[str, int] = {}
    else:
        sev = {
            "critical": int(row["critical_total"] or 0),
            "high": int(row["high_total"] or 0),
            "medium": int(row["medium_total"] or 0),
            "low": int(row["low_total"] or 0),
        }

    # Avg time-to-verdict over today's closed cases.
    ttv_row = (
        await db.execute(
            text(
                """
                SELECT
                  avg(extract(epoch from (closed_at - opened_at)))::float AS avg_ttv
                FROM investigations
                WHERE closed_at IS NOT NULL
                  AND closed_at >= date_trunc('day', now())
                """
            )
        )
    ).mappings().first()

    return MetricsOverview(
        open_investigations=int(row["open_count"] or 0),
        pending_reviews=int(row["pending_reviews"] or 0),
        investigations_created_today=int(row["opened_today"] or 0),
        investigations_closed_today=int(row["closed_today"] or 0),
        escalations_today=int(row["escalations_today"] or 0),
        auto_closed_today=int(row["auto_closed_today"] or 0),
        avg_time_to_triage_seconds=None,
        avg_time_to_verdict_seconds=(
            float(ttv_row["avg_ttv"]) if ttv_row["avg_ttv"] is not None else None
        ),
        total_alerts_today=int(alerts_today["total_alerts"] or 0),
        total_observables_today=int(alerts_today["total_iocs"] or 0),
        # We don't run cortex on the lab so there's no malicious-IOC
        # signal in the DB. Return 0 rather than fake.
        malicious_observables_today=0,
        severity_breakdown=sev,
        verdict_breakdown=verdicts,
    )


@router.get("/hourly", response_model=HourlyMetricsResponse)
async def hourly(
    request: Request, hours: int = Query(24, ge=1, le=168)
) -> HourlyMetricsResponse:
    _require_authed(request)
    db = _db(request)

    end = datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0)
    start = end - timedelta(hours=hours - 1)

    # Bucket cases + alerts into hourly slots and roll up. Generate
    # the full bucket series with generate_series so empty hours
    # render as zero rows on the chart instead of gaps.
    # asyncpg parses ``:`` as the start of a parameter token, which
    # collides with PostgreSQL's ``::`` cast operator. Bind the
    # timezone-aware datetimes directly (no in-SQL cast needed) and
    # use ``+ interval`` arithmetic on the parameters.
    rows = (
        await db.execute(
            text(
                """
                WITH buckets AS (
                  SELECT generate_series(
                    :start,
                    :end,
                    interval '1 hour'
                  ) AS hour
                ),
                opened AS (
                  SELECT date_trunc('hour', opened_at) AS hour, count(*) AS n
                  FROM investigations
                  WHERE opened_at BETWEEN :start AND :end + interval '1 hour'
                  GROUP BY 1
                ),
                closed AS (
                  SELECT date_trunc('hour', closed_at) AS hour, count(*) AS n,
                         count(*) FILTER (WHERE status = 'auto_closed_fp') AS auto_closed,
                         -- Escalations match the overview KPI: cases
                         -- whose terminal verdict was "escalate".
                         count(*) FILTER (WHERE status IN ('escalated', 'closed_tp')) AS escalations,
                         avg(extract(epoch from (closed_at - opened_at))) AS avg_ttv
                  FROM investigations
                  WHERE closed_at BETWEEN :start AND :end + interval '1 hour'
                  GROUP BY 1
                ),
                alerts_by_hour AS (
                  SELECT date_trunc('hour', first_event_at) AS hour,
                         count(*) AS n,
                         coalesce(sum(jsonb_array_length(initial_iocs)), 0) AS iocs
                  FROM alerts
                  WHERE first_event_at BETWEEN :start AND :end + interval '1 hour'
                  GROUP BY 1
                )
                SELECT
                  b.hour,
                  coalesce(o.n, 0)            AS investigations_created,
                  coalesce(cl.n, 0)           AS investigations_closed,
                  coalesce(cl.auto_closed, 0) AS auto_closed,
                  coalesce(cl.escalations, 0) AS escalations,
                  cl.avg_ttv                  AS avg_ttv,
                  coalesce(a.n, 0)            AS total_alerts,
                  coalesce(a.iocs, 0)         AS total_observables
                FROM buckets b
                LEFT JOIN opened    o  ON o.hour  = b.hour
                LEFT JOIN closed    cl ON cl.hour = b.hour
                LEFT JOIN alerts_by_hour a ON a.hour = b.hour
                ORDER BY b.hour ASC
                """
            ),
            {"start": start, "end": end},
        )
    ).mappings().all()

    # Running open-WIP: cases opened before ``start`` and still open at
    # ``start`` form the initial backlog; each hour adds inflow minus
    # outflow from that base. Without the seed, dashboards spanning a
    # cluster with pre-existing open cases would show open_wip=0 in
    # early buckets even while ``open_investigations`` reports >0.
    initial_open = (
        await db.execute(
            text(
                """
                SELECT count(*) FROM investigations
                WHERE opened_at < :start
                  AND (closed_at IS NULL OR closed_at >= :start)
                """
            ),
            {"start": start},
        )
    ).scalar_one()
    series: list[HourlyMetric] = []
    cum_open = int(initial_open or 0)
    for r in rows:
        cum_open += int(r["investigations_created"] or 0) - int(
            r["investigations_closed"] or 0
        )
        series.append(
            HourlyMetric(
                hour=r["hour"].isoformat(),
                investigations_created=int(r["investigations_created"] or 0),
                investigations_closed=int(r["investigations_closed"] or 0),
                escalations=int(r["escalations"] or 0),
                auto_closed=int(r["auto_closed"] or 0),
                avg_time_to_verdict_seconds=(
                    float(r["avg_ttv"]) if r["avg_ttv"] is not None else None
                ),
                total_alerts=int(r["total_alerts"] or 0),
                total_observables=int(r["total_observables"] or 0),
                malicious_observables=0,
                open_wip=max(0, cum_open),
            )
        )

    return HourlyMetricsResponse(
        metrics=series,
        start=start.isoformat(),
        end=end.isoformat(),
        total_hours=len(series),
    )
