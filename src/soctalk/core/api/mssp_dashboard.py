"""MSSP fleet dashboard endpoints.

Five widgets surfaced on the L1 ``/`` homepage when the operator is in
cross-tenant MSSP scope (``isMsspScope`` true; no ``current_tenant``
pin). Tenant-pinned MSSP users and customer-side roles never reach
these — the frontend conditionally renders the per-tenant dashboard
for those scopes.

Each endpoint runs in MSSP audience (no ``app.current_tenant_id``
set), so the underlying SELECTs span all tenants. Role-gated to
``mssp_admin`` and ``analyst`` (the two MSSP-side roles that drive
operational work — ``customer_viewer`` and tenant roles are filtered
out by the gate, not just the frontend).
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from soctalk.core.tenancy.auth import current_identity
from soctalk.core.tenancy.decorators import require_role
from soctalk.core.tenancy.models import Role


router = APIRouter(
    prefix="/api/mssp/dashboard",
    tags=["mssp-dashboard"],
    dependencies=[Depends(require_role(Role.MSSP_ADMIN, Role.MSSP_MANAGER, Role.ANALYST, Role.PLATFORM_ADMIN))],
)


def _db(request: Request) -> AsyncSession:
    s = getattr(request.state, "db", None)
    if s is None:
        raise HTTPException(500, "db session not attached")
    return s


def _require_mssp_scope(request: Request) -> None:
    """Belt-and-braces: role decorator allows MSSP-side roles, but if
    a session is currently pinned to a tenant via "Open SOC", the
    cross-tenant queries below would still leak no data — the SELECTs
    use no ``app.current_tenant_id`` set, so they span everything.
    Reject pinned sessions explicitly so the contract matches the
    frontend's ``isMsspScope`` gate.
    """
    identity = current_identity(request)
    if identity is None:
        raise HTTPException(401, "authentication required")
    if identity.current_tenant is not None:
        raise HTTPException(
            409,
            "fleet dashboard requires cross-tenant scope; clear the "
            "tenant pin first",
        )


# ---------------------------------------------------------------------------
# 1. Pending reviews by tenant
# ---------------------------------------------------------------------------


class PendingReviewRow(BaseModel):
    tenant_id: str
    slug: str
    display_name: str
    count: int


class PendingReviewsResponse(BaseModel):
    items: list[PendingReviewRow]


@router.get("/pending-reviews", response_model=PendingReviewsResponse)
async def pending_reviews(request: Request) -> PendingReviewsResponse:
    _require_mssp_scope(request)
    db = _db(request)
    rows = (
        await db.execute(
            text(
                """
                SELECT t.id::text AS tenant_id, t.slug, t.display_name,
                       count(*)::int AS count
                FROM investigations c
                JOIN tenants t ON t.id = c.tenant_id
                WHERE c.status = 'active'
                  AND EXISTS (
                    SELECT 1 FROM investigation_runs cr
                    WHERE cr.investigation_id = c.id AND cr.last_error IS NOT NULL
                  )
                GROUP BY t.id, t.slug, t.display_name
                ORDER BY count DESC, t.slug ASC
                """
            )
        )
    ).mappings().all()
    return PendingReviewsResponse(items=[PendingReviewRow(**r) for r in rows])


# ---------------------------------------------------------------------------
# 2. Open investigations by tenant (oldest + max severity)
# ---------------------------------------------------------------------------


class OpenByTenantRow(BaseModel):
    tenant_id: str
    slug: str
    display_name: str
    open_count: int
    oldest_opened_at: str | None
    max_severity: int | None


class OpenByTenantResponse(BaseModel):
    items: list[OpenByTenantRow]


@router.get("/open-by-tenant", response_model=OpenByTenantResponse)
async def open_by_tenant(request: Request) -> OpenByTenantResponse:
    _require_mssp_scope(request)
    db = _db(request)
    rows = (
        await db.execute(
            text(
                """
                SELECT t.id::text AS tenant_id, t.slug, t.display_name,
                       count(*)::int AS open_count,
                       min(c.opened_at)::text AS oldest_opened_at,
                       max(c.severity) AS max_severity
                FROM investigations c
                JOIN tenants t ON t.id = c.tenant_id
                WHERE c.status = 'active'
                GROUP BY t.id, t.slug, t.display_name
                ORDER BY oldest_opened_at ASC NULLS LAST
                """
            )
        )
    ).mappings().all()
    return OpenByTenantResponse(items=[OpenByTenantRow(**r) for r in rows])


# ---------------------------------------------------------------------------
# 3. Stuck cases (active + no activity in N hours)
# ---------------------------------------------------------------------------
#
# "Activity" = any of:
#   - the investigation itself was just opened
#   - a new case_run landed
#   - a case_event landed
# audit_log has no direct investigation_id column (investigation ids live inside the
# ``details`` JSONB), so we don't join it here. v1.1 can layer that in
# once we either add a column or commit to a JSONB index.


class StuckCaseRow(BaseModel):
    investigation_id: str
    tenant_id: str
    slug: str
    display_name: str
    opened_at: str
    last_activity_at: str
    severity: int
    stuck_for_seconds: int


class StuckInvestigationsResponse(BaseModel):
    items: list[StuckCaseRow]


@router.get("/stuck-investigations", response_model=StuckInvestigationsResponse)
async def stuck_investigations(
    request: Request, hours: int = Query(8, ge=1, le=720)
) -> StuckInvestigationsResponse:
    _require_mssp_scope(request)
    db = _db(request)
    rows = (
        await db.execute(
            text(
                """
                WITH last_run AS (
                  -- ``investigation_runs`` uses started_at/ended_at, not
                  -- created_at. Treat the most-recent of either as
                  -- "run activity": a started-but-still-running run
                  -- is just as live as one that ended seconds ago.
                  SELECT investigation_id,
                         max(coalesce(ended_at, started_at)) AS ts
                  FROM investigation_runs GROUP BY investigation_id
                ),
                last_event AS (
                  SELECT investigation_id, max(created_at) AS ts
                  FROM investigation_events GROUP BY investigation_id
                ),
                latest AS (
                  SELECT c.id AS investigation_id, c.tenant_id, c.opened_at, c.severity,
                         greatest(
                           c.opened_at,
                           coalesce(lr.ts, c.opened_at),
                           coalesce(le.ts, c.opened_at)
                         ) AS last_activity_at
                  FROM investigations c
                  LEFT JOIN last_run   lr ON lr.investigation_id = c.id
                  LEFT JOIN last_event le ON le.investigation_id = c.id
                  WHERE c.status = 'active'
                )
                SELECT l.investigation_id::text AS investigation_id, t.id::text AS tenant_id,
                       t.slug, t.display_name,
                       l.opened_at::text AS opened_at,
                       l.last_activity_at::text AS last_activity_at,
                       l.severity,
                       extract(epoch FROM (now() - l.last_activity_at))::int
                         AS stuck_for_seconds
                FROM latest l
                JOIN tenants t ON t.id = l.tenant_id
                WHERE l.last_activity_at < now() - make_interval(hours => :hours)
                ORDER BY l.last_activity_at ASC
                """
            ),
            {"hours": hours},
        )
    ).mappings().all()
    return StuckInvestigationsResponse(items=[StuckCaseRow(**r) for r in rows])


# ---------------------------------------------------------------------------
# 4. Per-tenant adapter health
# ---------------------------------------------------------------------------
#
# "Degraded" in MSSP context = per-tenant adapter silent or tenant in a
# non-running state. The adapter writes ``runtime->>'last_heartbeat'``
# on each /api/internal/adapter/heartbeat call. Threshold for unhealthy
# heartbeat is 5 minutes (the chart sets 60s heartbeat interval; 5x
# that catches transient flakes without false alarms).


_HEARTBEAT_UNHEALTHY_AGE_SECONDS = 300


class TenantHealthRow(BaseModel):
    tenant_id: str
    slug: str
    display_name: str
    state: str
    last_heartbeat: str | None
    heartbeat_age_seconds: int | None
    unhealthy: bool


class TenantHealthResponse(BaseModel):
    items: list[TenantHealthRow]


@router.get("/tenant-health", response_model=TenantHealthResponse)
async def tenant_health(request: Request) -> TenantHealthResponse:
    _require_mssp_scope(request)
    db = _db(request)
    # Decommissioned/archived/purged tenants are intentionally silent
    # — surfacing them as "no heartbeat" red alerts on the dashboard
    # is misleading. Hide them from this widget entirely; the lifecycle
    # view in /tenants is where their state belongs. Suspended tenants
    # stay visible (suspension is a soft-pause; ops should see them).
    rows = (
        await db.execute(
            text(
                """
                SELECT t.id::text AS tenant_id, t.slug, t.display_name,
                       t.state,
                       (t.runtime->>'last_heartbeat') AS last_heartbeat
                FROM tenants t
                WHERE t.deleted_at IS NULL
                  AND t.state NOT IN ('decommissioning', 'archived', 'purged')
                ORDER BY t.slug ASC
                """
            )
        )
    ).mappings().all()

    from datetime import datetime, timezone

    now = datetime.now(timezone.utc)
    items: list[TenantHealthRow] = []
    for r in rows:
        age: int | None = None
        if r["last_heartbeat"]:
            try:
                hb = datetime.fromisoformat(
                    r["last_heartbeat"].replace("Z", "+00:00")
                )
                if hb.tzinfo is None:
                    hb = hb.replace(tzinfo=timezone.utc)
                age = int((now - hb).total_seconds())
            except (TypeError, ValueError):
                age = None
        unhealthy = (
            r["state"] in ("pending", "provisioning", "degraded")
            or age is None
            or age > _HEARTBEAT_UNHEALTHY_AGE_SECONDS
        )
        items.append(
            TenantHealthRow(
                tenant_id=r["tenant_id"],
                slug=r["slug"],
                display_name=r["display_name"],
                state=r["state"],
                last_heartbeat=r["last_heartbeat"],
                heartbeat_age_seconds=age,
                unhealthy=unhealthy,
            )
        )
    return TenantHealthResponse(items=items)


# ---------------------------------------------------------------------------
# 5. Repeated IOCs across ≥ 2 tenants (last N days)
# ---------------------------------------------------------------------------


class RepeatedIocTenantRef(BaseModel):
    id: str
    slug: str
    display_name: str


class RepeatedIocRow(BaseModel):
    ioc_type: str
    ioc_value: str
    tenant_count: int
    tenants: list[RepeatedIocTenantRef]
    first_seen: str
    last_seen: str
    max_severity: int


class RepeatedIocsResponse(BaseModel):
    items: list[RepeatedIocRow]
    days: int
    threshold: int


@router.get("/repeated-iocs", response_model=RepeatedIocsResponse)
async def repeated_iocs(
    request: Request,
    days: int = Query(7, ge=1, le=90),
    limit: int = Query(50, ge=1, le=500),
) -> RepeatedIocsResponse:
    _require_mssp_scope(request)
    # Customer-facing role gate (the require_role decorator already
    # excludes customer_viewer, but defense-in-depth — IOC clusters
    # are explicitly MSSP-internal context and not exposed to
    # customer roles even if the role list ever changes).
    identity = current_identity(request)
    if identity is None or identity.user_type != "mssp":
        raise HTTPException(403, "MSSP-side roles only")

    db = _db(request)
    rows = (
        await db.execute(
            text(
                """
                WITH expanded AS (
                  SELECT a.tenant_id,
                         jsonb_array_elements(a.initial_iocs) AS ioc,
                         a.first_event_at,
                         a.severity
                  FROM alerts a
                  WHERE a.first_event_at >= now() - make_interval(days => :days)
                    AND a.initial_iocs IS NOT NULL
                    AND jsonb_typeof(a.initial_iocs) = 'array'
                ),
                agg AS (
                  SELECT ioc->>'type'  AS ioc_type,
                         ioc->>'value' AS ioc_value,
                         count(distinct tenant_id) AS tenant_count,
                         array_agg(distinct tenant_id) AS tenant_ids,
                         min(first_event_at) AS first_seen,
                         max(first_event_at) AS last_seen,
                         max(severity)       AS max_severity
                  FROM expanded
                  WHERE ioc->>'type' IS NOT NULL
                    AND ioc->>'value' IS NOT NULL
                  GROUP BY ioc->>'type', ioc->>'value'
                  HAVING count(distinct tenant_id) >= 2
                )
                SELECT a.ioc_type, a.ioc_value, a.tenant_count,
                       a.tenant_ids,
                       a.first_seen::text AS first_seen,
                       a.last_seen::text  AS last_seen,
                       a.max_severity
                FROM agg a
                ORDER BY a.tenant_count DESC, a.last_seen DESC,
                         a.max_severity DESC
                LIMIT :limit
                """
            ),
            {"days": days, "limit": limit},
        )
    ).mappings().all()

    if not rows:
        return RepeatedIocsResponse(items=[], days=days, threshold=2)

    # Resolve tenant slugs / display names in one round-trip.
    all_ids: set[Any] = set()
    for r in rows:
        for tid in r["tenant_ids"] or []:
            all_ids.add(tid)
    tenant_lookup: dict[str, dict[str, str]] = {}
    if all_ids:
        t_rows = (
            await db.execute(
                text(
                    """
                    SELECT id::text AS id, slug, display_name
                    FROM tenants
                    WHERE id = ANY(:ids)
                    """
                ),
                {"ids": list(all_ids)},
            )
        ).mappings().all()
        tenant_lookup = {t["id"]: dict(t) for t in t_rows}

    items: list[RepeatedIocRow] = []
    for r in rows:
        refs = [
            RepeatedIocTenantRef(**tenant_lookup[str(tid)])
            for tid in (r["tenant_ids"] or [])
            if str(tid) in tenant_lookup
        ]
        items.append(
            RepeatedIocRow(
                ioc_type=r["ioc_type"],
                ioc_value=r["ioc_value"],
                tenant_count=int(r["tenant_count"]),
                tenants=refs,
                first_seen=r["first_seen"],
                last_seen=r["last_seen"],
                max_severity=int(r["max_severity"]),
            )
        )

    return RepeatedIocsResponse(items=items, days=days, threshold=2)
