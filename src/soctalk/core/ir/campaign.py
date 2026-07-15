"""Campaign discrimination + topology (issue #31).

Turns the record of what happened into judgements about what it means:
is a cluster a declared test, benign scan, or a real intrusion — and what
does the environment look like beneath the alerts.

Deconfliction doctrine: an inferred-benign classification is only ever a
FLAG for confirmation, never a suppression (mimicry is the obvious
adversarial move). A declared engagement deconflicts by window + scope;
tester activity that strays out of scope is a contractual finding, not a
false alarm.
"""

from __future__ import annotations

import ipaddress
import re
from datetime import timedelta
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from soctalk.core.observability.audit import log_audit

# An engagement window longer than this is almost certainly a mistake (a
# forgotten window is a standing blind spot). Bound it at declare time.
DEFAULT_MAX_ENGAGEMENT_DAYS = 90

_TECHNIQUE_RE = re.compile(r"^T\d{4}(\.\d{3})?$")


# ---------------------------------------------------------------- engagements


def _valid_ip_or_cidr(entry: str) -> bool:
    try:
        if "/" in entry:
            ipaddress.ip_network(entry, strict=False)
        else:
            ipaddress.ip_address(entry)
        return True
    except ValueError:
        return False


async def declare_engagement(
    db: AsyncSession, *, tenant_id: UUID, name: str, kind: str,
    starts_at, ends_at, scope_source_ips: list[str],
    scope_hosts: list[str], scope_techniques: list[str],
    created_by: UUID | None = None,
    max_days: int = DEFAULT_MAX_ENGAGEMENT_DAYS,
) -> str:
    """Declare a bounded pentest/red-team window. Analyst-authored source of truth.

    Validated fail-closed so a declaration can never become an accidental
    match-all: a non-empty tester source axis and at least one bounded target
    axis (host or technique) are REQUIRED, and the window is bounded. An
    all-empty scope would deconflict every alert in its window — forbidden here.
    Raises ``ValueError`` on any invalid input.
    """
    if not name or not name.strip():
        raise ValueError("engagement name is required")
    if ends_at <= starts_at:
        raise ValueError("engagement ends_at must be after starts_at")
    if (ends_at - starts_at) > timedelta(days=max_days):
        raise ValueError(f"engagement window exceeds the {max_days}-day maximum")

    src = [s.strip() for s in scope_source_ips if s and s.strip()]
    if not src:
        raise ValueError("scope_source_ips must list at least one tester source ip/cidr")
    bad_ips = [s for s in src if not _valid_ip_or_cidr(s)]
    if bad_ips:
        raise ValueError(f"invalid source ip/cidr: {', '.join(bad_ips)}")

    hosts = [h.strip() for h in scope_hosts if h and h.strip()]
    techs = [t.strip().upper() for t in scope_techniques if t and t.strip()]
    if not hosts and not techs:
        raise ValueError(
            "declare at least one bounded target axis: scope_hosts or scope_techniques"
        )
    bad_tech = [t for t in techs if not _TECHNIQUE_RE.match(t)]
    if bad_tech:
        raise ValueError(f"invalid ATT&CK technique id: {', '.join(bad_tech)}")

    eid = str(uuid4())
    await db.execute(
        text(
            """
            INSERT INTO engagements
              (id, tenant_id, name, kind, starts_at, ends_at,
               scope_source_ips, scope_hosts, scope_techniques)
            VALUES (:id, :t, :n, :k, :s, :e,
                    CAST(:ips AS JSONB), CAST(:hosts AS JSONB), CAST(:tech AS JSONB))
            """
        ),
        {"id": eid, "t": str(tenant_id), "n": name.strip(), "k": kind,
         "s": starts_at, "e": ends_at, "ips": _json(src),
         "hosts": _json(hosts), "tech": _json(techs)},
    )
    await log_audit(
        db, action="ir.engagement.declared",
        actor_principal="analyst", actor_id=str(created_by) if created_by else "system",
        tenant_id=tenant_id, resource_type="engagement", resource_id=eid,
        notes=_json({"name": name.strip(), "kind": kind,
                     "source_ips": src, "hosts": hosts, "techniques": techs}),
    )
    return eid


async def revoke_engagement(
    db: AsyncSession, *, tenant_id: UUID, engagement_id: UUID,
    revoked_by: UUID | None = None, reason: str | None = None,
) -> bool:
    """End a declared window early. Stamps ``revoked_at`` WITHOUT mutating the
    declared ``ends_at`` (the window is audit-bearing). ``deconflict()`` ignores
    revoked engagements immediately. Returns False if not found / already revoked."""
    row = (await db.execute(
        text(
            "UPDATE engagements SET revoked_at = now(), revoked_by = :by, "
            "       revoke_reason = :reason "
            "WHERE id = :id AND tenant_id = :t AND revoked_at IS NULL "
            "RETURNING id"
        ),
        {"id": str(engagement_id), "t": str(tenant_id),
         "by": str(revoked_by) if revoked_by else None, "reason": reason},
    )).first()
    if row is None:
        return False
    await log_audit(
        db, action="ir.engagement.revoked",
        actor_principal="analyst", actor_id=str(revoked_by) if revoked_by else "system",
        tenant_id=tenant_id, resource_type="engagement", resource_id=str(engagement_id),
        notes=reason,
    )
    return True


async def list_engagements(
    db: AsyncSession, *, tenant_id: UUID, include_revoked: bool = False,
) -> list[dict[str, Any]]:
    """List engagements with declared-test / out-of-scope lane counts."""
    where = "WHERE e.tenant_id = :t" + ("" if include_revoked else " AND e.revoked_at IS NULL")
    rows = (await db.execute(
        text(
            f"""
            SELECT e.id, e.name, e.kind, e.starts_at, e.ends_at,
                   e.scope_source_ips, e.scope_hosts, e.scope_techniques,
                   e.revoked_at, e.created_at,
                   count(o.id) FILTER (WHERE o.status = 'declared_test') AS declared_test_count,
                   count(o.id) FILTER (WHERE o.status = 'out_of_scope') AS out_of_scope_count
            FROM engagements e
            LEFT JOIN engagement_observations o
              ON o.primary_engagement_id = e.id AND o.tenant_id = e.tenant_id
            {where}
            GROUP BY e.id
            ORDER BY e.starts_at DESC
            """
        ),
        {"t": str(tenant_id)},
    )).mappings().all()
    return [dict(r) for r in rows]


def _ip_in_scope(ip: str, scope_ips: list[str]) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for entry in scope_ips:
        try:
            if "/" in entry:
                if addr in ipaddress.ip_network(entry, strict=False):
                    return True
            elif ipaddress.ip_address(entry) == addr:
                return True
        except ValueError:
            continue
    return False


async def deconflict(
    db: AsyncSession, *, tenant_id: UUID, occurred_at,
    source_ips: list[str], hosts: list[str], techniques: list[str],
) -> dict[str, Any] | None:
    """Match activity against ALL declared engagements covering this window.

    Windows can legitimately overlap (a pentest and a red-team can run at once),
    so every in-window, non-revoked engagement is considered. FAIL-CLOSED: an
    alert is only ever suppressed as a declared test when it is POSITIVELY
    attributable to the tester — an in-scope source ip must be observed and no
    part of the activity may stray.

    Per engagement, declared_test requires ALL of:
      - the engagement declares a tester source scope (an engagement without one
        can never deconflict — it would be source-blind; skipped);
      - at least one observed source ip is in scope (the tester), and NO observed
        source ip is out of scope;
      - at least one target axis is positively satisfied — an in-scope host OR an
        in-scope technique — and no observed host/technique strays.

    Returns:
      - None: no engagement positively covers this activity (normal triage runs —
        an unattributable alert is never suppressed).
      - {status: 'declared_test', engagement_id, matched_engagement_ids}.
      - {status: 'out_of_scope', engagement_id, out_of_scope}: the tester source
        matched but the activity strayed (out-of-scope host/technique, mixed
        source, or no positive target) — a contractual finding, forced to a look.
    """
    rows = (await db.execute(
        text(
            """
            SELECT id, scope_source_ips, scope_hosts, scope_techniques
            FROM engagements
            WHERE tenant_id = :t AND starts_at <= :occ AND ends_at >= :occ
              AND revoked_at IS NULL
            ORDER BY starts_at DESC
            """
        ),
        {"t": str(tenant_id), "occ": occurred_at},
    )).mappings().all()
    if not rows:
        return None

    matched: list[str] = []
    best_oos: tuple[int, str, dict[str, Any]] | None = None
    for eng in rows:
        scope_ips = list(eng["scope_source_ips"] or [])
        scope_hosts = {h.lower() for h in (eng["scope_hosts"] or [])}
        scope_tech = {t.upper() for t in (eng["scope_techniques"] or [])}
        # An engagement without a tester source scope is source-blind and can
        # never deconflict. declare_engagement() forbids it; legacy rows aren't
        # trusted.
        if not scope_ips:
            continue

        src_in = [ip for ip in source_ips if _ip_in_scope(ip, scope_ips)]
        # Not attributable to this engagement's testers: it does not apply. The
        # alert falls through to normal triage — never silently suppressed.
        if not src_in:
            continue

        src_oos = [ip for ip in source_ips if not _ip_in_scope(ip, scope_ips)]
        host_in = [h for h in hosts if h.lower() in scope_hosts]
        host_oos = [h for h in hosts if scope_hosts and h.lower() not in scope_hosts]
        tech_in = [t for t in techniques if t.upper() in scope_tech]
        tech_oos = [t for t in techniques if scope_tech and t.upper() not in scope_tech]

        target_ok = bool(host_in or tech_in)  # a positive target match is required
        strays = src_oos + host_oos + tech_oos

        if target_ok and not strays:
            matched.append(str(eng["id"]))
        else:
            oos: dict[str, Any] = {
                "source_ips": src_oos, "hosts": host_oos, "techniques": tech_oos,
            }
            if not target_ok:
                oos["missing_target"] = True
            count = len(strays) + (0 if target_ok else 1)
            if best_oos is None or count < best_oos[0]:
                best_oos = (count, str(eng["id"]), oos)

    if matched:
        return {"status": "declared_test", "engagement_id": matched[0],
                "matched_engagement_ids": matched}
    if best_oos is not None:
        return {"status": "out_of_scope", "engagement_id": best_oos[1],
                "matched_engagement_ids": [best_oos[1]], "out_of_scope": best_oos[2]}
    return None


async def record_engagement_observation(
    db: AsyncSession, *, tenant_id: UUID, alert_id: UUID,
    source_event_row_id: UUID, status: str, primary_engagement_id: str,
    matched_engagement_ids: list[str], out_of_scope: dict[str, Any] | None,
    occurred_at,
) -> None:
    """Record one deconflicted alert into the durable declared-test lane.

    Idempotent per source-event row (a replay no-ops). A deconflicted alert is
    NEVER closed/FP — this row is how it stays queryable and counted."""
    await db.execute(
        text(
            """
            INSERT INTO engagement_observations
              (id, tenant_id, primary_engagement_id, matched_engagement_ids,
               alert_id, source_event_row_id, status, out_of_scope, occurred_at)
            VALUES (:id, :t, :peid, CAST(:meids AS JSONB), :aid, :seid, :st,
                    CAST(:oos AS JSONB), :occ)
            ON CONFLICT (tenant_id, source_event_row_id) DO NOTHING
            """
        ),
        {"id": str(uuid4()), "t": str(tenant_id), "peid": primary_engagement_id,
         "meids": _json(matched_engagement_ids), "aid": str(alert_id),
         "seid": str(source_event_row_id), "st": status,
         "oos": _json(out_of_scope) if out_of_scope is not None else None,
         "occ": occurred_at},
    )


# ------------------------------------------------------- probe classification


def classify_activity(features: dict[str, Any]) -> tuple[str, int]:
    """Classify a cluster from the shape of its own activity.

    Features (all optional): breadth (distinct hosts), depth (max stages on
    one host), tool_homogeneity (0..1), business_hours (bool), exfil (bool),
    known_scanner (bool), speed_per_min (events/min).

    Returns (classification, confidence 0..100). This is deterministic and
    conservative: inferred-benign is a flag, never a suppression.
    """
    breadth = int(features.get("breadth", 0))
    depth = int(features.get("depth", 0))
    known_scanner = bool(features.get("known_scanner", False))
    exfil = bool(features.get("exfil", False))
    tool_homogeneity = float(features.get("tool_homogeneity", 0.0))

    # Real campaign: depth (multi-stage on a host) or exfiltration.
    if exfil or depth >= 3:
        return "campaign", 80
    # Benign probe: broad + shallow + homogeneous tooling or known scanner.
    if known_scanner:
        return "inferred_test" if breadth >= 5 else "benign_probe", 60
    if breadth >= 10 and depth <= 1 and tool_homogeneity >= 0.8:
        return "benign_probe", 55
    # Broad + shallow but not clearly benign → inferred test (flag, confirm).
    if breadth >= 8 and depth <= 1:
        return "inferred_test", 50
    return "campaign", 40


async def record_cluster(
    db: AsyncSession, *, tenant_id: UUID, classification: str,
    confidence: int, investigation_ids: list[str],
    features: dict[str, Any], engagement_id: str | None = None,
) -> str:
    cid = str(uuid4())
    needs_confirmation = classification == "inferred_test"
    await db.execute(
        text(
            """
            INSERT INTO activity_clusters
              (id, tenant_id, classification, confidence_score, engagement_id,
               features, investigation_ids, needs_confirmation)
            VALUES (:id, :t, :c, :conf, :eng, CAST(:f AS JSONB),
                    CAST(:inv AS JSONB), :needs)
            """
        ),
        {"id": cid, "t": str(tenant_id), "c": classification, "conf": confidence,
         "eng": engagement_id, "f": _json(features),
         "inv": _json(investigation_ids), "needs": needs_confirmation},
    )
    return cid


# --------------------------------------------------------------- topology


async def upsert_topology_edge(
    db: AsyncSession, *, tenant_id: UUID, src_host: str, dst_host: str,
    port: int | None, adjacency: str, occurred_at,
) -> None:
    """Record/refresh an adjacency edge. Observed beats potential — an
    observed sighting upgrades a prior potential edge and bumps last_seen,
    rather than appending a duplicate row (review finding #5). Uniqueness is
    on the live (non-superseded) edge per (tenant, src, dst, port)."""
    await db.execute(
        text(
            """
            INSERT INTO topology_edges
              (id, tenant_id, src_host, dst_host, port, adjacency,
               first_seen, last_seen)
            VALUES (:id, :t, :s, :d, :p, :adj,
                    CAST(:occ AS timestamptz), CAST(:occ AS timestamptz))
            ON CONFLICT (tenant_id, src_host, dst_host, COALESCE(port, -1))
                WHERE superseded_at IS NULL
            DO UPDATE SET
                last_seen = GREATEST(topology_edges.last_seen, EXCLUDED.last_seen),
                -- observed is a one-way upgrade; never downgrade to potential.
                adjacency = CASE
                    WHEN topology_edges.adjacency = 'observed'
                         OR EXCLUDED.adjacency = 'observed' THEN 'observed'
                    ELSE EXCLUDED.adjacency END
            """
        ),
        {"id": str(uuid4()), "t": str(tenant_id), "s": src_host.lower(),
         "d": dst_host.lower(), "p": port, "adj": adjacency, "occ": occurred_at},
    )


async def attack_path_exists(
    db: AsyncSession, *, tenant_id: UUID, from_host: str, to_host: str,
    max_hops: int = 5,
) -> dict[str, Any]:
    """Is there a live route from ``from_host`` toward a crown-jewel host?

    BFS over live (non-superseded) topology edges. Returns whether a path
    exists, its length, and whether any hop is an OBSERVED edge (activity
    over a never-observed route is more suspicious, not less)."""
    edges = (await db.execute(
        text(
            "SELECT src_host, dst_host, adjacency FROM topology_edges "
            "WHERE tenant_id = :t AND superseded_at IS NULL"
        ),
        {"t": str(tenant_id)},
    )).mappings().all()
    adj: dict[str, list[tuple[str, str]]] = {}
    for e in edges:
        adj.setdefault(e["src_host"], []).append((e["dst_host"], e["adjacency"]))

    start, goal = from_host.lower(), to_host.lower()
    # BFS tracking path length + whether any edge was observed.
    queue: list[tuple[str, int, bool]] = [(start, 0, False)]
    seen = {start}
    while queue:
        node, dist, obs = queue.pop(0)
        if node == goal and dist > 0:
            return {"path_exists": True, "hops": dist, "any_observed": obs}
        if dist >= max_hops:
            continue
        for nxt, kind in adj.get(node, []):
            if nxt not in seen:
                seen.add(nxt)
                queue.append((nxt, dist + 1, obs or kind == "observed"))
    return {"path_exists": False, "hops": None, "any_observed": False}


def _json(obj: Any) -> str:
    import json
    return json.dumps(obj, separators=(",", ":"), sort_keys=True)
