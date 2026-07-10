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
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession


# ---------------------------------------------------------------- engagements


async def declare_engagement(
    db: AsyncSession, *, tenant_id: UUID, name: str, kind: str,
    starts_at, ends_at, scope_source_ips: list[str],
    scope_hosts: list[str], scope_techniques: list[str],
) -> str:
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
        {"id": eid, "t": str(tenant_id), "n": name, "k": kind,
         "s": starts_at, "e": ends_at, "ips": _json(scope_source_ips),
         "hosts": _json(scope_hosts), "tech": _json(scope_techniques)},
    )
    return eid


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
    """Match activity against declared engagements.

    Returns:
      - None: no engagement covers this window.
      - {status: 'declared_test', ...}: in-window AND fully in-scope.
      - {status: 'out_of_scope', out_of_scope: {...}}: in-window but the
        activity strays outside declared scope — a contractual finding,
        surfaced, never suppressed.
    """
    eng = (await db.execute(
        text(
            """
            SELECT id, scope_source_ips, scope_hosts, scope_techniques
            FROM engagements
            WHERE tenant_id = :t AND starts_at <= :occ AND ends_at >= :occ
            ORDER BY starts_at DESC LIMIT 1
            """
        ),
        {"t": str(tenant_id), "occ": occurred_at},
    )).mappings().first()
    if eng is None:
        return None

    scope_ips = list(eng["scope_source_ips"] or [])
    scope_hosts = {h.lower() for h in (eng["scope_hosts"] or [])}
    scope_tech = {t.upper() for t in (eng["scope_techniques"] or [])}

    oos_ips = [ip for ip in source_ips if scope_ips and not _ip_in_scope(ip, scope_ips)]
    oos_hosts = [h for h in hosts if scope_hosts and h.lower() not in scope_hosts]
    oos_tech = [t for t in techniques if scope_tech and t.upper() not in scope_tech]

    if oos_ips or oos_hosts or oos_tech:
        return {
            "status": "out_of_scope",
            "engagement_id": str(eng["id"]),
            "out_of_scope": {"source_ips": oos_ips, "hosts": oos_hosts,
                             "techniques": oos_tech},
        }
    return {"status": "declared_test", "engagement_id": str(eng["id"])}


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
