"""Demo-box seeder (issue #72): realistic volume through the FRONT DOOR.

Everything enters via the real adapter endpoint with real occurrence
timestamps; authorization facts enter via the real facts API; the
reasoning tail is triaged by a real runs-worker pointed at the scripted
provider (provider.py) — zero runtime inference, zero API tokens.

One command does a full day:

    uv run python scripts/demo-seed/seed.py run \
        --api http://127.0.0.1:8000 --tenant-id <uuid> \
        --adapter-token $ADAPTER_TOKEN [--seed 1] [--dry-run]

It: plans the day (diurnal curve + bursts) → writes the provider manifest
→ submits grants covering the 'covered'/'goldens_close' events → injects
in occurrence order → prints the adapter's action counts. `verify` prints
fleet-day counters through the MSSP API.

Family → expected pipeline path (authored to the verified gates):
  noise/webscan  sev<=2, no MITRE  → ingest rules-band auto-close
  operational    rule 202 groups   → graph operational close (no provider call)
  covered        grant matches     → scripted close, guard pass
  veto           facts, none cover → scripted close, REAL guard override
  escalate       compromised actor → scripted escalate → human lane
  goldens_*      vendored corpus   → per gold label (close / veto / escalate)
"""

from __future__ import annotations

import argparse
import json
import os
import random
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from zoneinfo import ZoneInfo

import httpx

sys.path.insert(0, str(Path(__file__).parent))
from families import (  # noqa: E402
    EventTemplate,
    goldens_events,
    noise_events,
    operational_events,
    scripted_families,
    webscan_events,
)

# Hour-of-day arrival weights (local demo time): quiet nights, two peaks.
DIURNAL = [2, 1, 1, 1, 1, 2, 4, 8, 12, 14, 13, 11, 9, 9, 12, 13, 11, 8, 6, 5, 4, 3, 3, 2]


def build_plan(args: argparse.Namespace) -> list[dict]:
    rng = random.Random(args.seed)
    events: list[EventTemplate] = []
    events += noise_events(rng, args.noise)
    events += operational_events(rng, args.operational)
    for _ in range(args.webscan_bursts):
        events += webscan_events(rng, args.webscan_size)
    events += scripted_families(rng, args.covered, args.veto, args.escalate)
    events += goldens_events(rng, args.goldens)

    # The fleet time-lapse windows on the VIEWER's local day (the frontend
    # sends Intl timeZone to /analytics/fleet-day, and closes are stamped
    # now()). Default the arrival window to local-midnight -> now in
    # --tz so dots and close counters land on the same lapse day; a UTC
    # default would straddle the local midnight for any non-UTC audience.
    zone = ZoneInfo(args.tz)
    start = (
        datetime.fromisoformat(args.window_start)
        if args.window_start
        else datetime.now(zone).replace(hour=0, minute=0, second=0, microsecond=0)
    )
    end = (
        datetime.fromisoformat(args.window_end)
        if args.window_end
        else datetime.now(UTC) - timedelta(minutes=2)
    )
    span_hours = max(1e-6, (end - start).total_seconds() / 3600)

    def draw_ts() -> datetime:
        # Rejection-sample an hour by diurnal weight inside the window.
        while True:
            offset = rng.uniform(0, span_hours)
            t = start + timedelta(hours=offset)
            if rng.uniform(0, max(DIURNAL)) <= DIURNAL[t.hour]:
                return t

    plan: list[dict] = []
    burst_anchor: dict[str, datetime] = {}
    for i, ev in enumerate(events):
        if ev.family == "webscan":
            # Cluster each burst's events within ~4 minutes of its anchor.
            anchor_key = next(e["value"] for e in ev.entities if e["type"] == "ip")
            anchor = burst_anchor.setdefault(anchor_key, draw_ts())
            ts = anchor + timedelta(seconds=rng.uniform(0, 240))
        else:
            ts = draw_ts()
        if ts > end:
            ts = end
        plan.append(
            {
                "ts": ts.isoformat(),
                "template": ev,
                "source_event_id": f"seed-{args.seed}-{i:05d}",
            }
        )
    plan.sort(key=lambda p: p["ts"])
    return plan


def facts_for_plan(plan: list[dict], tenant_id: str) -> list[dict]:
    """One standing-baseline grant per covered/goldens_close event, in the
    LIVE-BINDING vocabulary: subject=user entity, target=host entity,
    action=rule_id. Plus two texture records (expired + rejected tickets)."""
    facts: list[dict] = []
    now = datetime.now(UTC)
    for p in plan:
        ev: EventTemplate = p["template"]
        if ev.family not in ("covered", "goldens_close"):
            continue
        host = next(e["value"] for e in ev.entities if e["type"] == "host")
        user = next((e["value"] for e in ev.entities if e["type"] == "user"), "svc-app")
        facts.append(
            {
                "id": f"seed-grant-{host}-{ev.rule_id}",
                "kind": "grant",
                "track": "account",
                "grant_class": "standing_baseline",
                "status": "approved",
                "scope": {"subject": user, "target": host, "action": ev.rule_id},
                "created_by": "demo-seed",
            }
        )
    facts.append(
        {
            "id": "seed-ticket-expired-fin",
            "kind": "grant",
            "track": "account",
            "grant_class": "change_ticket",
            "status": "approved",
            "scope": {"subject": "svc-legacy", "target": "fin-db-legacy", "action": "5402"},
            "valid_until": (now - timedelta(days=6)).isoformat(),
            "created_by": "demo-seed",
        }
    )
    facts.append(
        {
            "id": "seed-ticket-rejected-fin",
            "kind": "grant",
            "track": "account",
            "grant_class": "change_ticket",
            "status": "rejected",
            "scope": {"subject": "svc-legacy", "target": "fin-db-legacy", "action": "5402"},
            "valid_until": (now + timedelta(days=20)).isoformat(),
            "created_by": "demo-seed",
        }
    )
    return facts


def write_manifest(plan: list[dict], path: Path) -> int:
    manifest = {}
    for p in plan:
        ev: EventTemplate = p["template"]
        if ev.script:
            manifest[ev.script["key"]] = {k: v for k, v in ev.script.items() if k != "key"}
    # Atomic publish: the provider hot-reloads by mtime and cannot read a
    # half-written file. Write to a temp sibling + os.replace.
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(manifest, indent=1))
    os.replace(tmp, path)
    return len(manifest)


def to_adapter_event(p: dict) -> dict:
    ev: EventTemplate = p["template"]
    return {
        "source_event_id": p["source_event_id"],
        "source": "wazuh",
        "rule_id": ev.rule_id,
        "severity": ev.severity,
        "asset_ids": ev.assets or [e["value"] for e in ev.entities if e["type"] == "host"],
        "initial_iocs": ev.iocs,
        "ts": p["ts"],
        "title": ev.title,
        "description": ev.description,
        "entities": ev.entities,
        "mitre": ev.mitre,
        "rule_groups": ev.rule_groups,
        "template_hash": ev.template_hash,
        "template_version": "1",
    }


def cmd_run(args: argparse.Namespace) -> None:
    if args.batch_size > 500:
        raise SystemExit("--batch-size must be <= 500 (adapter wire cap)")

    plan = build_plan(args)
    by_family: dict[str, int] = {}
    for p in plan:
        by_family[p["template"].family] = by_family.get(p["template"].family, 0) + 1
    print(f"plan: {len(plan)} events {by_family}")

    n_scripts = write_manifest(plan, Path(args.manifest))
    print(f"manifest: {n_scripts} scripted plays -> {args.manifest}")

    if args.dry_run:
        return

    client = httpx.Client(base_url=args.api, timeout=60.0)
    headers = {"Authorization": f"Bearer {args.adapter_token}"}

    facts = facts_for_plan(plan, args.tenant_id)
    r = client.post(
        "/api/internal/authorization/facts",
        headers=headers,
        json={"tenant_id": args.tenant_id, "facts": facts},
    )
    r.raise_for_status()
    body = r.json()
    print(f"facts: stored={len(body.get('stored', []))} errors={len(body.get('errors', []))}")
    if body.get("errors"):
        print(json.dumps(body["errors"][:3], indent=1))

    totals: dict[str, int] = {}
    for i in range(0, len(plan), args.batch_size):
        batch = plan[i : i + args.batch_size]
        r = client.post(
            "/api/internal/adapter/events",
            headers=headers,
            json={
                "tenant_id": args.tenant_id,
                "schema_version": 2,
                "events": [to_adapter_event(p) for p in batch],
            },
        )
        r.raise_for_status()
        for k, v in r.json().get("action_counts", {}).items():
            totals[k] = totals.get(k, 0) + v
        print(f"batch {i // args.batch_size + 1}: {r.json().get('action_counts')}")
    print(f"TOTAL actions: {totals}")


def cmd_verify(args: argparse.Namespace) -> None:
    client = httpx.Client(base_url=args.api, timeout=60.0)
    origin = args.origin or args.api
    r = client.post(
        "/api/auth/login",
        headers={"Origin": origin},
        json={"email": args.admin_email, "password": args.admin_password},
    )
    r.raise_for_status()
    client.post(
        "/api/auth/assume-tenant",
        headers={"Origin": origin},
        json={"tenant_id": args.tenant_id},
    ).raise_for_status()
    day = client.get("/api/analytics/fleet-day").json()
    keys = [
        "ingested",
        "closed_ingest_memoized",
        "closed_ingest_rules",
        "closed_operational",
        "closed_reasoning",
        "escalated",
        "guard_vetoes",
        "still_open",
        "sample_rate",
    ]
    print(json.dumps({k: day.get(k) for k in keys}, indent=1))
    live = client.get("/api/analytics/fleet-live").json()
    print(
        json.dumps(
            {"in_flight": live.get("in_flight"), "open_by_stage": live.get("open_by_stage")},
            indent=1,
        )
    )


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)

    runp = sub.add_parser("run", help="plan + facts + manifest + inject")
    runp.add_argument("--api", default=os.environ.get("SEED_API", "http://127.0.0.1:8000"))
    runp.add_argument("--tenant-id", required=True)
    runp.add_argument("--adapter-token", default=os.environ.get("ADAPTER_TOKEN"))
    runp.add_argument("--seed", type=int, default=1)
    runp.add_argument("--noise", type=int, default=260)
    runp.add_argument("--operational", type=int, default=12)
    runp.add_argument("--webscan-bursts", type=int, default=3)
    runp.add_argument("--webscan-size", type=int, default=18)
    runp.add_argument("--covered", type=int, default=8)
    runp.add_argument("--veto", type=int, default=6)
    runp.add_argument("--escalate", type=int, default=4)
    runp.add_argument("--goldens", type=int, default=18)
    runp.add_argument("--window-start", default=None)
    runp.add_argument("--window-end", default=None)
    runp.add_argument(
        "--tz",
        default=os.environ.get("SEED_TZ", "UTC"),
        help="viewer/demo timezone; default arrival window is this tz's "
        "local day so the fleet time-lapse sees arrivals and closes on "
        "one day (frontend windows fleet-day on the browser tz)",
    )
    runp.add_argument("--batch-size", type=int, default=400)
    runp.add_argument("--manifest", default=str(Path(__file__).parent / "manifest.json"))
    runp.add_argument("--dry-run", action="store_true")
    runp.set_defaults(func=cmd_run)

    ver = sub.add_parser("verify", help="print fleet-day/live counters")
    ver.add_argument("--api", default=os.environ.get("SEED_API", "http://127.0.0.1:8000"))
    ver.add_argument("--origin", default=None)
    ver.add_argument("--tenant-id", required=True)
    ver.add_argument("--admin-email", required=True)
    ver.add_argument("--admin-password", required=True)
    ver.set_defaults(func=cmd_verify)

    args = ap.parse_args()
    if args.cmd == "run" and not args.adapter_token and not args.dry_run:
        ap.error("--adapter-token (or ADAPTER_TOKEN env) required")
    args.func(args)


if __name__ == "__main__":
    main()
