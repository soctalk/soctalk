#!/usr/bin/env python3
"""Seed the L1 ``soctalk`` db with realistic multi-tenant SOC data.

Two modes, complementary:

1. **Direct-DB seed** (default; ``--db``): writes rows into
   ``tenants``, ``integration_configs``, ``branding_configs``,
   ``alerts``, ``investigations``, ``investigation_runs``, ``iocs``
   for fixture tenants ``acme-corp``, ``wayne-industries``,
   ``stark-defense``. Fast, deterministic, doesn't exercise the
   ingestion pipeline. Used to populate the MSSP cross-tenant
   widgets — needs ≥3 tenants to be meaningful.

2. **Wazuh replay** (``--wazuh``): POSTs a curated attack-chain of
   real Wazuh alerts into the labtenant indexer. The adapter forwards
   them naturally; the runs-worker triages each via Claude. Slower
   (~5 min for the chain to play out) and costs LLM tokens, but
   exercises the production ingestion path end-to-end and produces
   genuine LLM triage summaries.

3. ``--all`` (alias for ``--db --wazuh``): both, in order. The Wazuh
   alerts intentionally include the same C2 IP / domain that appear
   in the direct-DB tenants, so the ``Repeated IOCs`` panel jumps
   from 3-tenant overlap to 4-tenant overlap once the adapter
   forwards them.

Why direct-DB at all (instead of going through the API + Wazuh for
every tenant)?

- The MSSP wizard's ``POST /api/mssp/tenants`` flow is real, but it
  triggers the L1 → L2 helm-install cascade, which on lab clusters
  leaves the new tenant in ``pending`` state until L2 pods come up
  (10-15 min per tenant; sometimes longer). For a *demo dataset* we
  want tenants visible on the dashboard immediately, with their
  rows populated and their state already ``active``.
- ~30 alerts × 3 tenants × ~1 min adapter-to-LLM end-to-end is
  ~90 min of clock time and real token spend, just for the seed.
  Direct-DB cuts that to seconds.

So the direct-DB path is the demo population; the Wazuh-replay path
is the pipeline-validation overlay on top.

The widgets and what data this drives in each:

- ``Open investigations by tenant``  → rows in ``investigations`` with
  ``status='active'``, varied ``opened_at`` ages, varied severities.
- ``Stuck cases (Nh)``                → ``investigations`` whose latest
  ``investigation_runs`` activity is > N hours ago.
- ``Pending reviews by tenant``       → ``investigations`` with
  status=active AND an ``investigation_runs`` row carrying a
  non-NULL ``last_error`` (failed triage).
- ``Tenant health``                   → ``tenants.runtime->>'last_heartbeat'``
  variety: fresh, stale, never. ``state`` variety: active vs. degraded.
- ``Repeated IOCs across tenants``    → ``alerts.initial_iocs`` JSONB with
  shared ``{type, value}`` entries across ≥2 tenants in the last N days.

Story arc (so the data tells a story rather than reading like noise):

- acme-corp        — active ransomware (critical/high mix, stuck case,
                     stale adapter heartbeat). Shares C2 IP + hash with
                     other tenants.
- wayne-industries — phishing campaign last week (closed escalated,
                     auto-closed FP, one fresh medium). Fresh heartbeat.
                     Shares the C2 with acme.
- stark-defense    — ongoing brute force + recon. Two failed triage
                     runs (pending reviews). Adapter never heartbeated
                     (degraded). Shares the C2 hash + domain with
                     others.

Idempotent: re-running deletes the previously-seeded rows for our
fixture slugs first (best-effort). Real data on the cluster is
untouched.
"""

from __future__ import annotations

import argparse
import json
import secrets
import subprocess
import sys
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

NOW = datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# Cross-tenant IOCs — the ones that should appear in ≥2 tenants in the
# ``Repeated IOCs`` panel. Pick a small set with story-justifying
# attribution so the panel reads as a real cross-tenant pattern, not
# random overlap.

C2_IP   = "185.220.101.45"          # acme + wayne (Tor exit / known C2)
C2_HOST = "evil-c2.example.com"     # acme + wayne + stark
MALWARE_HASH = "6f5e4d3c2b1a09876543210fedcba9876543210fedcba9876543210fedcba"  # acme + stark


# ---------------------------------------------------------------------------
# Per-tenant story arcs.

@dataclass
class TenantSpec:
    slug: str
    display_name: str
    contact_email: str
    state: str = "active"
    heartbeat_age_minutes: int | None = 0    # None  → "never"; 0 → fresh
    config_extras: dict | None = None


TENANTS = [
    TenantSpec(
        slug="acme-corp",
        display_name="Acme Corp",
        contact_email="soc@acme.test",
        state="active",
        # 2h ago — adapter alive but slow. Triggers a yellow-zone
        # heartbeat reading without the tenant going degraded.
        heartbeat_age_minutes=120,
    ),
    TenantSpec(
        slug="wayne-industries",
        display_name="Wayne Industries",
        contact_email="ir@wayne.test",
        state="active",
        heartbeat_age_minutes=1,  # fresh
    ),
    TenantSpec(
        slug="stark-defense",
        display_name="Stark Defense",
        contact_email="cyber@stark.test",
        state="active",
        # Adapter never connected. tenants.runtime stays without a
        # last_heartbeat key → dashboard shows "never".
        heartbeat_age_minutes=None,
    ),
]


# ---------------------------------------------------------------------------
# Realistic Wazuh-shape alert templates. Each entry expands into rows
# in ``alerts`` (and a corresponding ``investigations`` row when
# ``open=True`` is set on the spec).
#
# Severity values use the project's ordinal scale (the chart's chip
# logic maps 0-15 → low/medium/high/critical):
#   ≥12 critical, ≥8 high, ≥5 medium, else low.

@dataclass
class AlertSpec:
    rule_id: str
    rule_desc: str             # human title; goes into investigation.title
    severity: int              # 0-15
    full_log: str
    asset_ids: list[str]
    initial_iocs: list[dict]   # [{"type": "ip"|"domain"|"sha256", "value": "..."}]
    age_hours: float           # alert age relative to NOW
    open: bool = True          # whether to spawn an investigation
    closed_status: str | None = None  # "closed"/"auto_closed"/"escalated" — terminal
    failed_run: bool = False   # triage run failed → drives Pending reviews
    stuck_hours: float | None = None  # if set, last run activity was > stuck_hours ago


ACME_ALERTS = [
    # Active ransomware story.
    AlertSpec(
        rule_id="92213",
        rule_desc="Possible ransomware activity: high rate of file rename + encryption",
        severity=14,
        full_log=(
            "agent='acme-fileserver-01' event='6 files modified in 2s in C:\\Users\\* "
            "with .locked extension' parent_process='powershell.exe -encoded ...'"
        ),
        asset_ids=["acme-fileserver-01", "10.40.5.12"],
        initial_iocs=[
            {"type": "sha256", "value": MALWARE_HASH},
            {"type": "ip", "value": C2_IP},
        ],
        age_hours=2.5,
    ),
    AlertSpec(
        rule_id="100200",
        rule_desc="Suspicious PowerShell: encoded command + outbound C2 connection",
        severity=13,
        full_log=(
            "EventID 4104: powershell.exe -nop -w hidden -enc <base64>... "
            f"connecting to {C2_IP}:443 from C:\\Users\\jdoe\\AppData\\Local\\Temp\\svchost.exe"
        ),
        asset_ids=["acme-workstation-jdoe", "10.40.5.55"],
        initial_iocs=[
            {"type": "ip", "value": C2_IP},
            {"type": "domain", "value": C2_HOST},
        ],
        age_hours=4,
    ),
    AlertSpec(
        rule_id="40111",
        rule_desc="Multiple authentication failures: possible reconnaissance",
        severity=8,
        full_log="acme-vpn-gw: 12 failed PSK auths from 203.0.113.42 in 60s",
        asset_ids=["acme-vpn-gw", "203.0.113.42"],
        initial_iocs=[{"type": "ip", "value": "203.0.113.42"}],
        age_hours=6,
    ),
    AlertSpec(
        rule_id="61603",
        rule_desc="Lateral movement: SMB share enumeration from non-admin host",
        severity=10,
        full_log="acme-fileserver-01: 47 SMB OPEN ops from 10.40.5.55 in 30s",
        asset_ids=["acme-fileserver-01", "10.40.5.55"],
        initial_iocs=[{"type": "ip", "value": "10.40.5.55"}],
        age_hours=3,
        # No new run activity for hours → drives Stuck cases.
        stuck_hours=10,
    ),
    AlertSpec(
        rule_id="86004",
        rule_desc="Suspicious DNS query: high-entropy domain (likely DGA)",
        severity=7,
        full_log=f"acme-dns-01: query for {C2_HOST} from 10.40.5.55",
        asset_ids=["acme-dns-01"],
        initial_iocs=[{"type": "domain", "value": C2_HOST}],
        age_hours=5,
        failed_run=True,  # triage hit a tool-call error → Pending review
    ),
]

WAYNE_ALERTS = [
    # Phishing campaign — mostly resolved.
    AlertSpec(
        rule_id="87102",
        rule_desc="Phishing email: suspicious attachment from external sender",
        severity=11,
        full_log=(
            "wayne-mailgw: subject='[URGENT] Invoice review' from='ceo@wayne-corp.co' "
            "attachment='Invoice-2026-04.html' contained obfuscated JS calling out to "
            f"{C2_HOST}"
        ),
        asset_ids=["wayne-exec-01", "wayne-exec-02", "wayne-exec-03"],
        initial_iocs=[
            {"type": "domain", "value": C2_HOST},
            {"type": "ip", "value": C2_IP},
        ],
        age_hours=72,
        closed_status="escalated",
    ),
    AlertSpec(
        rule_id="100200",
        rule_desc="Phishing follow-on: PowerShell execution after attachment open",
        severity=12,
        full_log=(
            "wayne-exec-02: child of OUTLOOK.EXE → powershell.exe -enc <base64> "
            f"connecting to {C2_IP}"
        ),
        asset_ids=["wayne-exec-02"],
        initial_iocs=[{"type": "ip", "value": C2_IP}],
        age_hours=70,
        closed_status="escalated",
    ),
    AlertSpec(
        rule_id="86006",
        rule_desc="DNS lookup for known phishing domain",
        severity=5,
        full_log=f"wayne-dns: query for {C2_HOST} from wayne-exec-04",
        asset_ids=["wayne-exec-04"],
        initial_iocs=[{"type": "domain", "value": C2_HOST}],
        age_hours=68,
        closed_status="auto_closed",  # AI verdict: malicious-but-blocked, no action
    ),
    AlertSpec(
        rule_id="60106",
        rule_desc="Office macro spawned cmd.exe — possible delivery payload",
        severity=9,
        full_log="wayne-exec-08: WINWORD.EXE → cmd.exe /c bitsadmin /transfer ...",
        asset_ids=["wayne-exec-08"],
        initial_iocs=[],
        age_hours=12,
    ),
]

STARK_ALERTS = [
    # Brute force + recon, with a couple of failed triages.
    AlertSpec(
        rule_id="5712",
        rule_desc="SSH brute force: 200 failed logins from single source",
        severity=8,
        full_log="stark-bastion-01: sshd: 200 failed pubkey+passwd from 198.51.100.77",
        asset_ids=["stark-bastion-01"],
        initial_iocs=[{"type": "ip", "value": "198.51.100.77"}],
        age_hours=1,
    ),
    AlertSpec(
        rule_id="5712",
        rule_desc="SSH brute force: 89 failed logins from related subnet",
        severity=7,
        full_log="stark-bastion-01: sshd: 89 failed from 198.51.100.78",
        asset_ids=["stark-bastion-01"],
        initial_iocs=[{"type": "ip", "value": "198.51.100.78"}],
        age_hours=1.5,
    ),
    AlertSpec(
        rule_id="5712",
        rule_desc="SSH brute force: 56 failed logins from third related host",
        severity=6,
        full_log="stark-bastion-02: sshd: 56 failed from 198.51.100.79",
        asset_ids=["stark-bastion-02"],
        initial_iocs=[{"type": "ip", "value": "198.51.100.79"}],
        age_hours=2,
        failed_run=True,
    ),
    AlertSpec(
        rule_id="40111",
        rule_desc="VPN reconnaissance: portal-config probe",
        severity=4,
        full_log="stark-vpn-gw: GET /remote/login from 198.51.100.77",
        asset_ids=["stark-vpn-gw"],
        initial_iocs=[{"type": "ip", "value": "198.51.100.77"}],
        age_hours=3,
    ),
    AlertSpec(
        rule_id="100401",
        rule_desc="Suspicious binary with known IOC hash dropped",
        severity=11,
        full_log=(
            f"stark-jumpbox-01: file write /tmp/.systemd-run.bin sha256={MALWARE_HASH}"
        ),
        asset_ids=["stark-jumpbox-01"],
        initial_iocs=[
            {"type": "sha256", "value": MALWARE_HASH},
            {"type": "domain", "value": C2_HOST},
        ],
        age_hours=8,
        # Hasn't moved in over a day — fills Stuck cases panel.
        stuck_hours=30,
        failed_run=True,
    ),
]


SPECS: dict[str, list[AlertSpec]] = {
    "acme-corp":        ACME_ALERTS,
    "wayne-industries": WAYNE_ALERTS,
    "stark-defense":    STARK_ALERTS,
}


# ---------------------------------------------------------------------------
# SQL builders.

def q(s: str | None) -> str:
    """Quote a SQL string literal, NULL-safe. NEVER pass user input."""
    if s is None:
        return "NULL"
    return "'" + s.replace("'", "''") + "'"


def jsonl(d) -> str:
    """JSON-encoded literal for a JSONB column."""
    return q(json.dumps(d, separators=(",", ":")))


def ts(dt: datetime) -> str:
    return q(dt.isoformat())


def severity_label(sev: int) -> str:
    if sev >= 12: return "critical"
    if sev >= 8:  return "high"
    if sev >= 5:  return "medium"
    return "low"


def build_seed_sql(org_id: str) -> str:
    """Return one SQL transaction that rewrites the demo fixture rows."""
    parts: list[str] = []

    parts.append("BEGIN;")

    # Wipe prior runs of THIS seed (idempotency). Identify by slug,
    # cascade through all FKs we touch. Real tenants are untouched.
    slugs = [t.slug for t in TENANTS]
    slug_list = ", ".join(q(s) for s in slugs)
    parts.append(
        f"""
DELETE FROM investigation_runs    WHERE tenant_id IN (SELECT id FROM tenants WHERE slug IN ({slug_list}));
DELETE FROM pending_reviews       WHERE tenant_id IN (SELECT id FROM tenants WHERE slug IN ({slug_list}));
DELETE FROM iocs                  WHERE tenant_id IN (SELECT id FROM tenants WHERE slug IN ({slug_list}));
DELETE FROM alerts                WHERE tenant_id IN (SELECT id FROM tenants WHERE slug IN ({slug_list}));
DELETE FROM investigations        WHERE tenant_id IN (SELECT id FROM tenants WHERE slug IN ({slug_list}));
DELETE FROM integration_configs   WHERE tenant_id IN (SELECT id FROM tenants WHERE slug IN ({slug_list}));
DELETE FROM branding_configs      WHERE tenant_id IN (SELECT id FROM tenants WHERE slug IN ({slug_list}));
DELETE FROM tenants               WHERE slug IN ({slug_list});
"""
    )

    # Per-tenant rows.
    short_id_seq = 9000  # well above any real investigations short_id range
    for spec in TENANTS:
        tid = str(uuid.uuid4())
        runtime: dict = {
            "health": "ok" if spec.heartbeat_age_minutes is not None else "unknown",
            "version": "0.3.0",
            "metrics_snapshot": {},
        }
        if spec.heartbeat_age_minutes is not None:
            hb = NOW - timedelta(minutes=spec.heartbeat_age_minutes)
            runtime["last_heartbeat"] = hb.isoformat()
        config = {"contact_email": spec.contact_email}

        parts.append(
            f"""
INSERT INTO tenants (id, slug, display_name, state, organization_id, profile, created_at, state_changed_at, config, runtime)
VALUES ({q(tid)}, {q(spec.slug)}, {q(spec.display_name)}, {q(spec.state)},
        {q(org_id)}, 'poc', NOW() - INTERVAL '14 days', NOW() - INTERVAL '14 days',
        {jsonl(config)}::jsonb, {jsonl(runtime)}::jsonb);
INSERT INTO integration_configs (id, tenant_id) VALUES ({q(str(uuid.uuid4()))}, {q(tid)});
INSERT INTO branding_configs (id, tenant_id, app_name) VALUES ({q(str(uuid.uuid4()))}, {q(tid)}, {q(spec.display_name + ' SOC')});
"""
        )

        # Alerts + their investigations.
        for spec_alert in SPECS[spec.slug]:
            event_at = NOW - timedelta(hours=spec_alert.age_hours)
            alert_id = str(uuid.uuid4())
            inv_id = str(uuid.uuid4())
            short_id_seq += 1
            short_id = f"{NOW.year}-{short_id_seq:04d}"
            sig = secrets.token_hex(32)

            # Investigation row.
            if spec_alert.closed_status == "escalated":
                inv_status = "escalated"
                closed_at = event_at + timedelta(hours=2)
                close_reason = "Escalated to TheHive: confirmed malicious"
            elif spec_alert.closed_status == "auto_closed":
                inv_status = "auto_closed"
                closed_at = event_at + timedelta(hours=1)
                close_reason = "AI verdict: blocked at gateway, no impact"
            else:
                inv_status = "active"
                closed_at = None
                close_reason = None

            opened_at = event_at + timedelta(seconds=10)
            updated_at = NOW - timedelta(hours=spec_alert.stuck_hours or 0.1)

            parts.append(
                f"""
INSERT INTO investigations (id, tenant_id, short_id, title, status, severity,
                            opened_at, closed_at, close_reason, reopen_count,
                            visibility, created_at, updated_at)
VALUES ({q(inv_id)}, {q(tid)}, {q(short_id)}, {q(spec_alert.rule_desc)},
        {q(inv_status)}, {spec_alert.severity},
        {ts(opened_at)}, {ts(closed_at) if closed_at else 'NULL'},
        {q(close_reason)}, 0, 'mssp_only',
        {ts(opened_at)}, {ts(updated_at)});
"""
            )

            parts.append(
                f"""
INSERT INTO alerts (id, tenant_id, source, rule_id, severity, signature,
                    first_event_at, last_event_at, event_count,
                    source_event_ids, asset_ids, initial_iocs,
                    ai_assessment, ai_confidence, status, investigation_id,
                    visibility, created_at)
VALUES ({q(alert_id)}, {q(tid)}, 'wazuh', {q(spec_alert.rule_id)},
        {spec_alert.severity}, {q(sig)},
        {ts(event_at)}, {ts(event_at)}, 1,
        {jsonl([f'evt-{spec_alert.rule_id}-{secrets.token_hex(4)}'])}::jsonb,
        {jsonl(spec_alert.asset_ids)}::jsonb,
        {jsonl(spec_alert.initial_iocs)}::jsonb,
        {q(spec_alert.full_log[:512])},
        0.85, 'promoted', {q(inv_id)}, 'mssp_only',
        {ts(event_at + timedelta(seconds=5))});
"""
            )

            # IOC rows for the cross-tenant panel's "first/last seen"
            # column — separate from alerts.initial_iocs which drives
            # the aggregation. Both are needed for full UI coverage.
            for ioc in spec_alert.initial_iocs:
                parts.append(
                    f"""
INSERT INTO iocs (id, tenant_id, type, value, fingerprint, tlp, pap,
                  first_seen, last_seen, external_context, visibility)
VALUES ({q(str(uuid.uuid4()))}, {q(tid)}, {q(ioc['type'])}, {q(ioc['value'])},
        {q(secrets.token_hex(16))}, 'amber', 'amber',
        {ts(event_at)}, {ts(event_at)}, '{{}}'::jsonb, 'mssp_only')
ON CONFLICT DO NOTHING;
"""
                )

            # investigation_runs row(s) — drive Stuck and Pending widgets.
            run_id = str(uuid.uuid4())
            run_started = opened_at + timedelta(seconds=15)
            run_ended_or_null: str
            run_error: str | None = None
            if spec_alert.failed_run:
                run_status = "failed"
                run_error = "tool_call_failed: virustotal lookup timed out after 30s"
                run_ended_or_null = ts(run_started + timedelta(seconds=12))
                tokens = 0
                dollars = 0.0
            elif spec_alert.closed_status:
                run_status = "completed"
                run_ended_or_null = ts(run_started + timedelta(seconds=45))
                tokens = 4500
                dollars = 0.012
            else:
                run_status = "completed"
                # For stuck cases, push the run completion BACK by stuck_hours
                # so the dashboard's last-activity computation flags it.
                ended_age = spec_alert.stuck_hours if spec_alert.stuck_hours else 0.05
                run_ended = NOW - timedelta(hours=ended_age)
                run_started = run_ended - timedelta(seconds=45)
                run_ended_or_null = ts(run_ended)
                tokens = 5200
                dollars = 0.015

            parts.append(
                f"""
INSERT INTO investigation_runs (id, tenant_id, investigation_id, status,
                                tokens_used, tokens_budget, dollars_used, dollars_budget,
                                tool_calls_used, tool_calls_budget,
                                started_at, ended_at, last_error)
VALUES ({q(run_id)}, {q(tid)}, {q(inv_id)}, {q(run_status)},
        {tokens}, 100000, {dollars}, 5.0,
        3, 50,
        {ts(run_started)}, {run_ended_or_null}, {q(run_error)});
"""
            )

    parts.append("COMMIT;")
    return "\n".join(parts)


# ---------------------------------------------------------------------------
# Wazuh replay — real-pipeline validation.
#
# Curated attack chain that lands in the labtenant Wazuh indexer.
# All alerts have ``rule.level >= 10`` so they pass the adapter's
# ``minSeverity`` filter and get forwarded to L1. Each alert produces
# an investigation that the runs-worker triages via the configured
# LLM (Anthropic Claude, in this lab).
#
# IOCs deliberately overlap the direct-DB tenants' so the
# ``Repeated IOCs across tenants`` panel jumps from 3-tenant overlap
# to 4-tenant overlap once the adapter forwards these.

LABTENANT_ATTACK_CHAIN = [
    {
        "rule_id": "87102",
        "level": 11,
        "description": "Phishing email opened: macro-enabled attachment from external sender",
        "groups": ["windows", "phishing", "attack.t1566.001"],
        "agent": {"id": "010", "name": "labtenant-exec-01"},
        "full_log": (
            "OUTLOOK.EXE → opened attachment 'Q1-Renewal-Quote.docm' "
            "from external sender 'finance@evil-c2.example.com'"
        ),
        "iocs": [{"type": "domain", "value": C2_HOST}],
    },
    {
        "rule_id": "92214",
        "level": 13,
        "description": "Macro spawned PowerShell with encoded payload",
        "groups": ["windows", "powershell", "attack.t1059.001"],
        "agent": {"id": "010", "name": "labtenant-exec-01"},
        "full_log": (
            "EventID 4104: WINWORD.EXE → powershell.exe -nop -w hidden -enc "
            "JABjAGwAaQBlAG4AdAAgAD0AIA... (decoded: download from evil-c2.example.com/payload.bin)"
        ),
        "iocs": [
            {"type": "domain", "value": C2_HOST},
        ],
    },
    {
        "rule_id": "61603",
        "level": 12,
        "description": "Scheduled task created for persistence (suspicious binary path)",
        "groups": ["windows", "persistence", "attack.t1053.005"],
        "agent": {"id": "010", "name": "labtenant-exec-01"},
        "full_log": (
            "schtasks.exe /create /tn 'WindowsUpdateCheck' /tr "
            "'C:\\Users\\admin\\AppData\\Local\\Temp\\svchost.exe' /sc onlogon"
        ),
        "iocs": [{"type": "sha256", "value": MALWARE_HASH}],
    },
    {
        "rule_id": "100200",
        "level": 13,
        "description": "Outbound C2 beacon: connection to known malicious infrastructure",
        "groups": ["network", "attack.t1071.001"],
        "agent": {"id": "010", "name": "labtenant-exec-01"},
        "full_log": (
            f"netconn: 10.50.5.55 → {C2_IP}:443 process=svchost.exe "
            "(unusual parent: AppData\\Local\\Temp)"
        ),
        "iocs": [
            {"type": "ip", "value": C2_IP},
            {"type": "domain", "value": C2_HOST},
        ],
    },
    {
        "rule_id": "60106",
        "level": 11,
        "description": "Reconnaissance: net.exe / nltest.exe enumeration burst",
        "groups": ["windows", "discovery", "attack.t1087", "attack.t1482"],
        "agent": {"id": "010", "name": "labtenant-exec-01"},
        "full_log": (
            "net.exe group 'Domain Admins' /domain ; nltest /dclist:CORP ; "
            "net.exe view /domain — all within 8 seconds"
        ),
        "iocs": [],
    },
    {
        "rule_id": "100401",
        "level": 14,
        "description": "Large outbound transfer to suspicious domain — possible exfiltration",
        "groups": ["network", "attack.t1041"],
        "agent": {"id": "010", "name": "labtenant-exec-01"},
        "full_log": (
            f"netconn: 10.50.5.55 → {C2_HOST} (resolved {C2_IP}) "
            "POST /upload 847MB over 90s (uncompressed archive)"
        ),
        "iocs": [
            {"type": "domain", "value": C2_HOST},
            {"type": "ip", "value": C2_IP},
        ],
    },
]


def inject_wazuh_alerts(*, ctx: str) -> int:
    """POST the attack chain into labtenant's Wazuh indexer.

    Each alert is sent with ``refresh=true`` so it's queryable
    immediately by the adapter on its next 15s poll. The adapter
    only forwards ``rule.level >= 10`` (per its env), so all entries
    in :data:`LABTENANT_ATTACK_CHAIN` qualify by construction.

    Returns the number of alerts successfully POSTed (so a partial
    failure surfaces). Failures don't raise — if Wazuh is down, we
    print and move on; the direct-DB seed still leaves the dashboard
    populated.
    """
    import base64

    ns = "tenant-labtenant"
    indexer_pod = "wazuh-labtenant-wazuh-indexer-0"
    creds_secret = "wazuh-labtenant-wazuh-creds"

    # Resolve indexer creds.
    cmd = [
        "kubectl", "--context", ctx, "-n", ns,
        "get", "secret", creds_secret, "-o", "jsonpath={.data}",
    ]
    proc = subprocess.run(cmd, capture_output=True)
    if proc.returncode != 0:
        sys.stderr.write(
            f"  wazuh: indexer creds secret '{creds_secret}' unreadable in {ns}; "
            f"skipping (is labtenant up?)\n"
        )
        return 0
    data = json.loads(proc.stdout)
    user = base64.b64decode(data["INDEXER_USERNAME"]).decode()
    password = base64.b64decode(data["INDEXER_PASSWORD"]).decode()

    today = NOW.strftime("%Y.%m.%d")
    index = f"wazuh-alerts-4.x-{today}"

    # Stagger timestamps over the last hour so the dashboard's
    # "oldest_opened_at" column shows variety. Order: oldest first
    # (matches narrative — phishing came in first, exfil last).
    base_ts = NOW - timedelta(minutes=58)
    interval = timedelta(minutes=10)

    posted = 0
    for i, spec in enumerate(LABTENANT_ATTACK_CHAIN):
        event_at = base_ts + i * interval
        doc = {
            "@timestamp": event_at.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
            "timestamp": event_at.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
            "id": f"easy-poc-chain-{i}-{secrets.token_hex(4)}",
            "rule": {
                "id": spec["rule_id"],
                "level": spec["level"],
                "description": spec["description"],
                "groups": spec["groups"],
            },
            "agent": spec["agent"],
            "manager": {"name": "wazuh-labtenant-wazuh-manager-0"},
            "full_log": spec["full_log"],
            "decoder": {"name": "windows-eventchannel"},
            "location": "Microsoft-Windows-Sysmon/Operational",
            # The adapter's _extract_iocs() hunts patterns in the
            # rule_desc + full_log strings, so the IOCs are already
            # encoded in the text. We don't need to mirror them as
            # structured fields for the L1 to pick them up — but
            # adding them here keeps the doc rich for any other
            # downstream consumers (Wazuh dashboard, Kibana, etc.).
            "data": {"iocs_seed": spec["iocs"]},
        }

        url = f"https://localhost:9200/{index}/_doc?refresh=true"
        # Build curl inside the indexer pod so TLS verification works
        # against the indexer's own cert (which only resolves to its
        # in-cluster DNS name, not 'localhost' at the cert level — but
        # we're using -k anyway).
        curl_cmd = [
            "kubectl", "--context", ctx, "-n", ns,
            "exec", "-i", indexer_pod, "--",
            "curl", "-sk", "-u", f"{user}:{password}",
            "-X", "POST", url, "-H", "Content-Type: application/json",
            "-d", json.dumps(doc),
        ]
        proc = subprocess.run(curl_cmd, capture_output=True)
        if proc.returncode != 0:
            sys.stderr.write(
                f"  wazuh: alert {i+1}/{len(LABTENANT_ATTACK_CHAIN)} POST failed: "
                f"{proc.stderr.decode()[:200]}\n"
            )
            continue
        # Indexer returns JSON with "result":"created"; sanity-check.
        try:
            resp = json.loads(proc.stdout)
            if resp.get("result") != "created":
                sys.stderr.write(
                    f"  wazuh: unexpected indexer response for alert {i+1}: {resp}\n"
                )
                continue
        except Exception:
            sys.stderr.write(f"  wazuh: alert {i+1} indexer returned non-JSON\n")
            continue
        posted += 1

    return posted


# ---------------------------------------------------------------------------
# Execution.

def kubectl_psql(sql: str, *, ctx: str, ns: str, pod: str, db: str, user: str, password: str) -> None:
    """Pipe ``sql`` to psql inside the postgres pod via kubectl exec."""
    cmd = [
        "kubectl", "--context", ctx, "-n", ns,
        "exec", "-i", pod, "--",
        "env", f"PGPASSWORD={password}",
        "psql", "-U", user, "-d", db, "-v", "ON_ERROR_STOP=1",
    ]
    proc = subprocess.run(cmd, input=sql.encode(), capture_output=True)
    if proc.returncode != 0:
        sys.stderr.write(proc.stderr.decode())
        sys.exit(proc.returncode)
    out = proc.stdout.decode().strip()
    if out:
        print(out)


def get_org_id(ctx: str, ns: str, pod: str, db: str, user: str, password: str) -> str:
    """Pick the FIRST organization to own these tenants. The L1 has
    exactly one organization (the MSSP install itself); we don't have
    to disambiguate — but doing the lookup keeps the script portable
    across re-installs."""
    cmd = [
        "kubectl", "--context", ctx, "-n", ns,
        "exec", "-i", pod, "--",
        "env", f"PGPASSWORD={password}",
        "psql", "-U", user, "-d", db, "-tA", "-c",
        "SELECT id FROM organizations ORDER BY created_at LIMIT 1;",
    ]
    proc = subprocess.run(cmd, capture_output=True)
    if proc.returncode != 0:
        sys.stderr.write(proc.stderr.decode())
        sys.exit(proc.returncode)
    org_id = proc.stdout.decode().strip()
    if not org_id:
        sys.exit("no organization found in L1 db — install incomplete?")
    return org_id


def main() -> None:
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("--context", default="k3s-lab", help="kubectl context")
    ap.add_argument("--namespace", default="soctalk-system", help="L1 install namespace")
    ap.add_argument("--pod", default="soctalk-system-postgres-0", help="postgres pod name")
    ap.add_argument("--db-name", default="soctalk", dest="dbname")
    ap.add_argument("--user", default="soctalk_admin")
    ap.add_argument(
        "--password-from-secret",
        default="soctalk-system-postgres-admin-creds",
        help="K8s Secret in --namespace holding postgres admin creds (data.password)",
    )

    # Mode selection. Default behavior: run the direct-DB seed only.
    # ``--all`` fans out into both DB + Wazuh replay; ``--wazuh`` runs
    # only the replay (skipping the DB step is useful when the fixture
    # tenants are already in place from a prior run and you only want
    # to validate the ingestion pipeline).
    ap.add_argument(
        "--db", action="store_true", dest="run_db",
        help="Run the direct-DB seed for fixture tenants (default if no mode flag)",
    )
    ap.add_argument(
        "--wazuh", action="store_true", dest="run_wazuh",
        help="POST a curated attack chain into labtenant's Wazuh indexer "
             "(real-pipeline path; ~5 min, costs LLM tokens)",
    )
    ap.add_argument(
        "--all", action="store_true",
        help="Shortcut for --db --wazuh",
    )

    ap.add_argument("--dry-run", action="store_true", help="print SQL, don't execute")
    args = ap.parse_args()

    if args.all:
        args.run_db = True
        args.run_wazuh = True
    if not (args.run_db or args.run_wazuh):
        # No mode flag at all → preserve historical default (db only).
        args.run_db = True

    if args.dry_run:
        sql = build_seed_sql(org_id="00000000-0000-0000-0000-000000000000")
        print(sql)
        return

    if args.run_db:
        # Resolve postgres password from the K8s secret (don't pass it
        # on the CLI — it'd land in shell history).
        secret_cmd = [
            "kubectl", "--context", args.context, "-n", args.namespace,
            "get", "secret", args.password_from_secret,
            "-o", "jsonpath={.data.password}",
        ]
        secret_proc = subprocess.run(secret_cmd, capture_output=True)
        if secret_proc.returncode != 0:
            sys.stderr.write(secret_proc.stderr.decode())
            sys.exit(1)
        import base64
        password = base64.b64decode(secret_proc.stdout).decode()

        org_id = get_org_id(
            ctx=args.context, ns=args.namespace, pod=args.pod,
            db=args.dbname, user=args.user, password=password,
        )
        print(f"  db: org {org_id}")

        sql = build_seed_sql(org_id=org_id)
        kubectl_psql(
            sql,
            ctx=args.context, ns=args.namespace, pod=args.pod,
            db=args.dbname, user=args.user, password=password,
        )
        print("  db: seeded fixture tenants.")

    if args.run_wazuh:
        print(f"  wazuh: posting {len(LABTENANT_ATTACK_CHAIN)} alerts to labtenant indexer...")
        n = inject_wazuh_alerts(ctx=args.context)
        print(f"  wazuh: {n}/{len(LABTENANT_ATTACK_CHAIN)} alerts indexed.")
        if n > 0:
            print(
                "  wazuh: adapter polls every 15s; runs-worker triages each "
                "alert via Claude (~45s). Total play-out: ~5 min before all\n"
                "         investigations land in /investigations with LLM-generated summaries."
            )


if __name__ == "__main__":
    main()
