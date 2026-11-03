"""Demo-seed corpus (issue #72): authored families + goldens-derived cases.

Every template is authored to the PRODUCT'S ACTUAL GATES (verified against
source, see the round-4 review constraints in the design history):

- assess(): sev>=8 real, 5-7 unclear, 3-4 likely_fp, <3 high_conf_fp
  UNLESS MITRE present (then unclear). Rules-band ingest auto-close fires
  only for high_conf_fp (conf 0.95 >= default threshold 0.90), no IOCs.
- Everything not closed/merged PROMOTES — there is no limbo band.
- Operational close: rule 202 with agent_flooding/agent_buffer groups, no
  MITRE/IOCs, non-critical severity → graph closes deterministically, no
  provider call.
- Live authz binding: activity.action = rule_id, subject = user entity,
  target = host entity — facts are authored in THAT vocabulary.

All prose in this file was written offline, never by runtime inference.
"""

from __future__ import annotations

import json
import random
from dataclasses import dataclass, field
from pathlib import Path

CORPUS_DIR = Path(__file__).parent / "corpus"

# A realistic fleet: enough hosts that same-rule noise events rarely collide
# on (rule_id, asset, 5-min bucket) — otherwise the adapter coalesces/reopens
# them into a handful of churning investigations instead of distinct closes.
_ROLES = ["web", "app", "api", "db", "cache", "queue", "build", "ci", "bastion", "edge"]
HOSTS_NOISE = [f"{r}-{i:02d}" for r in _ROLES for i in range(1, 7)]  # 60 hosts
USERS_NOISE = [
    "deploy", "svc-backup", "ansible", "jenkins", "www-data", "monitor",
    "gitlab-runner", "prometheus", "svc-etl", "packer", "terraform", "cron",
]
EXT_IPS = ["203.0.113.40", "198.51.100.23", "203.0.113.77", "192.0.2.146", "198.51.100.9"]
INT_IPS = ["10.20.8.14", "10.20.9.3", "172.16.4.9", "10.20.11.25"]


@dataclass
class EventTemplate:
    family: str
    rule_id: str
    severity: int
    title: str
    description: str
    rule_groups: list[str] = field(default_factory=list)
    mitre: dict | None = None
    entities: list[dict] = field(default_factory=list)
    assets: list[str] = field(default_factory=list)
    iocs: list[dict] = field(default_factory=list)
    template_hash: str | None = None
    # For promotable families: the scripted-provider play to register.
    script: dict | None = None


# ---------------------------------------------------------------------------
# Deterministic bulk: rules-band ingest closes (sev <= 2, MITRE-free)
# ---------------------------------------------------------------------------


# A realistic spread of benign, low-severity Wazuh rule IDs. Diversity here
# governs how many DISTINCT closed investigations the day produces: reopen
# matches any-of (asset|ioc|rule) within the 30d window, so recurrence of a
# rule reopens its first close (real product behavior — the flight recorder
# shows the REOPENED beat). More rules → more distinct closes, fewer reopens.
def noise_events(rng: random.Random, n: int) -> list[EventTemplate]:
    """High-volume benign noise that the ingest plane closes itself."""
    shapes = [
        ("5501", "PAM: login session opened", "pam session opened for user {user} on {host}", ["pam", "syslog"]),
        ("5502", "PAM: login session closed", "pam session closed for user {user} on {host}", ["pam", "syslog"]),
        ("2902", "New dpkg (Debian package) installed", "package {pkg} installed on {host}", ["syslog", "dpkg"]),
        ("2903", "Dpkg (Debian package) removed", "package {pkg} removed on {host}", ["syslog", "dpkg"]),
        ("530", "OSSEC process list checksum changed", "periodic process inventory delta on {host}", ["ossec"]),
        ("531", "Disk usage checked", "disk usage report collected on {host}", ["ossec"]),
        ("5901", "New group added to the system", "group ci-runners refreshed on {host}", ["syslog"]),
        ("5902", "New user added to the system", "service account {user} provisioned on {host}", ["syslog"]),
        ("2501", "Syslog daemon restarted", "rsyslog reloaded on {host}", ["syslog"]),
        ("1002", "Unknown problem somewhere in the system", "low-signal anomaly on {host}", ["syslog"]),
        ("510", "Host-based anomaly detection (rootcheck)", "rootcheck scan completed on {host}", ["ossec", "rootcheck"]),
        ("591", "Log file rotated", "logrotate ran for {pkg} on {host}", ["syslog"]),
        ("2932", "Yum package updated", "package {pkg} updated on {host}", ["syslog", "yum"]),
        ("5301", "User authentication failure (single)", "one failed password for {user} on {host}", ["pam", "syslog"]),
        ("5715", "sshd authentication success", "accepted key for {user} on {host}", ["sshd", "syslog"]),
        ("2503", "SSHD server restarted", "sshd reloaded on {host}", ["sshd", "syslog"]),
        ("580", "FIM directory scan completed", "syscheck baseline scan finished on {host}", ["syscheck"]),
        ("533", "Listened ports status changed", "open-port inventory delta on {host}", ["ossec"]),
        ("5401", "sudo session opened for cron", "cron opened a sudo session on {host}", ["syslog", "sudo"]),
        ("2951", "APT cache cleaned", "apt autoclean ran on {host}", ["syslog"]),
    ]
    pkgs = ["curl", "openssl", "libssl3", "tzdata", "ca-certificates", "nginx", "python3", "containerd"]
    out = []
    for i in range(n):
        rid, title, desc, groups = shapes[rng.randrange(len(shapes))]
        host = HOSTS_NOISE[rng.randrange(len(HOSTS_NOISE))]
        user = USERS_NOISE[rng.randrange(len(USERS_NOISE))]
        out.append(
            EventTemplate(
                family="noise",
                rule_id=rid,
                severity=rng.choice([0, 1, 2]),
                title=title,
                description=desc.format(user=user, host=host, pkg=rng.choice(pkgs)),
                rule_groups=groups,
                assets=[host],
                template_hash=f"tpl-{rid}",
            )
        )
    return out


def operational_events(rng: random.Random, n: int) -> list[EventTemplate]:
    """Agent-health alerts the built-in operational policy closes in-graph
    (rule 202, agent_flooding/agent_buffer, no MITRE/IOCs)."""
    out = []
    for i in range(n):
        host = f"edge-agent-{rng.randrange(1, 30):02d}"
        flavor = rng.choice(
            [
                ("Agent event queue is flooded", "agent_flooding"),
                ("Agent buffer is full", "agent_buffer"),
            ]
        )
        out.append(
            EventTemplate(
                family="operational",
                rule_id="202",
                severity=rng.choice([3, 4, 5]),
                title=f"{flavor[0]} on {host}",
                description=f"wazuh agent on {host}: {flavor[0].lower()}; events may be dropped until the queue drains",
                rule_groups=["wazuh", flavor[1]],
                assets=[host],
                template_hash="tpl-202",
            )
        )
    return out


def webscan_events(rng: random.Random, n: int) -> list[EventTemplate]:
    """Web scanner bursts. Low severity, MITRE-free → ingest close; each
    burst shares an external source IP and a short time span (the seeder
    schedules the burst)."""
    out = []
    ip = EXT_IPS[rng.randrange(len(EXT_IPS))]
    for i in range(n):
        host = rng.choice(["web-01", "web-02"])
        out.append(
            EventTemplate(
                family="webscan",
                rule_id="31101",
                severity=rng.choice([1, 2]),
                title=f"Web server 400 error code ({host})",
                description=f"multiple 4xx responses to probing requests from {ip} against {host}",
                rule_groups=["web", "accesslog"],
                assets=[host],
                entities=[{"type": "ip", "value": ip, "role": "src"}],
                template_hash="tpl-31101",
            )
        )
    return out


# ---------------------------------------------------------------------------
# Promotable, scripted families (unique host token routes the provider)
# ---------------------------------------------------------------------------


def _tok(rng: random.Random) -> str:
    return "".join(rng.choice("abcdefghjkmnpqrstuvwxyz23456789") for _ in range(4))


def scripted_families(
    rng: random.Random, n_covered: int, n_veto: int, n_escalate: int
) -> list[EventTemplate]:
    """The reasoning tail. Three sub-families driven by REAL guard behavior
    against the bootstrap fact set (see seed.py BOOTSTRAP_FACTS):

    - covered:  activity matches an active grant → verdict close, guard pass.
    - veto:     account-track facts exist but none cover → engine says
                contradicted; the scripted verdict closes anyway (the model
                'trusts the pattern') and the REAL guard flips it.
    - escalate: compromised-actor shape; verdict escalates itself.
    """
    out: list[EventTemplate] = []

    for _ in range(n_covered):
        t = _tok(rng)
        host, user, rid = f"app-{t}", "svc-backup", "5715"
        out.append(
            EventTemplate(
                family="covered",
                rule_id=rid,
                severity=rng.choice([5, 6]),
                title=f"SSH authentication success followed by remote command on {host}",
                description=f"sshd session for {user} on {host} ran a remote command shortly after login",
                rule_groups=["sshd", "authentication_success"],
                mitre={
                    "ids": ["T1021.004"],
                    "tactics": ["Lateral Movement"],
                    "techniques": ["Remote Services: SSH"],
                },
                entities=[
                    {"type": "host", "value": host, "role": "target"},
                    {"type": "user", "value": user, "role": "actor"},
                    {"type": "ip", "value": rng.choice(INT_IPS), "role": "src"},
                ],
                template_hash="tpl-5715",
                script={
                    "key": host,
                    "verdict": {
                        "decision": "close",
                        "confidence": round(rng.uniform(0.88, 0.95), 2),
                        "threat_assessment": f"Scheduled backup automation on {host}: the {user} service account's SSH-plus-command pattern matches its standing maintenance authorization.",
                        "evidence_strength": "strong",
                        "potential_impact": "low",
                        "urgency": "routine",
                        "key_evidence": [
                            f"{user} is a service account with a standing grant covering rule 5715 on {host}",
                            "single command consistent with backup tooling, no interactive shell",
                            "source address inside the management subnet",
                        ],
                        "gaps_in_evidence": ["command arguments not captured by the decoder"],
                        "alternative_explanations": [
                            "operator running an ad-hoc job under the service account"
                        ],
                        "recommendation": "Close as authorized automation; the reopen window guards recurrence drift.",
                    },
                    "route": ["INVESTIGATE", "VERDICT"],
                },
            )
        )

    for _ in range(n_veto):
        t = _tok(rng)
        host, user, rid = f"fin-{t}", "svc-legacy", "5402"
        out.append(
            EventTemplate(
                family="veto",
                rule_id=rid,
                severity=rng.choice([5, 6, 7]),
                title=f"Successful sudo to ROOT executed by {user} on {host}",
                description=f"{user} elevated to root on {host} outside its usual change pattern",
                rule_groups=["syslog", "sudo"],
                mitre={
                    "ids": ["T1548.003"],
                    "tactics": ["Privilege Escalation"],
                    "techniques": ["Sudo and Sudo Caching"],
                },
                entities=[
                    {"type": "host", "value": host, "role": "target"},
                    {"type": "user", "value": user, "role": "actor"},
                ],
                template_hash="tpl-5402",
                script={
                    "key": host,
                    "verdict": {
                        "decision": "close",
                        "confidence": round(rng.uniform(0.72, 0.82), 2),
                        "threat_assessment": f"Root elevation by {user} on {host} resembles this team's routine maintenance cadence.",
                        "evidence_strength": "moderate",
                        "potential_impact": "medium",
                        "urgency": "routine",
                        "key_evidence": [
                            "elevation pattern matches prior maintenance sessions for this account",
                            "no follow-on persistence or lateral movement observed",
                        ],
                        "gaps_in_evidence": [
                            "no change ticket located for this specific host and window",
                        ],
                        "alternative_explanations": [
                            "an engineer reusing the service account interactively"
                        ],
                        "recommendation": "Close as routine maintenance based on the historical pattern.",
                    },
                    "route": ["INVESTIGATE", "VERDICT"],
                },
            )
        )

    for _ in range(n_escalate):
        t = _tok(rng)
        host, user, rid = f"db-{t}", "svc-etl", "5715"
        ip = rng.choice(EXT_IPS)
        out.append(
            EventTemplate(
                family="escalate",
                rule_id=rid,
                severity=rng.choice([8, 9, 10]),
                title=f"SSH success after repeated failures for {user} on {host}",
                description=f"{user} authenticated to {host} from {ip} after a burst of failures; account normally logs in from the management subnet only",
                rule_groups=["sshd", "authentication_success"],
                mitre={
                    "ids": ["T1078", "T1110"],
                    "tactics": ["Initial Access", "Credential Access"],
                    "techniques": ["Valid Accounts", "Brute Force"],
                },
                entities=[
                    {"type": "host", "value": host, "role": "target"},
                    {"type": "user", "value": user, "role": "actor"},
                    {"type": "ip", "value": ip, "role": "src"},
                ],
                template_hash="tpl-5715-bf",
                script={
                    "key": host,
                    "verdict": {
                        "decision": "escalate",
                        "confidence": round(rng.uniform(0.84, 0.93), 2),
                        "threat_assessment": f"Probable credential compromise of {user}: failure burst followed by success from an external address that has never touched {host} before.",
                        "evidence_strength": "strong",
                        "potential_impact": "high",
                        "urgency": "urgent",
                        "key_evidence": [
                            f"authentication failures followed by success from {ip}",
                            "source address outside every known management range",
                            "service accounts do not log in interactively from external networks",
                        ],
                        "gaps_in_evidence": ["no packet capture for the session content"],
                        "assumptions_made": [
                            "the account's usual source ranges are complete in inventory"
                        ],
                        "alternative_explanations": [
                            "an engineer travelling and tunnelling through an unlisted egress"
                        ],
                        "recommendation": "Escalate for credential rotation and session forensics on the target host.",
                    },
                    "route": ["INVESTIGATE", "VERDICT"],
                },
            )
        )

    return out


# ---------------------------------------------------------------------------
# Goldens-derived reasoning cases (vendored snapshot)
# ---------------------------------------------------------------------------


def goldens_events(rng: random.Random, n: int) -> list[EventTemplate]:
    """Sample vendored goldens cases into promotable events. Gold labels
    steer the scripted verdict: close → covered-style close; escalate with
    paperwork contradiction → fooled-close (guard veto candidate); escalate
    with actor_genuine=false → scripted escalate."""
    cases = [
        json.loads(line)
        for line in (CORPUS_DIR / "goldens" / "cases.jsonl").read_text().splitlines()
    ]
    gold = {
        g["id"]: g
        for g in (
            json.loads(line)
            for line in (CORPUS_DIR / "goldens" / "gold.jsonl").read_text().splitlines()
        )
    }
    rng.shuffle(cases)
    out: list[EventTemplate] = []
    for case in cases[:n]:
        g = gold[case["id"]]
        alert = case["alert"]
        rid = str(alert.get("rule", {}).get("id", "5402"))
        t = _tok(rng)
        host = f"g{t}-{alert.get('agent', {}).get('name', 'app-00')}"
        # The ACTOR is the source user; dstuser is the elevation target
        # (often root for sudo) and would misname the account in the demo
        # story. Prefer srcuser.
        user = (
            (alert.get("data", {}) or {}).get("srcuser")
            or (alert.get("data", {}) or {}).get("dstuser")
            or "svc-app"
        )
        comp = g.get("components", {})
        decision = g.get("decision", "escalate")
        actor_bad = comp.get("actor_genuine") is False
        if decision == "close":
            fam, sdec, conf = "goldens_close", "close", round(rng.uniform(0.87, 0.94), 2)
            threat = "Activity is covered by current organizational authorization state; no indicator contradicts the covering record."
            rec = "Close as authorized activity."
        elif actor_bad:
            fam, sdec, conf = "goldens_escalate", "escalate", round(rng.uniform(0.82, 0.92), 2)
            threat = "The covering paperwork exists, but the actor's authenticity is in doubt — treat the credential as potentially compromised."
            rec = "Escalate for identity verification and credential rotation."
        else:
            fam, sdec, conf = "goldens_veto", "close", round(rng.uniform(0.7, 0.8), 2)
            dim = g.get("metadata", {}).get("flipped_dimension", "coverage")
            threat = f"Activity resembles routinely authorized work; assessed against the historical pattern (note: {dim.replace('_', ' ')})."
            rec = "Close as routine authorized activity based on precedent."
        out.append(
            EventTemplate(
                family=fam,
                rule_id=rid,
                severity=6 if sdec == "close" else 8,
                title=f"{alert.get('rule', {}).get('description') or 'Privileged activity'} on {host}",
                description=f"{user} activity matching rule {rid} on {host} (goldens group {g.get('metadata', {}).get('counterfactual_group', '?')[:8]})",
                rule_groups=list(alert.get("rule", {}).get("groups") or []) or ["syslog"],
                mitre=None,
                entities=[
                    {"type": "host", "value": host, "role": "target"},
                    {"type": "user", "value": str(user), "role": "actor"},
                ],
                template_hash=f"tpl-g-{rid}",
                script={
                    "key": host,
                    "verdict": {
                        "decision": sdec,
                        "confidence": conf,
                        "threat_assessment": threat,
                        "evidence_strength": "strong"
                        if sdec != "close" or decision == "close"
                        else "moderate",
                        "potential_impact": "high" if sdec == "escalate" else "low",
                        "urgency": "urgent" if sdec == "escalate" else "routine",
                        "key_evidence": [
                            f"rule {rid} activity by {user} on {host}",
                            "assessment grounded in the tenant's authorization state",
                        ],
                        "gaps_in_evidence": ["full command context unavailable"],
                        "alternative_explanations": [],
                        "recommendation": rec,
                    },
                    "route": ["INVESTIGATE", "VERDICT"],
                },
            )
        )
    return out
