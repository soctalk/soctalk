"""Triage-policy registry: vetted built-ins plus declarative YAML files (#44).

``match_triage_policy`` is pure and deterministic — the resolver node calls it once per
run and writes the winner into graph state. Priority order (lower first) puts
security-judgment playbooks before operational ones, so an alert that somehow
matches both gets the stricter treatment; file-loaded playbooks default below the
built-ins.

File loading (``SOCTALK_PLAYBOOK_DIR``, ``*.yaml``/``*.yml``) fails closed per
file: schema violations, unknown fields, or invalid guardrail conditions reject
the whole file with an error log — a playbook that cannot be fully validated
never governs anything. File-loaded playbooks default to ``status: shadow``
(decisions logged, nothing enforced) until their author explicitly sets
``status: active`` — the #44 activation gate. Tenant scoping: a playbook with a
concrete ``tenant`` applies only when the process's ``SOCTALK_TENANT_ID`` (or
``SOCTALK_TENANT_SLUG``) matches; ``tenant: "*"`` applies everywhere. Every
load/skip decision is logged as the activation audit trail.
"""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from typing import Any

import structlog

from soctalk.triage_policy.models import (
    CLOSE_OPERATIONAL,
    GATHER_AUTHORIZATION_CONTEXT,
    TriagePolicy,
    TriagePolicyMatch,
)

logger = structlog.get_logger()

# The dual-use privileged-exec class: host-auth activity (sudo/su) where the same
# observable event is routine administration under a covering record and an incident
# without one. Matches natively on sudo/su rule groups, and on any investigation that
# carries an account-track authorization context (the M1 claim/fixture seam).
PRIVILEGED_EXEC_PLAYBOOK = TriagePolicy(
    id="dual-use-privileged-exec",
    version=2,
    priority=10,
    applies_to=TriagePolicyMatch(
        rule_groups=["sudo", "su"],
        authorization_tracks=["account"],
    ),
    required_steps=[GATHER_AUTHORIZATION_CONTEXT],
    decision_modules=["authorization_engine"],
    # CLOSE is never legal for the dual-use class: the router tier must not
    # short-circuit-close an alert whose whole point is that benign and hostile
    # look identical — the reasoning-tier verdict makes that call. VERDICT stays
    # legal in triage because proposing it triggers the required-step reroute.
    legal_actions={
        "triage": ["ENRICH", "CONTEXTUALIZE", "INVESTIGATE", "VERDICT"],
        "decide": ["ENRICH", "CONTEXTUALIZE", "INVESTIGATE", "VERDICT"],
    },
    # The #43 worked example: a close on a PCI-scoped asset needs human sign-off
    # even when a record fully covers the activity.
    close_signoff_data_classes=["pci"],
)

# The agent-health/operational class: Wazuh agent self-monitoring noise ("Agent
# event queue is flooded", buffer full/flooded) — an infrastructure or agent-health
# condition, not a security event, unless security indicators say otherwise. The
# deterministic disposition closes it as operational WITHOUT an LLM look; any veto
# in soctalk.triage_policy.operational (MITRE mapping, IOCs, critical severity,
# malicious signal) sends it to full triage instead. This is what makes verdicts
# on this class consistent: a pure function cannot flip between 30% and 50%.
AGENT_HEALTH_PLAYBOOK = TriagePolicy(
    id="agent-health-operational",
    version=1,
    priority=50,
    applies_to=TriagePolicyMatch(
        # Wazuh internal agent-health rules: 202 "Agent event queue is flooded"
        # and its buffer siblings carry the agent_flooding/agent_buffer groups.
        rule_groups=["agent_flooding", "agent_buffer"],
        rule_ids=["202"],
    ),
    deterministic_disposition=CLOSE_OPERATIONAL,
)

BUILTIN_TRIAGE_POLICIES: tuple[TriagePolicy, ...] = (
    PRIVILEGED_EXEC_PLAYBOOK,
    AGENT_HEALTH_PLAYBOOK,
)


# File-loaded playbooks may never outrank the built-ins on a double match: a
# high-priority authored playbook governing (say) sudo alerts would silently strip
# the built-in dual-use protections (required evidence step, no-CLOSE legal set).
# Files below this floor are REJECTED at load — an explicit authoring fix, not a
# silent clamp. Built-ins use 10/50.
FILE_PRIORITY_FLOOR = 60

# A playbook file larger than this is rejected unread past the stat — the loader
# runs at worker startup and a runaway file (or symlink to one) must not OOM it.
_MAX_FILE_BYTES = 64 * 1024


def _process_tenant_identifiers() -> frozenset[str]:
    """Every identity this process runs as — the runs-worker carries BOTH the
    tenant UUID and the slug, and a playbook's ``tenant:`` may name either."""
    return frozenset(
        v
        for v in (os.getenv("SOCTALK_TENANT_ID"), os.getenv("SOCTALK_TENANT_SLUG"))
        if v
    )


def parse_triage_policy_text(text: str) -> TriagePolicy:
    """Parse + fully validate one YAML playbook document. Raises on ANY problem —
    unknown fields, bad enums, invalid guardrail conditions (fail closed). Text
    is the unit of validation so callers that also SHIP the content (render.py)
    validate exactly the bytes they ship — no read-twice TOCTOU window.
    File-loaded playbooks default to shadow unless the document says otherwise."""
    import yaml

    if len(text.encode()) > _MAX_FILE_BYTES:
        raise ValueError(f"playbook exceeds {_MAX_FILE_BYTES} bytes")
    raw = yaml.safe_load(text)
    if not isinstance(raw, dict):
        raise ValueError("playbook file must be a mapping at its root")
    raw.setdefault("status", "shadow")
    pb = TriagePolicy.model_validate(raw)
    if pb.priority < FILE_PRIORITY_FLOOR:
        raise ValueError(
            f"file playbooks must have priority >= {FILE_PRIORITY_FLOOR} "
            f"(got {pb.priority}) — built-in protections may not be outranked"
        )
    if pb.deterministic_disposition is not None:
        # Codex #44 High: minting a new auto-close CLASS is a code-review
        # decision (a vetted built-in), never file data — the class-attestation
        # veto trusts the playbook's own rule_groups, so an authored file could
        # otherwise declare any group operational and deterministically close it.
        raise ValueError(
            "deterministic_disposition is a built-in-only capability; file "
            "playbooks compose guardrails/steps/legal_actions only"
        )
    return pb


def load_triage_policy_file(path: Path) -> TriagePolicy:
    """Read + validate one playbook file (see ``parse_triage_policy_text``)."""
    if path.stat().st_size > _MAX_FILE_BYTES:
        raise ValueError(f"playbook file exceeds {_MAX_FILE_BYTES} bytes")
    return parse_triage_policy_text(path.read_text())


def _load_file_triage_policies() -> list[TriagePolicy]:
    # Canonical env is SOCTALK_TRIAGE_POLICY_DIR; SOCTALK_PLAYBOOK_DIR is the
    # deprecated alias, read for one release so a not-yet-rolled pod still works.
    directory = os.getenv("SOCTALK_TRIAGE_POLICY_DIR") or os.getenv("SOCTALK_PLAYBOOK_DIR", "")
    if not directory:
        return []
    root = Path(directory)
    if not root.is_dir():
        logger.warning("playbook_dir_missing", dir=directory)
        return []
    tenants = _process_tenant_identifiers()
    loaded: list[TriagePolicy] = []
    for path in sorted(root.glob("*.y*ml")):
        try:
            pb = load_triage_policy_file(path)
        except Exception as exc:  # noqa: BLE001 — a bad file must never govern
            logger.error(
                "playbook_file_rejected", file=str(path), error=str(exc)[:300]
            )
            continue
        if pb.tenant != "*" and pb.tenant not in tenants:
            logger.info(
                "playbook_file_skipped_foreign_tenant",
                file=str(path), playbook=pb.id, tenant=pb.tenant,
            )
            continue
        if any(pb.id == b.id for b in BUILTIN_TRIAGE_POLICIES):
            logger.error(
                "playbook_file_rejected", file=str(path), playbook=pb.id,
                error="id collides with a built-in playbook",
            )
            continue
        logger.info(
            "playbook_loaded",
            file=str(path), playbook=pb.id, version=pb.version,
            status=pb.status, priority=pb.priority, tenant=pb.tenant,
        )
        loaded.append(pb)
    return loaded


@lru_cache(maxsize=1)
def _registry() -> tuple[TriagePolicy, ...]:
    """Built-ins + validated file playbooks, priority-sorted (stable). Cached for
    process lifetime — a playbook edit rolls out with the worker, which is the
    #44 activation gate working as intended."""
    merged = list(BUILTIN_TRIAGE_POLICIES) + _load_file_triage_policies()
    merged.sort(key=lambda p: p.priority)
    return tuple(merged)


def reset_registry_cache() -> None:
    """For tests that change SOCTALK_PLAYBOOK_DIR at runtime."""
    _registry.cache_clear()


def all_triage_policies() -> tuple[TriagePolicy, ...]:
    """Every playbook the process governs by — built-ins plus validated file
    playbooks, priority-sorted. Read-only view for governance/observability
    surfaces; reflects THIS process's SOCTALK_PLAYBOOK_DIR + tenant scoping."""
    return _registry()


def is_builtin(triage_policy_id: str) -> bool:
    return any(triage_policy_id == b.id for b in BUILTIN_TRIAGE_POLICIES)


def _alert_rule_groups(investigation: dict[str, Any]) -> set[str]:
    groups: set[str] = set()
    for alert in investigation.get("alerts") or []:
        if isinstance(alert, dict):
            groups.update(str(g).lower() for g in alert.get("rule_groups") or [])
    return groups


def _alert_rule_ids(investigation: dict[str, Any]) -> set[str]:
    ids: set[str] = set()
    for alert in investigation.get("alerts") or []:
        if isinstance(alert, dict) and alert.get("rule_id"):
            ids.add(str(alert["rule_id"]))
    return ids


def _authorization_track(investigation: dict[str, Any]) -> str | None:
    ctx = investigation.get("authorization_context")
    if not isinstance(ctx, dict):
        return None
    activity = ctx.get("activity")
    if not isinstance(activity, dict):
        return None
    track = activity.get("track")
    return str(track) if track else None


def _matches(pb: TriagePolicy, groups: set[str], rule_ids: set[str], track: str | None) -> bool:
    if pb.applies_to.rule_groups and groups.intersection(
        g.lower() for g in pb.applies_to.rule_groups
    ):
        return True
    if pb.applies_to.rule_ids and rule_ids.intersection(pb.applies_to.rule_ids):
        return True
    return track is not None and track in pb.applies_to.authorization_tracks


def match_triage_policy(investigation: dict[str, Any]) -> TriagePolicy | None:
    """Highest-priority matching ACTIVE playbook for this investigation, or None.

    Matching reads only the projected alert dicts (``rule_groups``/``rule_id``) and
    the authorization context's activity track — it selects WHICH playbook governs
    the run, never a security judgment (that stays in the engine + LLM). A matched
    deterministic disposition still has to clear its own per-alert class attestation
    and security-indicator vetoes before it applies.
    """
    groups = _alert_rule_groups(investigation)
    rule_ids = _alert_rule_ids(investigation)
    track = _authorization_track(investigation)
    for pb in _registry():
        if pb.status == "active" and _matches(pb, groups, rule_ids, track):
            return pb
    return None


def match_shadow_triage_policies(investigation: dict[str, Any]) -> list[TriagePolicy]:
    """Every matching SHADOW playbook — evaluated for audit only, never enforced."""
    groups = _alert_rule_groups(investigation)
    rule_ids = _alert_rule_ids(investigation)
    track = _authorization_track(investigation)
    return [
        pb
        for pb in _registry()
        if pb.status == "shadow" and _matches(pb, groups, rule_ids, track)
    ]
