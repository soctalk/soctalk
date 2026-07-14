"""Adapt benchmark org-state (soctalk-goldens orgstate.jsonl rows) into AuthorizationFacts.

soctalk never imports the soctalk-goldens package; the benchmark contributes DATA only. Each
orgstate.jsonl row is ``{id, track, activity, org_state}`` where ``org_state`` is the goldens
OrgState/FimOrgState dump (tickets, baselines, policies, freezes, assets, accounts, sightings /
their FIM analogues). This module maps every record onto the AuthorizationFact contract so the
engine can reason over facts alone; the parity test proves the mapping+engine reproduce the
benchmark's deterministic labels.

Also here: the "stackless" projection (epic M0) — the subset of an org-state a SIEM-only
deployment could actually know (sighting history, asset/path inventory with containment flags,
account names+types) with all ITSM/CMDB/GRC records (tickets, baselines, policies, freezes,
org links) removed and business-context attributes reset to defaults. It operates on the raw
org-state dicts so measured deltas are attributable purely to missing records, not adapter drift.
"""

from __future__ import annotations

from typing import Any

from soctalk.models.authorization import (
    TRUST_TIER,
    AccountKind,
    AuthorizationActivity,
    AuthorizationEntityKind,
    AuthorizationFact,
    AuthorizationSourceType,
    AuthorizationTrack,
    ChangeFreezeFact,
    ChangeKind,
    CompromiseStatus,
    EntityContextFact,
    FactScope,
    FreezeScope,
    GrantClass,
    GrantFact,
    GrantStatus,
    PolicyApplicability,
    PolicyPriority,
    ProhibitionFact,
    RecurringWindow,
)

_SYSTEM_TRUST = TRUST_TIER[AuthorizationSourceType.SYSTEM_ASSERTED]
_TELEMETRY_TRUST = TRUST_TIER[AuthorizationSourceType.TELEMETRY_ROUTINE]


def _status(value: object) -> GrantStatus:
    return GrantStatus(str(value or "approved"))


def _priority(value: object) -> PolicyPriority:
    return PolicyPriority(str(value or "high"))


def _change_kind(value: object) -> ChangeKind:
    return ChangeKind(str(value or "any"))


def _compromise(value: object) -> CompromiseStatus | None:
    return CompromiseStatus(str(value)) if value else None


def _account_kind(value: object) -> AccountKind | None:
    return AccountKind(str(value)) if value else None


def activity_from_row(row: dict[str, Any]) -> AuthorizationActivity:
    """Build the activity tuple from an orgstate.jsonl row (extra keys are ignored)."""
    track = AuthorizationTrack(row["track"])
    act = row["activity"]
    if track == AuthorizationTrack.ACCOUNT:
        return AuthorizationActivity(
            track=track,
            host=act["host"],
            account=act["account"],
            action=act["action"],
            time=act["time"],
            interactive=bool(act.get("interactive", False)),
        )
    return AuthorizationActivity(
        track=track,
        path=act["path"],
        change_type=ChangeKind(act["change_type"]),
        time=act["time"],
    )


def facts_from_row(row: dict[str, Any]) -> tuple[AuthorizationActivity, list[AuthorizationFact]]:
    activity = activity_from_row(row)
    if activity.track == AuthorizationTrack.ACCOUNT:
        return activity, facts_from_account_org_state(row["org_state"])
    return activity, facts_from_fim_org_state(row["org_state"])


def _window(record: dict[str, Any]) -> RecurringWindow | None:
    if record.get("window_start") and record.get("window_end"):
        return RecurringWindow(start=record["window_start"], end=record["window_end"])
    return None


def facts_from_account_org_state(org: dict[str, Any]) -> list[AuthorizationFact]:
    facts: list[AuthorizationFact] = []
    for t in org.get("tickets", []):
        facts.append(
            GrantFact(
                id=t["id"],  # record id is load-bearing: freezes except tickets by id
                track=AuthorizationTrack.ACCOUNT,
                scope=FactScope(
                    subject=t["account"],
                    target=t["host"],
                    action=t["action"],
                    recurring_window=_window(t),
                ),
                grant_class=GrantClass.CHANGE_TICKET,
                status=_status(t.get("status")),
                cab_required=t.get("cab_required", False),
                cab_approved=t.get("cab_approved", True),
                emergency=t.get("emergency", False),
                freeze_exception=t.get("freeze_exception", False),
                valid_from=t.get("effective_from"),
                valid_until=t["valid_until"],
            )
        )
    for b in org.get("baselines", []):
        facts.append(
            GrantFact(
                id=b["id"],
                track=AuthorizationTrack.ACCOUNT,
                scope=FactScope(
                    subject=b["account"],
                    target=b["host"],
                    action=b["action"],
                    recurring_window=_window(b),
                ),
                grant_class=GrantClass.STANDING_BASELINE,
            )
        )
    for i, o in enumerate(org.get("observations", [])):
        facts.append(
            GrantFact(
                id=f"OBS-{i}",
                track=AuthorizationTrack.ACCOUNT,
                scope=FactScope(subject=o["account"], target=o["host"], action=o["action"]),
                grant_class=GrantClass.ROUTINE_OBSERVATION,
                source_type=AuthorizationSourceType.TELEMETRY_ROUTINE,
                trust=_TELEMETRY_TRUST,
                seen_count=o.get("seen_count", 0),
                ioc=o.get("ioc", False),
            )
        )
    for p in org.get("policies", []):
        facts.append(
            ProhibitionFact(
                id=p["id"],
                track=AuthorizationTrack.ACCOUNT,
                forbid_action=p["forbid_action"],
                forbid_account_type=_account_kind(p.get("forbid_account_type")),
                applies_to=PolicyApplicability(
                    env=p.get("applies_to_env"),
                    criticality=p.get("applies_to_criticality"),
                    data_class=p.get("applies_to_data_class"),
                ),
                priority=_priority(p.get("priority")),
                waiver_present=p.get("waiver_present", False),
                break_glass_exception=p.get("break_glass_exception", False),
            )
        )
    for i, fr in enumerate(org.get("freezes", [])):
        facts.append(
            ChangeFreezeFact(
                id=f"FRZ-{i}",
                track=AuthorizationTrack.ACCOUNT,
                freeze_scope=FreezeScope(envs=fr["envs"]),
                start=fr["start"],
                end=fr["end"],
                allowed_exception_ids=fr.get("allowed_exception_ticket_ids", []),
            )
        )
    for i, a in enumerate(org.get("assets", [])):
        facts.append(
            EntityContextFact(
                id=f"ENT-A{i}",
                track=AuthorizationTrack.ACCOUNT,
                entity_type=AuthorizationEntityKind.ASSET,
                name=a["name"],
                environment=a.get("environment"),
                criticality=a.get("criticality"),
                data_classification=a.get("data_classification"),
                owner_org=a.get("owner_org"),
                custodian_account=a.get("custodian_account"),
                compromise_status=_compromise(a.get("compromise_status")),
                source_type=AuthorizationSourceType.CONNECTOR_VERIFIED,
                trust=a.get("source_reliability", 100),
            )
        )
    compromised = set(org.get("compromised_accounts", []))
    for i, acct in enumerate(org.get("accounts", [])):
        facts.append(
            EntityContextFact(
                id=f"ENT-U{i}",
                track=AuthorizationTrack.ACCOUNT,
                entity_type=AuthorizationEntityKind.ACCOUNT,
                name=acct["name"],
                account_type=_account_kind(acct.get("type")),
                owner_org=acct.get("owner_org"),
                privileged=acct.get("privileged"),
                on_call=acct.get("on_call"),
                break_glass=acct.get("break_glass"),
                service_owner=acct.get("service_owner"),
                compromise_status=(
                    CompromiseStatus.COMPROMISED if acct["name"] in compromised else None
                ),
                trust=_SYSTEM_TRUST,
            )
        )
    known = {acct["name"] for acct in org.get("accounts", [])}
    for i, name in enumerate(n for n in org.get("compromised_accounts", []) if n not in known):
        facts.append(
            EntityContextFact(
                id=f"ENT-C{i}",
                track=AuthorizationTrack.ACCOUNT,
                entity_type=AuthorizationEntityKind.ACCOUNT,
                name=name,
                compromise_status=CompromiseStatus.COMPROMISED,
                trust=_SYSTEM_TRUST,
            )
        )
    for i, o in enumerate(org.get("orgs", [])):
        if o.get("linked_orgs"):
            facts.append(
                EntityContextFact(
                    id=f"ENT-O{i}",
                    track=AuthorizationTrack.ACCOUNT,
                    entity_type=AuthorizationEntityKind.ORG,
                    name=o["name"],
                    linked_orgs=o["linked_orgs"],
                    trust=_SYSTEM_TRUST,
                )
            )
    return facts


def facts_from_fim_org_state(org: dict[str, Any]) -> list[AuthorizationFact]:
    facts: list[AuthorizationFact] = []
    for cr in org.get("change_requests", []):
        facts.append(
            GrantFact(
                id=cr["id"],
                track=AuthorizationTrack.FIM,
                scope=FactScope(
                    target=cr["path_glob"],
                    change_type=_change_kind(cr.get("change_type")),
                    recurring_window=_window(cr),
                ),
                grant_class=GrantClass.CHANGE_TICKET,
                status=_status(cr.get("status")),
                cab_required=cr.get("cab_required", False),
                cab_approved=cr.get("cab_approved", True),
                emergency=cr.get("emergency", False),
                freeze_exception=cr.get("freeze_exception", False),
                valid_from=cr.get("effective_from"),
                valid_until=cr["valid_until"],
            )
        )
    for b in org.get("change_baselines", []):
        facts.append(
            GrantFact(
                id=b["id"],
                track=AuthorizationTrack.FIM,
                scope=FactScope(
                    target=b["path_glob"],
                    change_type=_change_kind(b.get("change_type")),
                    recurring_window=_window(b),
                ),
                grant_class=GrantClass.STANDING_BASELINE,
            )
        )
    for i, fr in enumerate(org.get("change_freezes", [])):
        facts.append(
            ChangeFreezeFact(
                id=f"FRZ-{i}",
                track=AuthorizationTrack.FIM,
                freeze_scope=FreezeScope(config_classes=fr["config_classes"]),
                start=fr["start"],
                end=fr["end"],
                allowed_exception_ids=fr.get("allowed_exception_ids", []),
            )
        )
    for p in org.get("change_policies", []):
        facts.append(
            ProhibitionFact(
                id=p["id"],
                track=AuthorizationTrack.FIM,
                forbid_change_type=p.get("forbid_change_type"),
                # empty list = ANY class (source semantics) — pass through verbatim
                applies_to=PolicyApplicability(config_class=p.get("forbid_change_to_class", [])),
                priority=_priority(p.get("priority")),
                waiver_present=p.get("waiver_present", False),
                break_glass_exception=p.get("break_glass_exception", False),
            )
        )
    for i, wp in enumerate(org.get("paths", [])):
        facts.append(
            EntityContextFact(
                id=f"ENT-P{i}",
                track=AuthorizationTrack.FIM,
                entity_type=AuthorizationEntityKind.WATCHED_PATH,
                name=wp["path"],
                config_class=wp.get("config_class"),
                criticality=wp.get("criticality"),
                environment=wp.get("environment"),
                owner_org=wp.get("owner_org"),
                approver=wp.get("approver"),
                compromise_status=_compromise(wp.get("compromise_status")),
                source_type=AuthorizationSourceType.CONNECTOR_VERIFIED,
                trust=wp.get("source_reliability", 100),
            )
        )
    return facts


# --- stackless projection (M0) -------------------------------------------------------------


def stackless_org_state(org: dict[str, Any], track: AuthorizationTrack) -> dict[str, Any]:
    """Project an org-state down to what a SIEM-only (stackless) deployment can know.

    Kept: sighting history (Wazuh/UEBA telemetry), containment/compromise flags (the SOC's own
    EDR/active-response state), the asset/path inventory (agent inventory / syscheck config),
    and account names + service/human type (UEBA-inferable from session patterns).

    Dropped: tickets, baselines, policies, freezes, org links (ITSM/GRC records) and
    business-context attributes — environment, criticality, data classification, ownership,
    on-call/break-glass/privileged (CMDB/IAM/rota knowledge). `privileged` is arguably
    syscollector-derivable but only bites combined with on-call/break-glass, so keeping it
    would just manufacture unresolvable escalations.
    """
    if track == AuthorizationTrack.ACCOUNT:
        return {
            "host": org.get("host", ""),
            "accounts": [
                {"name": a["name"], "type": a["type"]} for a in org.get("accounts", [])
            ],
            "compromised_accounts": list(org.get("compromised_accounts", [])),
            "assets": [
                {
                    "name": a["name"],
                    "compromise_status": a.get("compromise_status", "clean"),
                    "source_reliability": a.get("source_reliability", 100),
                }
                for a in org.get("assets", [])
            ],
            "observations": [dict(o) for o in org.get("observations", [])],
        }
    return {
        "path": org.get("path", ""),
        "paths": [
            {
                "path": p["path"],
                "compromise_status": p.get("compromise_status", "clean"),
                "source_reliability": p.get("source_reliability", 100),
            }
            for p in org.get("paths", [])
        ],
    }


def stackless_facts_from_row(
    row: dict[str, Any],
) -> tuple[AuthorizationActivity, list[AuthorizationFact]]:
    activity = activity_from_row(row)
    projected = stackless_org_state(row["org_state"], activity.track)
    if activity.track == AuthorizationTrack.ACCOUNT:
        return activity, facts_from_account_org_state(projected)
    return activity, facts_from_fim_org_state(projected)
