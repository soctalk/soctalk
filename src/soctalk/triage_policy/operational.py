"""The ``close_operational`` deterministic disposition (issue #43, second triage policy).

Some alert classes are operational, not security events: Wazuh agent-health noise
(event queue flooded, buffer full) is an infrastructure/agent-configuration
condition. Sending it to LLM triage buys nothing but inconsistent verdicts (the
threat-verdict framing has no bucket for "ops issue"), spurious human-review rows,
and token spend. The class decision is deterministic, so it is made in code; the
LLM is invoked only when security indicators make the alert more than its class.

``operational_close_vetoes`` is that indicator check, pure and unit-tested. The
vocabulary deliberately mirrors the SIEM-routine shadow scorer's exclusions
(``core/ir/authz_shadow.exclusion_reasons``): MITRE-mapped, IOC-bearing, or
high-severity alerts are never silently closed, and neither is anything carrying a
confirmed malicious signal. Any veto routes to FULL triage — the fail-closed
direction for a close-shaped capability. The terminal safety floor still applies
downstream, unchanged.
"""

from __future__ import annotations

from typing import Any

from soctalk.authorization.render import has_malicious_signal

VETO_MITRE = "mitre_mapped"
VETO_OBSERVABLES = "ioc_present"
VETO_SEVERITY = "severity_too_high"
VETO_MALICIOUS = "malicious_signal"
VETO_UNATTESTED_CLASS = "unattested_alert_class"

# Wazuh level 12+ is critical territory; an agent-health rule someone deliberately
# raised to critical has been re-classified by the operator — honor that.
OPERATIONAL_MAX_LEVEL = 11


def _has_mitre(mitre: dict[str, Any] | None) -> bool:
    """True if the alert carries ANY MITRE mapping — canonical wire keys
    (ids/tactics/techniques) AND the legacy singular ones, same coverage as the
    shadow scorer's guardrail (a missed key here would be a close-suppression
    bypass in the other direction)."""
    if not mitre:
        return False
    return any(
        mitre.get(k) for k in ("ids", "tactics", "techniques", "id", "tactic", "technique")
    )


def operational_close_vetoes(
    investigation: dict[str, Any], class_rule_groups: list[str] | None = None
) -> list[str]:
    """Security indicators that forbid the deterministic operational close.

    Pure over the projected investigation dict (the worker's pre-LLM view). Empty
    list = the alert is its class and nothing more; any entry = full LLM triage.

    Class attestation: EVERY alert on the investigation must carry one of the
    triage policy's ``class_rule_groups`` (the ruleset's semantic class), or the close is
    vetoed. This is what stops a correlated multi-alert investigation from being
    closed on the strength of one agent-health member, and it demands more identity
    than a bare rule id — a rule-id-only match still routes to the triage policy, but an
    alert whose groups don't attest the class goes to full triage (the fail-closed
    direction). An investigation with no alerts can't attest anything and is vetoed
    the same way.
    """
    vetoes: list[str] = []
    alerts = [a for a in investigation.get("alerts") or [] if isinstance(a, dict)]
    class_groups = {g.lower() for g in class_rule_groups or []}
    if class_groups:
        attested = bool(alerts) and all(
            class_groups.intersection(str(g).lower() for g in a.get("rule_groups") or [])
            for a in alerts
        )
        if not attested:
            vetoes.append(VETO_UNATTESTED_CLASS)
    if any(_has_mitre(a.get("mitre")) for a in alerts):
        vetoes.append(VETO_MITRE)
    if investigation.get("observables"):
        vetoes.append(VETO_OBSERVABLES)
    if any(int(a.get("level") or 0) > OPERATIONAL_MAX_LEVEL for a in alerts):
        vetoes.append(VETO_SEVERITY)
    if has_malicious_signal(investigation):
        vetoes.append(VETO_MALICIOUS)
    return vetoes
