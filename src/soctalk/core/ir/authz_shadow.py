"""SIEM-routine authorization scoring — SHADOW MODE ONLY (epic M2, Phase a).

Scores whether SIEM-derived routine history would authorize-close an incoming alert and
LOGS the would-close decision (audit action ``ir.authorization.routine_shadow``). It never
changes a disposition: Phase b (actual auto-close) is gated on the shadow data this module
produces showing a zero false-negative rate on the red-team set (handoff §7 M2 exit).

Guardrails (§8.3) are enforced IN CODE, not left to the engine or a prompt:

- kill switch (``SOCTALK_AUTHZ_ROUTINE_KILL``) overrides everything;
- scoped to explicitly enabled alert families (``SOCTALK_AUTHZ_ROUTINE_FAMILIES``, csv of
  decoder names; empty = disabled) AND a per-tenant policy flag
  (``authz_routine_shadow_enabled``, default off);
- malicious signal wins: an alert carrying IOCs or a MITRE mapping is NEVER would-close,
  no matter how routine its history (tested in code);
- high-severity alerts are excluded (``SOCTALK_AUTHZ_ROUTINE_MAX_SEVERITY``, default 9 —
  only sub-high levels are ever candidates);
- routine is keyed on a SPECIFIC tuple — (tenant, source, decoder, template hash+version,
  host entity, account entity when present) — never on rule id alone, and requires mature
  history: sightings on >= ``SOCTALK_AUTHZ_ROUTINE_MIN_DAYS`` distinct days (default 5)
  within the lookback window (default 30d). A same-day burst never counts as routine.

The scoring itself runs through the production authorization contract — a
``telemetry_routine`` GrantFact evaluated by ``soctalk.authorization.engine`` — so Phase b
inherits exactly the semantics the benchmark parity suite pins down.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any
from uuid import UUID

import structlog
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from soctalk.authorization.engine import evaluate_authorization
from soctalk.core.observability.audit import log_audit
from soctalk.models.authorization import (
    TRUST_TIER,
    AuthorizationActivity,
    AuthorizationSourceType,
    AuthorizationTrack,
    FactScope,
    GrantClass,
    GrantFact,
)

logger = structlog.get_logger()

AUDIT_ACTION = "ir.authorization.routine_shadow"


@dataclass(frozen=True)
class ShadowSettings:
    kill: bool = False
    families: frozenset[str] = field(default_factory=frozenset)  # decoder names; empty = off
    lookback_days: int = 30
    min_days: int = 5
    max_severity: int = 9  # inclusive; Wazuh level >= 10 is high/critical territory

    @classmethod
    def from_env(cls) -> ShadowSettings:
        """Fail-closed env parse: any malformed value disables scoring (kill=True)
        rather than raising — this runs on the ingest path and must never throw."""
        try:
            families = frozenset(
                f.strip() for f in os.getenv("SOCTALK_AUTHZ_ROUTINE_FAMILIES", "").split(",")
                if f.strip()
            )
            return cls(
                kill=os.getenv("SOCTALK_AUTHZ_ROUTINE_KILL", "").lower() in ("1", "true", "yes"),
                families=families,
                lookback_days=int(os.getenv("SOCTALK_AUTHZ_ROUTINE_LOOKBACK_DAYS", "30")),
                min_days=int(os.getenv("SOCTALK_AUTHZ_ROUTINE_MIN_DAYS", "5")),
                max_severity=int(os.getenv("SOCTALK_AUTHZ_ROUTINE_MAX_SEVERITY", "9")),
            )
        except (ValueError, TypeError):
            logger.warning("authz_routine_shadow_bad_env — disabling scoring")
            return cls(kill=True)


def should_score(
    settings: ShadowSettings, policy: dict[str, Any], decoder: str | None
) -> bool:
    """The gate: kill switch off, decoder in the enabled family allowlist, the per-tenant
    policy flag set to a real boolean True, AND entity correlation enabled (§8.2 — the
    active-incident veto runs before this hook, so scoring an alert while correlation is
    off would count an alert routine that should have attached to a live incident)."""
    if settings.kill:
        return False
    if not decoder or decoder not in settings.families:
        return False
    if policy.get("authz_routine_shadow_enabled") is not True:  # stringly "false" is not True
        return False
    return policy.get("entity_correlation_enabled") is True


def exclusion_reasons(
    *,
    severity: int,
    mitre: dict[str, Any] | None,
    initial_iocs: list[dict[str, Any]] | None,
    settings: ShadowSettings,
    history_ioc: bool = False,
) -> list[str]:
    """Code-level §8.3 exclusions. Any reason forces would_close=False regardless of
    history — authorization/routine evidence never overrides malicious signal.

    ``history_ioc`` is the taint signal that the ROUTINE HISTORY itself (not just the current
    alert) carries a threat-intel hit: a tuple whose prior sightings were IOC-flagged is not
    benign routine, even when the current alert looks clean. Missing this is a false-negative
    the goldens red-team set (dimension ``ioc_sighting``) surfaces — the sighting is flagged
    but the alert has no data-level IOC, so the alert-only ``ioc_present`` check misses it."""
    reasons = []
    if severity > settings.max_severity:
        reasons.append("severity_too_high")
    if _has_mitre(mitre):
        reasons.append("mitre_mapped")
    if initial_iocs:
        reasons.append("ioc_present")
    if history_ioc:
        reasons.append("routine_ioc_tainted")
    return reasons


def _has_mitre(mitre: dict[str, Any] | None) -> bool:
    """True if the alert carries ANY MITRE mapping. Checks the canonical wire keys
    (ids/tactics/techniques, from soctalk_wire.events) AND the legacy singular
    (id/tactic) — a technique mapping means this is not routine, so a missed key would
    be a guardrail bypass."""
    if not mitre:
        return False
    return any(mitre.get(k) for k in ("ids", "tactics", "techniques", "id", "tactic", "technique"))


def evaluate_shadow(
    *,
    seen_days: int,
    severity: int,
    mitre: dict[str, Any] | None,
    initial_iocs: list[dict[str, Any]] | None,
    host: str,
    account: str,
    action: str,
    ts: datetime,
    settings: ShadowSettings,
    history_ioc: bool = False,
) -> dict[str, Any]:
    """Pure would-close decision: exclusions first, then the production engine over a
    telemetry_routine fact built from the sighting history. ``history_ioc`` marks the tuple's
    prior sightings as IOC-flagged (a threat-intel hit on the routine itself)."""
    excluded = exclusion_reasons(
        severity=severity, mitre=mitre, initial_iocs=initial_iocs, settings=settings,
        history_ioc=history_ioc,
    )

    fact = GrantFact(
        id="ROUTINE-SHADOW",
        track=AuthorizationTrack.ACCOUNT,
        scope=FactScope(subject=account, target=host, action=action),
        grant_class=GrantClass.ROUTINE_OBSERVATION,
        source_type=AuthorizationSourceType.TELEMETRY_ROUTINE,
        trust=TRUST_TIER[AuthorizationSourceType.TELEMETRY_ROUTINE],
        seen_count=seen_days,
        ioc=bool(initial_iocs) or history_ioc,  # tainted routine is not routine
        created_by="authz-routine-shadow",
    )
    activity = AuthorizationActivity(
        track=AuthorizationTrack.ACCOUNT, host=host, account=account, action=action, time=ts
    )
    components = evaluate_authorization(activity, [fact])
    mature = seen_days >= settings.min_days
    would_close = bool(
        not excluded and mature and components.decision == "close"
    )
    return {
        "would_close": would_close,
        "seen_days": seen_days,
        "mature_history": mature,
        "excluded": excluded,
        "components": components.model_dump(),
    }


# The full discriminating entity vocabulary (soctalk_wire.events.Entity.type). The routine
# tuple must match on EVERY such entity present on the alert — template_hash masks IPs and
# paths, so a new destination/process/port would otherwise collide with benign history under
# the same template and inflate seen_days (§8.3: key on a SPECIFIC tuple).
_DISCRIMINATING_ENTITY_TYPES = ("host", "user", "process", "ip", "domain", "port")


def _discriminating_entities(entities: list[dict[str, Any]] | None) -> list[dict[str, str]]:
    """Every discriminating entity on the alert, deduped, in a stable order. Values are used
    verbatim (NOT lowercased) so JSONB containment against the stored `entities` matches — a
    mixed-case fold would silently under-count history (a false-negative that makes shadow
    data misleading), and it keeps distinct same-type entities (src/dst IP, two hosts)
    separate so each must be present in prior history."""
    seen: set[tuple[str, str]] = set()
    out: list[dict[str, str]] = []
    for e in entities or []:
        if not isinstance(e, dict):
            continue
        et, val = e.get("type"), e.get("value")
        if et in _DISCRIMINATING_ENTITY_TYPES and val:
            key = (et, str(val))
            if key not in seen:
                seen.add(key)
                out.append({"type": et, "value": str(val)})
    return sorted(out, key=lambda d: (d["type"], d["value"]))


def _first_value(entities: list[dict[str, str]], entity_type: str) -> str | None:
    for e in entities:
        if e["type"] == entity_type:
            return e["value"]
    return None


async def score_alert_shadow(
    db: AsyncSession,
    *,
    tenant_id: UUID,
    source: str,
    rule_id: str | None,
    severity: int,
    initial_iocs: list[dict[str, Any]],
    evidence: dict[str, Any],
    ts: datetime,
    alert_id: UUID,
    settings: ShadowSettings | None = None,
) -> dict[str, Any] | None:
    """Score one alert in shadow mode and write the audit row. Returns the shadow result
    (for tests/telemetry), or None when the alert isn't a candidate. Never mutates the
    alert or its disposition."""
    settings = settings or ShadowSettings.from_env()
    decoder = evidence.get("decoder")
    template_hash = evidence.get("template_hash")
    scope = _discriminating_entities(evidence.get("entities"))
    host = _first_value(scope, "host")

    # A specific tuple or nothing: no template hash or no host entity means the shape is
    # too coarse to ever count as "the same routine activity" (§8.3).
    if not template_hash or not host:
        return None

    account = _first_value(scope, "user") or ""
    params: dict[str, Any] = {
        "t": str(tenant_id),
        "src": source,
        "d": decoder,
        "th": template_hash,
        "tv": evidence.get("template_version"),
        "since": ts - timedelta(days=settings.lookback_days),
        "now": ts,
    }
    # Require history to contain EVERY discriminating entity on this alert — one containment
    # clause per entity object (a new or additional destination/process/port/host yields a
    # different, previously-unseen tuple, so it can't inherit another entity's benign history).
    entity_clauses = ""
    for i, ent in enumerate(scope):
        key = f"ent_{i}"
        entity_clauses += f"AND entities @> CAST(:{key} AS JSONB) "
        params[key] = json.dumps([ent])

    seen_days = (
        await db.execute(
            text(
                "SELECT COUNT(DISTINCT date(occurred_at)) FROM alert_source_events "
                "WHERE tenant_id = :t AND source = :src AND decoder = :d "
                "AND template_hash = :th "
                "AND template_version IS NOT DISTINCT FROM :tv "
                "AND occurred_at >= :since AND occurred_at < :now " + entity_clauses
            ),
            params,
        )
    ).scalar_one()

    # History IOC taint (§8.2): if any prior alert on this host carried a threat-intel IOC
    # within the window, the tuple's routine history is not benign — a clean-looking current
    # alert must not close on it. Host-scoped is deliberately conservative for shadow mode
    # (over-excludes rather than misses); the goldens red-team `ioc_sighting` dimension is the
    # false-negative this prevents.
    history_ioc = bool(
        (
            await db.execute(
                text(
                    "SELECT EXISTS (SELECT 1 FROM alerts "
                    "WHERE tenant_id = :t AND initial_iocs <> '[]'::jsonb "
                    "AND asset_ids @> CAST(:host_asset AS JSONB) "
                    "AND first_event_at >= :since AND first_event_at < :now)"
                ),
                {
                    "t": str(tenant_id),
                    "since": params["since"],
                    "now": ts,
                    "host_asset": json.dumps([host]),
                },
            )
        ).scalar_one()
    )

    result = evaluate_shadow(
        seen_days=int(seen_days or 0),
        severity=severity,
        mitre=evidence.get("mitre"),
        initial_iocs=initial_iocs,
        host=host,
        account=account,
        action=decoder or (rule_id or "unknown"),
        ts=ts,
        settings=settings,
        history_ioc=history_ioc,
    )
    result["tuple"] = {
        "source": source,
        "decoder": decoder,
        "template_hash": template_hash,
        "scope": scope,
        "rule_id": rule_id,
    }

    await log_audit(
        db,
        action=AUDIT_ACTION,
        actor_principal="system",
        actor_id="triage",
        tenant_id=tenant_id,
        resource_type="alert",
        resource_id=str(alert_id),
        notes=json.dumps(
            {
                "would_close": result["would_close"],
                "seen_days": result["seen_days"],
                "mature_history": result["mature_history"],
                "excluded": result["excluded"],
                "tuple": result["tuple"],
            },
            sort_keys=True,
        ),
    )
    logger.info(
        "authz_routine_shadow_scored",
        alert_id=str(alert_id),
        would_close=result["would_close"],
        seen_days=result["seen_days"],
        excluded=result["excluded"],
    )
    return result
