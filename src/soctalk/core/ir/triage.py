"""Wazuh → alert → investigation pipeline.

Responsibilities:

1. Ingest a raw Wazuh event (JSON from the adapter).
2. Compute a coalescing signature and upsert an alert row. Bursts of
   similar events merge into one alert within a 5-minute window.
3. Perform AI assessment — rules-based in MVP, LLM-backed later.
4. Promote to an investigation (or auto-close for high-confidence FPs).

AI assessment in MVP:
  - severity >= 8 → real
  - severity 5-7  → unclear
  - severity 3-4  → likely_fp
  - severity < 3  → high_conf_fp (auto-close if policy allows)

This module emits domain events via the reducer pipeline and writes
audit rows via the execution log. It does not call out to external
services; that lands when we wire the LLM tool registry.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

import structlog
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from soctalk.core.ir.authz_shadow import ShadowSettings, score_alert_shadow, should_score
from soctalk.core.ir.correlation import (
    extract_keys,
    find_correlated_investigation,
    record_keys,
)
from soctalk.core.ir.events import (
    EventKind,
    alert_signature,
    append_event,
    canonical_json,
    ioc_fingerprint,
)
from soctalk.core.ir.graph import land_alert_entities
from soctalk.core.ir.memoization import (
    bump_hit as bump_memo_hit,
)
from soctalk.core.ir.memoization import (
    lookup_memoized_close,
)
from soctalk.core.ir.memoization import (
    shape_key as memo_shape_key,
)
from soctalk.core.ir.policies import effective_policy
from soctalk.core.ir.runtime import active_run_for_case, start_run
from soctalk.core.ir.scorer import suggest_for_alert as suggest_correlation
from soctalk.core.observability.audit import log_audit
from soctalk.playbook.floor import (
    FLOOR_AUDIT_ACTION,
    VETO_ACTIVE_INCIDENT,
    VETO_IOC,
)

logger = structlog.get_logger()


async def _close_floor_veto(
    db: AsyncSession,
    *,
    tenant_id: UUID,
    initial_iocs: list[dict[str, Any]],
    keys: list[tuple[str, str, str]],
    correlation_already_checked: bool,
) -> str | None:
    """Non-overridable safety floor on the ingest auto-close plane (issue #43).

    An alert carrying IOCs, or sharing an attach-eligible entity with an ACTIVE
    investigation, must never be auto-closed — by memoization or by the rules
    band — regardless of policy flags. Returns the veto reason, or None.

    ``correlation_already_checked``: when entity correlation is enabled, the attach
    check already ran this ingest with the same keys and found nothing (a match
    returns before any close path), so the lookup is skipped rather than repeated.
    """
    if initial_iocs:
        return VETO_IOC
    if correlation_already_checked:
        return None
    if await find_correlated_investigation(db, tenant_id=tenant_id, keys=keys) is not None:
        return VETO_ACTIVE_INCIDENT
    return None


async def _audit_floor_veto(
    db: AsyncSession,
    *,
    tenant_id: UUID,
    alert_id: UUID,
    veto: str,
    blocked: str,
) -> None:
    await log_audit(
        db,
        action=FLOOR_AUDIT_ACTION,
        actor_principal="system",
        actor_id="triage",
        tenant_id=tenant_id,
        resource_type="alert",
        resource_id=str(alert_id),
        notes=canonical_json({"veto": veto, "blocked": blocked}),
    )
    logger.warning(
        "close_floor_veto", alert_id=str(alert_id), veto=veto, blocked=blocked
    )


def _evidence_retention_days() -> int:
    """Retention window for raw evidence rows (issue #17 fix 3). Raw logs
    carry PII/secrets even after redaction markers, so they expire; a
    reaper (separate job) deletes rows past retention_until."""
    import os
    try:
        return max(1, int(os.getenv("SOCTALK_EVIDENCE_RETENTION_DAYS", "90")))
    except ValueError:
        return 90


# ---------------------------------------------------------------------------
# Rules-based AI assessment (MVP)
# ---------------------------------------------------------------------------


def assess(
    severity: int,
    rule_id: str | None = None,
    *,
    mitre: dict[str, Any] | None = None,
) -> tuple[str, float]:
    """Return (assessment, confidence).

    Rules-based stub. Replace with LLM-driven assessment later.

    Rule semantics (issue #17 T6): if the rule carries MITRE ATT&CK
    technique/tactic references, never classify it as a high-confidence
    false positive — a technique-mapped detection is by definition not
    obvious noise, so it must not be auto-closed without the LLM looking.
    """

    if severity >= 8:
        return "real", 0.85
    if severity >= 5:
        return "unclear", 0.5

    has_mitre = bool(mitre) and any(
        mitre.get(k) for k in ("ids", "tactics", "techniques")
    )
    if severity >= 3:
        return "likely_fp", 0.75
    if has_mitre:
        # Low severity but technique-mapped — bump out of auto-close range.
        return "unclear", 0.5
    return "high_conf_fp", 0.95


# ---------------------------------------------------------------------------
# Short-ID generation
# ---------------------------------------------------------------------------


async def next_short_id(db: AsyncSession, tenant_id: UUID) -> str:
    """Generate a human-friendly short ID scoped to tenant + year.

    Uses a Postgres sequence for monotonic numbering; we prefix with
    the year for readability.
    """

    n = (
        await db.execute(text("SELECT nextval('investigations_short_id_seq')"))
    ).scalar_one()
    year = datetime.now(UTC).year
    return f"{year}-{int(n):04d}"


# ---------------------------------------------------------------------------
# Alert upsert (coalescing)
# ---------------------------------------------------------------------------


async def upsert_alert(
    db: AsyncSession,
    *,
    tenant_id: UUID,
    source: str,
    rule_id: str | None,
    severity: int,
    asset_ids: list[str],
    initial_iocs: list[dict[str, Any]],
    source_event_id: str,
    ts: datetime,
    mitre: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Upsert an alert row with coalescing.

    Same (rule_id, asset_ids, 5-min bucket) signature:
      - matching ``new`` alert → merge (increment event_count etc.)
      - matching ``promoted`` alert whose investigation is not a closed FP →
        merge into that alert and report ``attached`` so the caller links the
        event to the existing investigation instead of creating a new one
      - matching ``promoted`` alert on a closed-FP investigation → fall
        through (the reopen check owns that path)
    Otherwise insert a new alert.

    A transaction-scoped advisory lock on (tenant, signature) serializes
    concurrent ingests of the same signature — the check-then-insert below
    is racy without it, and a partial unique index alone cannot help because
    promotion moves the row out of ``status='new'`` before commit.
    """

    sig = alert_signature(rule_id, asset_ids, ts)
    await db.execute(
        text("SELECT pg_advisory_xact_lock(hashtext(:t), hashtext(:s))"),
        {"t": str(tenant_id), "s": sig},
    )
    existing = (
        await db.execute(
            text(
                "SELECT id, event_count, source_event_ids, asset_ids, initial_iocs "
                "FROM alerts "
                "WHERE tenant_id = :t AND signature = :s AND status = 'new' "
                "LIMIT 1"
            ),
            {"t": str(tenant_id), "s": sig},
        )
    ).mappings().first()

    attached_investigation_id: UUID | None = None
    if existing is None:
        # No open alert — a duplicate of an already-promoted alert should
        # become evidence on its investigation, not a brand-new case.
        promoted = (
            await db.execute(
                text(
                    "SELECT a.id, a.event_count, a.source_event_ids, "
                    "       a.asset_ids, a.initial_iocs, a.investigation_id, "
                    "       i.status AS investigation_status "
                    "FROM alerts a "
                    "JOIN investigations i ON i.id = a.investigation_id "
                    "WHERE a.tenant_id = :t AND a.signature = :s "
                    "  AND a.status = 'promoted' "
                    "  AND a.investigation_id IS NOT NULL "
                    "ORDER BY a.last_event_at DESC "
                    "LIMIT 1"
                ),
                {"t": str(tenant_id), "s": sig},
            )
        ).mappings().first()
        if promoted is not None and promoted["investigation_status"] != "auto_closed_fp":
            existing = promoted
            attached_investigation_id = UUID(str(promoted["investigation_id"]))

    if existing:
        event_ids = list(existing["source_event_ids"] or []) + [source_event_id]
        asset_list = sorted(
            set(list(existing["asset_ids"] or []) + asset_ids)
        )
        ioc_list = list(existing["initial_iocs"] or []) + initial_iocs
        await db.execute(
            text(
                "UPDATE alerts SET event_count = event_count + 1, "
                "       last_event_at = :ts, "
                "       source_event_ids = CAST(:eids AS JSONB), "
                "       asset_ids = CAST(:aids AS JSONB), "
                "       initial_iocs = CAST(:iocs AS JSONB) "
                "WHERE id = :id"
            ),
            {
                "id": str(existing["id"]),
                "ts": ts,
                "eids": canonical_json(event_ids),
                "aids": canonical_json(asset_list),
                "iocs": canonical_json(ioc_list),
            },
        )
        return {
            "id": UUID(str(existing["id"])),
            "merged": attached_investigation_id is None,
            "attached": attached_investigation_id is not None,
            "investigation_id": attached_investigation_id,
            "event_count": (existing["event_count"] or 0) + 1,
        }

    # Fresh insert.
    alert_id = uuid4()
    assessment, confidence = assess(severity, rule_id, mitre=mitre)
    await db.execute(
        text(
            """
            INSERT INTO alerts
              (id, tenant_id, source, rule_id, severity, signature,
               first_event_at, last_event_at, event_count,
               source_event_ids, asset_ids, initial_iocs,
               ai_assessment, ai_confidence, status, visibility)
            VALUES
              (:id, :t, :src, :rid, :sev, :sig,
               :ts, :ts, 1,
               CAST(:eids AS JSONB), CAST(:aids AS JSONB), CAST(:iocs AS JSONB),
               :a, :c, 'new', 'mssp_only')
            """
        ),
        {
            "id": str(alert_id),
            "t": str(tenant_id),
            "src": source,
            "rid": rule_id,
            "sev": severity,
            "sig": sig,
            "ts": ts,
            "eids": canonical_json([source_event_id]),
            "aids": canonical_json(asset_ids),
            "iocs": canonical_json(initial_iocs),
            "a": assessment,
            "c": confidence,
        },
    )
    return {"id": alert_id, "merged": False, "attached": False, "event_count": 1}


# ---------------------------------------------------------------------------
# Case promotion
# ---------------------------------------------------------------------------


async def promote_alert_to_case(
    db: AsyncSession,
    *,
    tenant_id: UUID,
    alert_id: UUID,
    title: str | None = None,
    settle_seconds: float = 0.0,
) -> UUID:
    """Create an investigation from an alert, emit alert_ingested, start a run.

    ``settle_seconds`` delays the run's claimability (issue #28 settle
    window) so correlated events landing right after this promotion attach
    to the investigation before the first LLM look.
    """

    alert = (
        await db.execute(
            text(
                "SELECT source, rule_id, severity, asset_ids, initial_iocs, "
                "       source_event_ids, ai_confidence, first_event_at "
                "FROM alerts WHERE id = :id"
            ),
            {"id": str(alert_id)},
        )
    ).mappings().first()
    if alert is None:
        raise ValueError(f"alert {alert_id} not found")

    # Initial visibility per install/tenant policy. ``auto`` mode
    # makes the investigation visible to the tenant immediately (right default
    # for the wholesale flow); ``explicit`` / ``disabled`` keep it
    # ``mssp_only`` until an analyst promotes it.
    policy = await effective_policy(db, tenant_id)
    initial_visibility = (
        "customer_safe"
        if policy.get("customer_safe_promotion") == "auto"
        else "mssp_only"
    )

    investigation_id = uuid4()
    short_id = await next_short_id(db, tenant_id)
    case_title = title or f"Alert from {alert['source']} rule {alert['rule_id'] or '?'}"

    await db.execute(
        text(
            """
            INSERT INTO investigations
              (id, tenant_id, short_id, title, status, severity,
               opened_at, visibility)
            VALUES
              (:id, :t, :sid, :title, 'active', :sev, :ts, :vis)
            """
        ),
        {
            "id": str(investigation_id),
            "t": str(tenant_id),
            "sid": short_id,
            "title": case_title,
            "sev": alert["severity"],
            "ts": alert["first_event_at"],
            "vis": initial_visibility,
        },
    )

    # Attach IOCs from the alert to the investigation.
    for ioc in list(alert["initial_iocs"] or []):
        if not isinstance(ioc, dict) or "type" not in ioc or "value" not in ioc:
            continue
        fp = ioc_fingerprint(ioc["type"], ioc["value"])
        ioc_id = uuid4()
        # Upsert the IOC (tenant-scoped).
        await db.execute(
            text(
                """
                INSERT INTO iocs (id, tenant_id, type, value, fingerprint,
                                  tlp, pap, visibility)
                VALUES (:id, :t, :type, :val, :fp, 'amber', 'amber', 'mssp_only')
                ON CONFLICT (tenant_id, fingerprint) DO UPDATE
                  SET last_seen = now()
                RETURNING id
                """
            ),
            {
                "id": str(ioc_id),
                "t": str(tenant_id),
                "type": ioc["type"],
                "val": ioc["value"],
                "fp": fp,
            },
        )
        # Re-read the id (might be existing).
        existing = (
            await db.execute(
                text("SELECT id FROM iocs WHERE tenant_id = :t AND fingerprint = :f"),
                {"t": str(tenant_id), "f": fp},
            )
        ).scalar_one()
        await db.execute(
            text(
                "INSERT INTO investigation_iocs (tenant_id, investigation_id, ioc_id, added_by) "
                "VALUES (:t, :c, :i, 'ai') "
                "ON CONFLICT DO NOTHING"
            ),
            {"t": str(tenant_id), "c": str(investigation_id), "i": str(existing)},
        )

    # Link to the alert.
    await db.execute(
        text(
            "UPDATE alerts SET status = 'promoted', investigation_id = :c WHERE id = :id"
        ),
        {"c": str(investigation_id), "id": str(alert_id)},
    )

    # Start a run for the investigation (delayed by the settle window).
    run_id = await start_run(db, tenant_id, investigation_id, settle_seconds=settle_seconds)

    # Emit alert_ingested event so the reducer seeds the hypothesis.
    await append_event(
        db,
        tenant_id=tenant_id,
        investigation_id=investigation_id,
        run_id=run_id,
        kind=EventKind.ALERT_INGESTED,
        payload={
            "alert_id": str(alert_id),
            "source_events": list(alert["source_event_ids"] or []),
            "asset_ids": list(alert["asset_ids"] or []),
            "initial_iocs": list(alert["initial_iocs"] or []),
            "rule_id": alert["rule_id"],
            "severity": alert["severity"],
            "ai_confidence": alert["ai_confidence"],
            "initial_hypothesis": "under_investigation",
        },
        producer="triage",
    )
    await log_audit(
        db,
        action="ir.investigation.created_from_alert",
        actor_principal="system",
        actor_id="triage",
        tenant_id=tenant_id,
        resource_type="investigation",
        resource_id=str(investigation_id),
    )
    return investigation_id


def _reopen_fields(
    *,
    rule_ids: list[str],
    asset_ids: list[str],
    initial_iocs: list[dict[str, Any]],
    window_start: datetime,
    reopen_window_days: int,
) -> tuple[str, datetime]:
    """Build (reopen_signature JSON, reopen_window_until) from alert facts.

    Shared by every path that closes an investigation as a false positive —
    rules-based auto-close, worker ``close_fp`` verdicts, and analyst
    rejects — so all of them stay resurrectable by ``_check_and_reopen``.
    """
    ioc_fps = [
        ioc_fingerprint(i["type"], i["value"])
        for i in initial_iocs
        if isinstance(i, dict) and i.get("type") and i.get("value")
    ]
    sig = {
        "ioc_fingerprints": ioc_fps,
        "asset_ids": asset_ids,
        "rule_ids": rule_ids,
        "time_window": {
            "start": window_start.isoformat(),
            "end": (window_start + timedelta(days=reopen_window_days)).isoformat(),
        },
    }
    reopen_until = datetime.now(UTC) + timedelta(days=reopen_window_days)
    return canonical_json(sig), reopen_until


async def build_reopen_fields_for_investigation(
    db: AsyncSession,
    *,
    tenant_id: UUID,
    investigation_id: UUID,
    reopen_window_days: int,
) -> tuple[str, datetime]:
    """Union rule/asset/IOC facts across every alert linked to an investigation.

    Anchored at the earliest ``first_event_at``. Falls back to now() if the
    investigation somehow has no linked alerts.
    """
    rows = (
        await db.execute(
            text(
                "SELECT rule_id, asset_ids, initial_iocs, first_event_at "
                "FROM alerts "
                "WHERE tenant_id = :t AND investigation_id = :c "
                "ORDER BY first_event_at"
            ),
            {"t": str(tenant_id), "c": str(investigation_id)},
        )
    ).mappings().all()

    rule_ids: dict[str, None] = {}
    asset_ids: dict[str, None] = {}
    iocs: list[dict[str, Any]] = []
    for r in rows:
        if r["rule_id"]:
            rule_ids.setdefault(r["rule_id"])
        for a in list(r["asset_ids"] or []):
            asset_ids.setdefault(a)
        iocs.extend(list(r["initial_iocs"] or []))
    window_start = rows[0]["first_event_at"] if rows else datetime.now(UTC)

    return _reopen_fields(
        rule_ids=list(rule_ids),
        asset_ids=list(asset_ids),
        initial_iocs=iocs,
        window_start=window_start,
        reopen_window_days=reopen_window_days,
    )


async def auto_close_alert(
    db: AsyncSession,
    *,
    tenant_id: UUID,
    alert_id: UUID,
    reason: str,
    reopen_window_days: int = 30,
) -> UUID:
    """Auto-close an alert as a FP. Creates a closed investigation for the audit trail
    with a reopen signature so future matching events can reopen it."""

    alert = (
        await db.execute(
            text(
                "SELECT rule_id, severity, asset_ids, initial_iocs, "
                "       first_event_at, source "
                "FROM alerts WHERE id = :id"
            ),
            {"id": str(alert_id)},
        )
    ).mappings().first()
    if alert is None:
        raise ValueError(f"alert {alert_id} not found")

    investigation_id = uuid4()
    short_id = await next_short_id(db, tenant_id)
    sig_json, reopen_until = _reopen_fields(
        rule_ids=[alert["rule_id"]] if alert["rule_id"] else [],
        asset_ids=list(alert["asset_ids"] or []),
        initial_iocs=list(alert["initial_iocs"] or []),
        window_start=alert["first_event_at"],
        reopen_window_days=reopen_window_days,
    )

    await db.execute(
        text(
            """
            INSERT INTO investigations
              (id, tenant_id, short_id, title, status, severity,
               opened_at, closed_at, close_reason,
               reopen_window_until, reopen_signature, visibility)
            VALUES
              (:id, :t, :sid, :title, 'auto_closed_fp', :sev,
               :ts, now(), :reason,
               :reopen_until, CAST(:sig AS JSONB), 'mssp_only')
            """
        ),
        {
            "id": str(investigation_id),
            "t": str(tenant_id),
            "sid": short_id,
            "title": f"Auto-closed FP: {alert['source']} rule {alert['rule_id'] or '?'}",
            "sev": alert["severity"],
            "ts": alert["first_event_at"],
            "reason": reason,
            "reopen_until": reopen_until,
            "sig": sig_json,
        },
    )
    await db.execute(
        text("UPDATE alerts SET status = 'auto_closed', investigation_id = :c WHERE id = :id"),
        {"c": str(investigation_id), "id": str(alert_id)},
    )
    await log_audit(
        db,
        action="ir.investigation.auto_closed",
        actor_principal="system",
        actor_id="triage",
        tenant_id=tenant_id,
        resource_type="investigation",
        resource_id=str(investigation_id),
        notes=reason,
    )
    return investigation_id


# ---------------------------------------------------------------------------
# Main triage entry point
# ---------------------------------------------------------------------------


async def triage_event(
    db: AsyncSession,
    *,
    tenant_id: UUID,
    source: str,
    rule_id: str | None,
    severity: int,
    asset_ids: list[str],
    initial_iocs: list[dict[str, Any]],
    source_event_id: str,
    ts: datetime | None = None,
    description: str | None = None,
    title: str | None = None,
    evidence: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Main triage entry: raw event → alert → investigation or auto-close.

    Returns a dict with alert_id and investigation_id (if promoted / closed).

    ``evidence`` carries the optional schema-v2 sidecar (entities, mitre,
    rule_groups, decoder, redacted full_log, template hash, observed_at)
    persisted to ``alert_source_events`` — which also enforces
    idempotency: a replayed ``(tenant, source, source_event_id)`` no-ops
    without touching coalescing counters.
    """

    ts = ts or datetime.now(UTC)
    evidence = evidence or {}

    # 0. Idempotency gate (issue #17 fix 7). Reserve the source-event key
    #    up front; a conflict means we've already processed this event, so
    #    return a clean no-op WITHOUT running triage (no event_count
    #    inflation, no attach event, no duplicate investigation).
    reserved = (
        await db.execute(
            text(
                """
                INSERT INTO alert_source_events
                  (id, tenant_id, source, source_event_id,
                   occurred_at, observed_at,
                   description_redacted, full_log_redacted, entities, mitre,
                   rule_groups, decoder, template_hash, template_version,
                   redaction_version, schema_version, batch_seq,
                   retention_until)
                VALUES
                  (:id, :t, :src, :seid,
                   :occurred, :observed,
                   :desc, :full_log, CAST(:entities AS JSONB), CAST(:mitre AS JSONB),
                   CAST(:rule_groups AS JSONB), :decoder, :thash, :tver,
                   :rver, :sver, :bseq,
                   now() + make_interval(days => :retention_days))
                ON CONFLICT (tenant_id, source, source_event_id) DO NOTHING
                RETURNING id
                """
            ),
            {
                "id": str(uuid4()),
                "t": str(tenant_id),
                "src": source,
                "seid": source_event_id,
                "occurred": ts,
                "observed": evidence.get("observed_at"),
                "desc": (description or None),
                "full_log": evidence.get("full_log"),
                "entities": canonical_json(evidence.get("entities", [])),
                "mitre": canonical_json(evidence.get("mitre", {})),
                "rule_groups": canonical_json(evidence.get("rule_groups", [])),
                "decoder": evidence.get("decoder"),
                "thash": evidence.get("template_hash"),
                "tver": evidence.get("template_version"),
                "rver": evidence.get("redaction_version"),
                "sver": evidence.get("schema_version", 1),
                "bseq": evidence.get("batch_seq"),
                "retention_days": _evidence_retention_days(),
            },
        )
    ).first()
    if reserved is None:
        return {"action": "duplicate", "source_event_id": source_event_id}
    source_event_row_id = reserved[0]

    # 1. Upsert alert with coalescing.
    alert_result = await upsert_alert(
        db,
        tenant_id=tenant_id,
        source=source,
        rule_id=rule_id,
        severity=severity,
        asset_ids=asset_ids,
        initial_iocs=initial_iocs,
        source_event_id=source_event_id,
        ts=ts,
        mitre=evidence.get("mitre"),
    )
    alert_id = alert_result["id"]

    # Link the source-event row to its alert.
    await db.execute(
        text("UPDATE alert_source_events SET alert_id = :a WHERE id = :id"),
        {"a": str(alert_id), "id": str(source_event_row_id)},
    )

    if description and not alert_result["merged"] and not alert_result.get("attached"):
        # Persist the human-readable line into the alert's dedicated
        # description column (issue #17 fix 3 — no longer clobbering
        # ai_assessment, which holds the rules-based assess() label).
        await db.execute(
            text("UPDATE alerts SET description = :d WHERE id = :id"),
            {"d": description[:1024], "id": str(alert_id)},
        )

    # Coalesced into existing → no new investigation action.
    if alert_result["merged"]:
        return {"alert_id": str(alert_id), "action": "merged"}

    # Duplicate of an already-promoted alert → the event becomes evidence
    # on the existing investigation's alert row. Never starts a run. Note:
    # a LIVE run does NOT see this update — the worker snapshots graph
    # state once before invocation — so mid-run recurrence is picked up by
    # the follow-up-run mechanism, not by mutating the running graph.
    if alert_result.get("attached"):
        attached_case_id = alert_result["investigation_id"]
        await append_event(
            db,
            tenant_id=tenant_id,
            investigation_id=attached_case_id,
            run_id=None,
            kind=EventKind.ALERT_INGESTED,
            payload={
                "alert_id": str(alert_id),
                "coalesced": True,
                "event_count": alert_result.get("event_count"),
                "source_event_id": source_event_id,
                "rule_id": rule_id,
                "severity": severity,
                "asset_ids": asset_ids,
            },
            idempotency_key=f"attach-{alert_id}-{source_event_id}",
            producer="triage",
        )
        # Follow-up flag (review #2): a live run snapshotted before this
        # recurrence — mark for a follow-up run at completion.
        if await active_run_for_case(db, attached_case_id) is not None:
            await db.execute(
                text("UPDATE investigations SET has_new_evidence = true "
                     "WHERE id = :c AND tenant_id = :t"),
                {"c": str(attached_case_id), "t": str(tenant_id)},
            )
        await log_audit(
            db,
            action="ir.investigation.alert_attached",
            actor_principal="system",
            actor_id="triage",
            tenant_id=tenant_id,
            resource_type="investigation",
            resource_id=str(attached_case_id),
            notes=f"duplicate signature event {source_event_id} attached",
        )
        return {
            "alert_id": str(alert_id),
            "investigation_id": str(attached_case_id),
            "action": "attached",
            "event_count": alert_result.get("event_count"),
        }

    # 2. Check reopen signatures first — a matching event on an auto-closed
    #    investigation re-opens rather than creating a new one.
    reopened_case_id = await _check_and_reopen(
        db,
        tenant_id=tenant_id,
        asset_ids=asset_ids,
        ioc_values=[(i["type"], i["value"]) for i in initial_iocs
                    if isinstance(i, dict) and i.get("type") and i.get("value")],
        rule_id=rule_id,
        ts=ts,
    )
    if reopened_case_id is not None:
        # attach this alert to the reopened investigation.
        await db.execute(
            text(
                "UPDATE alerts SET status = 'promoted', investigation_id = :c WHERE id = :id"
            ),
            {"c": str(reopened_case_id), "id": str(alert_id)},
        )
        return {
            "alert_id": str(alert_id),
            "investigation_id": str(reopened_case_id),
            "action": "reopened",
        }

    # 3. Decide based on AI assessment + policy. Rule semantics (MITRE) can
    #    veto a high-confidence-FP auto-close (issue #17 T6).
    assessment, confidence = assess(severity, rule_id, mitre=evidence.get("mitre"))
    policy = await effective_policy(db, tenant_id)
    keys = extract_keys(
        entities=evidence.get("entities"),
        initial_iocs=initial_iocs,
        rule_id=rule_id,
    )

    # 3. Entity-overlap correlation (issue #27): a real alert that shares a
    #    high-strength, non-hub typed entity with an ACTIVE investigation
    #    attaches to it — inserted-and-linked. This runs BEFORE memoized-close
    #    and auto-close (review finding #1): an alert whose shape is normally
    #    benign but which shares an entity with a LIVE incident right now must
    #    correlate, not be suppressed. If the target has a live run, flag it
    #    for a follow-up run (the run already snapshotted its alerts).
    if policy.get("entity_correlation_enabled", False):
        correlated_id = await find_correlated_investigation(
            db, tenant_id=tenant_id, keys=keys
        )
        if correlated_id is not None:
            await db.execute(
                text(
                    "UPDATE alerts SET status = 'promoted', investigation_id = :c "
                    "WHERE id = :id"
                ),
                {"c": str(correlated_id), "id": str(alert_id)},
            )
            await record_keys(
                db, tenant_id=tenant_id, alert_id=alert_id,
                investigation_id=correlated_id, keys=keys, occurred_at=ts,
            )
            await append_event(
                db,
                tenant_id=tenant_id,
                investigation_id=correlated_id,
                run_id=None,
                kind=EventKind.ALERT_INGESTED,
                payload={
                    "alert_id": str(alert_id),
                    "correlated": True,
                    "source_event_id": source_event_id,
                    "rule_id": rule_id,
                    "severity": severity,
                    "asset_ids": asset_ids,
                },
                idempotency_key=f"corr-{alert_id}-{source_event_id}",
                producer="triage",
            )
            # Follow-up run (review finding #2): if a run is already live on
            # this investigation it snapshotted its alerts before this one
            # arrived, so flag the investigation — complete_run starts a
            # fresh run when the current one finishes if evidence arrived.
            if await active_run_for_case(db, correlated_id) is not None:
                await db.execute(
                    text("UPDATE investigations SET has_new_evidence = true "
                         "WHERE id = :c AND tenant_id = :t"),
                    {"c": str(correlated_id), "t": str(tenant_id)},
                )
            await log_audit(
                db,
                action="ir.investigation.alert_correlated",
                actor_principal="system",
                actor_id="triage",
                tenant_id=tenant_id,
                resource_type="investigation",
                resource_id=str(correlated_id),
                notes=f"entity-overlap attach of alert {alert_id}",
            )
            if policy.get("entity_graph_enabled", False):
                await land_alert_entities(
                    db, tenant_id=tenant_id, alert_id=alert_id,
                    investigation_id=correlated_id,
                    entities=evidence.get("entities"), mitre=evidence.get("mitre"),
                    occurred_at=ts, source_event_id=source_event_id,
                )
            return {
                "alert_id": str(alert_id),
                "investigation_id": str(correlated_id),
                "action": "correlated",
            }

    # 3b. Authorization routine scoring (epic M2) — SHADOW ONLY. Scores whether
    #     SIEM-derived routine history would authorize-close this alert and logs
    #     the would-close decision; it NEVER changes the disposition. Placed
    #     after entity correlation (§8.2: a live-incident alert must correlate,
    #     never be counted routine) and behind kill switch + family allowlist +
    #     per-tenant policy flag. Everything (incl. settings construction) is
    #     inside the guard so a scoring failure can never block ingest.
    _shadow_settings = ShadowSettings.from_env()  # fail-closed; never raises
    _routine_eligible = should_score(_shadow_settings, policy, evidence.get("decoder"))
    _routine_result: dict[str, Any] | None = None
    if _routine_eligible:
        try:
            _routine_result = await score_alert_shadow(
                db, tenant_id=tenant_id, source=source, rule_id=rule_id,
                severity=severity, initial_iocs=initial_iocs, evidence=evidence,
                ts=ts, alert_id=alert_id, settings=_shadow_settings,
            )
        except Exception as e:  # noqa: BLE001 — shadow scoring must never block ingest
            logger.warning("authz_routine_shadow_failed", error=str(e))

    # Safety floor over BOTH ingest auto-close paths below (issue #43): IOC or
    # active-incident overlap vetoes the close and the alert falls through to
    # promotion — a real triage run looks at it instead of a silent close.
    _correlation_checked = bool(policy.get("entity_correlation_enabled", False))

    # 3a. Verdict memoization (issue #29): a recurring high-confidence-FP
    #     shape closes by reference — AFTER the entity-correlation check so it
    #     can never suppress an alert that belongs to a live incident.
    memo_replay_denied = False
    if policy.get("verdict_memoization_enabled", False):
        mkey = memo_shape_key(
            source=source,
            decoder=evidence.get("decoder"),
            template_hash=evidence.get("template_hash"),
            template_version=evidence.get("template_version"),
        )
        if mkey is not None:
            memo = await lookup_memoized_close(db, tenant_id=tenant_id, key=mkey)
            if memo is not None:
                # Two guards compose over the memo replay, strongest first:
                # (1) the non-overridable safety FLOOR (issue #43): IOC or active-incident
                #     overlap vetoes any close regardless of policy — falls through to a run.
                # (2) the opt-in AUTHORIZATION-AWARE gate: the memo key is source-blind
                #     (source|decoder|template_hash|version), so a cached benign-close for a
                #     template must not replay onto a different source sharing it (a scanner's
                #     routine close vs an attacker's identical shape from a new IP). When
                #     enabled, the replay is applied ONLY if the CURRENT alert independently
                #     passes source-aware routine authorization (deterministic would_close on
                #     its specific entity tuple). Reuses 3b's routine result, present exactly
                #     when routine scoring was eligible (should_score) — a killed / ineligible /
                #     non-candidate / non-would_close alert is DENIED, never replayed. A denial
                #     also suppresses the cruder high-conf-FP fallback below, so authz still
                #     protects the low-severity attacker-shares-template case.
                veto = await _close_floor_veto(
                    db, tenant_id=tenant_id, initial_iocs=initial_iocs,
                    keys=keys, correlation_already_checked=_correlation_checked,
                )
                if veto is not None:
                    await _audit_floor_veto(
                        db, tenant_id=tenant_id, alert_id=alert_id,
                        veto=veto, blocked="memoized_close",
                    )
                    # floored → fall through (high-conf-FP path re-checks the same floor)
                else:
                    authz_basis = ""
                    replay_ok = True
                    if policy.get("authz_aware_memoization", False):
                        routine = _routine_result if _routine_eligible else None
                        if not (routine and routine.get("would_close")):
                            await log_audit(
                                db,
                                action="ir.verdict_memoization.replay_denied",
                                actor_principal="system",
                                actor_id="triage",
                                tenant_id=tenant_id,
                                resource_type="alert",
                                resource_id=str(alert_id),
                                notes=canonical_json(
                                    {
                                        "shape_key": mkey,
                                        "memo_confidence": memo["confidence"],
                                        "reason": "routine_authorization_denied",
                                        "routine_eligible": _routine_eligible,
                                        "seen_days": (routine or {}).get("seen_days"),
                                        "excluded": (routine or {}).get("excluded"),
                                        "tuple": (routine or {}).get("tuple"),
                                    }
                                ),
                            )
                            memo_replay_denied = True  # also blocks the high-conf-FP fallback
                            replay_ok = False
                        else:
                            authz_basis = (
                                f"; routine seen_days={routine['seen_days']} "
                                f"scope={routine['tuple']['scope']}"
                            )
                    if replay_ok:
                        investigation_id = await auto_close_alert(
                            db,
                            tenant_id=tenant_id,
                            alert_id=alert_id,
                            reason=(
                                f"memoized-fp: prior verdict close "
                                f"confidence={memo['confidence']:.2f}{authz_basis}"
                            ),
                            reopen_window_days=policy.get("reopen_window_days", 30),
                        )
                        await bump_memo_hit(db, tenant_id=tenant_id, key=mkey)
                        return {
                            "alert_id": str(alert_id),
                            "investigation_id": str(investigation_id),
                            "action": "memoized_close",
                        }

    if (
        assessment == "high_conf_fp"
        and not memo_replay_denied  # authz-denied replay must route to the LLM, not this fallback
        and policy.get("auto_close_enabled", True)
        and confidence >= policy.get("auto_close_threshold", 0.90)
    ):
        veto = await _close_floor_veto(
            db, tenant_id=tenant_id, initial_iocs=initial_iocs,
            keys=keys, correlation_already_checked=_correlation_checked,
        )
        if veto is not None:
            await _audit_floor_veto(
                db, tenant_id=tenant_id, alert_id=alert_id,
                veto=veto, blocked="rules_auto_close",
            )
        else:
            investigation_id = await auto_close_alert(
                db,
                tenant_id=tenant_id,
                alert_id=alert_id,
                reason=f"auto-close: {assessment} confidence={confidence:.2f}",
                reopen_window_days=policy.get("reopen_window_days", 30),
            )
            return {
                "alert_id": str(alert_id),
                "investigation_id": str(investigation_id),
                "action": "auto_closed",
            }

    # 4a. Learned scorer (issue #30) — REVIEW-ONLY. The deterministic
    #     entity-attach above didn't fire; if the scorer is enabled, record a
    #     suggestion for any active investigation it thinks this alert belongs
    #     to. It NEVER attaches — an analyst reviews the suggestion, and the
    #     scorer only earns enforcement after the offline spike gate proves
    #     its precision (soctalk.evals.correlation).
    if policy.get("correlation_scorer_enabled", False):
        try:
            await suggest_correlation(
                db, tenant_id=tenant_id, alert_id=alert_id,
                alert_keys=keys, alert_ts=ts, rule_id=rule_id,
            )
        except Exception as e:  # noqa: BLE001 — a scorer miss must never block ingest
            logger.warning("correlation_scorer_failed", error=str(e))

    # 5. All other bands: create an investigation. Apply the settle window
    # (issue #28) unless the alert is high-severity, which claims
    # immediately — we don't trade latency for batching on critical alerts.
    settle_seconds = (
        0.0
        if severity >= policy.get("settle_bypass_severity", 12)
        else float(policy.get("settle_window_seconds", 0))
    )
    investigation_id = await promote_alert_to_case(
        db, tenant_id=tenant_id, alert_id=alert_id, title=title,
        settle_seconds=settle_seconds,
    )
    await record_keys(
        db, tenant_id=tenant_id, alert_id=alert_id,
        investigation_id=investigation_id, keys=keys, occurred_at=ts,
    )
    if policy.get("entity_graph_enabled", False):
        await land_alert_entities(
            db, tenant_id=tenant_id, alert_id=alert_id,
            investigation_id=investigation_id,
            entities=evidence.get("entities"), mitre=evidence.get("mitre"),
            occurred_at=ts, source_event_id=source_event_id,
        )
    return {
        "alert_id": str(alert_id),
        "investigation_id": str(investigation_id),
        "action": "promoted",
        "assessment": assessment,
    }


async def _check_and_reopen(
    db: AsyncSession,
    *,
    tenant_id: UUID,
    asset_ids: list[str],
    ioc_values: list[tuple[str, str]],
    rule_id: str | None,
    ts: datetime,
) -> UUID | None:
    """Look for an auto-closed investigation whose reopen_signature matches, and reopen it."""

    ioc_fps = [ioc_fingerprint(t, v) for t, v in ioc_values]
    # Any-of match: shared asset OR shared IOC OR shared rule, within window.
    rows = (
        await db.execute(
            text(
                """
                SELECT id, tenant_id, reopen_signature
                FROM investigations
                WHERE tenant_id = :t
                  AND status = 'auto_closed_fp'
                  AND reopen_window_until > :ts
                """
            ),
            {"t": str(tenant_id), "ts": ts},
        )
    ).mappings().all()

    for row in rows:
        sig = dict(row["reopen_signature"] or {})
        sig_assets = set(sig.get("asset_ids") or [])
        sig_iocs = set(sig.get("ioc_fingerprints") or [])
        sig_rules = set(sig.get("rule_ids") or [])

        if (
            (sig_assets & set(asset_ids))
            or (sig_iocs & set(ioc_fps))
            or (rule_id and rule_id in sig_rules)
        ):
            investigation_id = UUID(str(row["id"]))
            # Reopen the investigation.
            await db.execute(
                text(
                    "UPDATE investigations SET status = 'active', closed_at = NULL, "
                    "       reopen_count = reopen_count + 1, updated_at = now() "
                    "WHERE id = :id"
                ),
                {"id": str(investigation_id)},
            )
            # Start a fresh run — unless a live one still exists (e.g. the
            # investigation was analyst-rejected while its run was active,
            # or is parked on HIL/budget). uq_investigation_runs_single_active
            # forbids a second live run; the existing run simply continues
            # with the reopened investigation's accumulated evidence.
            run_id = await active_run_for_case(db, investigation_id)
            if run_id is None:
                run_id = await start_run(db, tenant_id, investigation_id)
            await append_event(
                db,
                tenant_id=tenant_id,
                investigation_id=investigation_id,
                run_id=run_id,
                kind=EventKind.REOPENED,
                payload={"reason": "matching event during reopen window"},
                producer="triage",
            )
            await log_audit(
                db,
                action="ir.investigation.reopened",
                actor_principal="system",
                actor_id="triage",
                tenant_id=tenant_id,
                resource_type="investigation",
                resource_id=str(investigation_id),
            )
            return investigation_id
    return None


__all__ = [
    "assess",
    "auto_close_alert",
    "build_reopen_fields_for_investigation",
    "next_short_id",
    "promote_alert_to_case",
    "triage_event",
    "upsert_alert",
]
