"""Learned correlation scorer (issue #30) — hybrid score, review-only.

Suggests entity-overlap attaches the deterministic predicate (#27) misses.
**Review-only**: the deterministic entity match stays the only thing that
auto-attaches; the scorer records suggestions for analyst review until a
labeled offline spike proves its precision (soctalk.evals.correlation).

The score is a weighted combination of deterministic features — no
embeddings required for these (embeddings/pgvector are a separate, flagged
term that plugs in later):

  score = w_e * entity_jaccard(rarity-weighted)
        + w_t * time_decay
        + w_r * rule_cooccurrence(from analyst labels)

Two thresholds: >= theta_attach -> 'suggest' band; [theta_review,
theta_attach) -> 'review' band (would go to the tier-0 adjudicator);
below -> nothing.

Feedback-loop guard: the co-occurrence prior is mined from
``correlation_labels`` (analyst merge/confirm actions), NEVER from the
scorer's own accepted suggestions.
"""

from __future__ import annotations

import math
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

# Strength -> base weight for a shared key (strong keys dominate).
_STRENGTH_WEIGHT = {"strong": 1.0, "conditional": 0.5, "weak": 0.15}


@dataclass(frozen=True)
class ScoreWeights:
    w_entity: float = 0.6
    w_time: float = 0.2
    w_rule: float = 0.2
    theta_attach: float = 0.7
    theta_review: float = 0.4
    time_tau_minutes: float = 120.0


def _weights() -> ScoreWeights:
    def f(name: str, default: float) -> float:
        try:
            return float(os.getenv(name, str(default)))
        except ValueError:
            return default
    return ScoreWeights(
        w_entity=f("SOCTALK_SCORE_W_ENTITY", 0.6),
        w_time=f("SOCTALK_SCORE_W_TIME", 0.2),
        w_rule=f("SOCTALK_SCORE_W_RULE", 0.2),
        theta_attach=f("SOCTALK_SCORE_THETA_ATTACH", 0.7),
        theta_review=f("SOCTALK_SCORE_THETA_REVIEW", 0.4),
        time_tau_minutes=f("SOCTALK_SCORE_TAU_MIN", 120.0),
    )


def entity_jaccard(
    keys_a: list[tuple[str, str, str]],
    keys_b: list[tuple[str, str, str]],
    *,
    rarity: dict[tuple[str, str], float] | None = None,
) -> float:
    """Rarity-weighted Jaccard over typed keys. Each key contributes its
    strength weight times its rarity factor (rare keys weigh more, IDF-like).
    """
    rarity = rarity or {}

    def wt(k: tuple[str, str, str]) -> float:
        kt, kv, strength = k
        return _STRENGTH_WEIGHT.get(strength, 0.15) * rarity.get((kt, kv), 1.0)

    set_a = {(kt, kv): wt((kt, kv, st)) for kt, kv, st in keys_a}
    set_b = {(kt, kv): wt((kt, kv, st)) for kt, kv, st in keys_b}
    if not set_a or not set_b:
        return 0.0
    shared = set_a.keys() & set_b.keys()
    inter = sum(min(set_a[k], set_b[k]) for k in shared)
    union = sum(set_a.values()) + sum(set_b.values()) - inter
    return inter / union if union > 0 else 0.0


def time_decay(alert_ts: datetime, investigation_last: datetime, tau_minutes: float) -> float:
    dt_min = abs((alert_ts - investigation_last).total_seconds()) / 60.0
    return math.exp(-dt_min / max(tau_minutes, 1.0))


@dataclass(frozen=True)
class Suggestion:
    investigation_id: UUID
    score: float
    band: str  # 'suggest' | 'review'
    features: dict[str, Any]


async def _rarity_map(
    db: AsyncSession, tenant_id: UUID, keys: list[tuple[str, str, str]],
) -> dict[tuple[str, str], float]:
    """IDF-like rarity factor per key from entity_key_stats: rarer -> higher."""
    out: dict[tuple[str, str], float] = {}
    for kt, kv, _ in keys:
        seen = (await db.execute(
            text("SELECT seen_count FROM entity_key_stats "
                 "WHERE tenant_id = :t AND key_type = :kt AND key_value = :kv"),
            {"t": str(tenant_id), "kt": kt, "kv": kv},
        )).scalar_one_or_none()
        n = int(seen) if seen else 1
        out[(kt, kv)] = 1.0 / math.log1p(n)  # decays as the key gets common
    return out


async def _rule_cooccurrence(
    db: AsyncSession, tenant_id: UUID, rule_a: str | None, rule_ids_b: set[str],
) -> float:
    """P(rule_a groups with rules_b) from ANALYST labels only (feedback-loop
    guard). Counts merge/confirm labels whose investigations shared rules."""
    if not rule_a or not rule_ids_b:
        return 0.0
    # How often has an analyst confirmed/merged groupings containing rule_a?
    n = (await db.execute(
        text("SELECT count(*) FROM correlation_labels "
             "WHERE tenant_id = :t AND label IN ('merge','confirm')"),
        {"t": str(tenant_id)},
    )).scalar_one()
    # Cheap prior: presence of any analyst-confirmed grouping nudges the score;
    # a real model would key on the rule pair. Bounded to [0, 0.5].
    return min(0.5, 0.1 * math.log1p(int(n)))


async def score_candidate(
    db: AsyncSession, *, tenant_id: UUID,
    alert_keys: list[tuple[str, str, str]], alert_ts: datetime, rule_id: str | None,
    investigation_id: UUID,
) -> Suggestion | None:
    """Score one (alert, candidate investigation) pair. Returns a Suggestion
    if the score reaches the review band, else None."""
    w = _weights()
    inv_keys = (await db.execute(
        text("SELECT key_type, key_value, strength FROM alert_entity_keys "
             "WHERE tenant_id = :t AND investigation_id = :c"),
        {"t": str(tenant_id), "c": str(investigation_id)},
    )).all()
    keys_b = [(r[0], r[1], r[2]) for r in inv_keys]
    if not keys_b:
        return None

    rarity = await _rarity_map(db, tenant_id, alert_keys + keys_b)
    ej = entity_jaccard(alert_keys, keys_b, rarity=rarity)

    inv = (await db.execute(
        text("SELECT updated_at, opened_at FROM investigations "
             "WHERE id = :c AND tenant_id = :t"),
        {"c": str(investigation_id), "t": str(tenant_id)},
    )).mappings().first()
    last = (inv["updated_at"] or inv["opened_at"]) if inv else alert_ts
    if last.tzinfo is None:
        last = last.replace(tzinfo=timezone.utc)
    td = time_decay(alert_ts, last, w.time_tau_minutes)

    rule_ids_b = {kv for kt, kv, _ in keys_b if kt == "rule"}
    rc = await _rule_cooccurrence(db, tenant_id, rule_id, rule_ids_b)

    score = w.w_entity * ej + w.w_time * td + w.w_rule * rc
    features = {"entity_jaccard": round(ej, 4), "time_decay": round(td, 4),
                "rule_cooccurrence": round(rc, 4)}
    if score >= w.theta_attach:
        band = "suggest"
    elif score >= w.theta_review:
        band = "review"
    else:
        return None
    return Suggestion(investigation_id=investigation_id, score=round(score, 4),
                      band=band, features=features)


async def record_suggestion(
    db: AsyncSession, *, tenant_id: UUID, alert_id: UUID, s: Suggestion,
) -> None:
    """Persist a review-only suggestion. NEVER attaches — analyst reviews it."""
    import json
    await db.execute(
        text(
            """
            INSERT INTO correlation_suggestions
              (id, tenant_id, alert_id, suggested_investigation_id, score, band,
               features, status)
            VALUES (:id, :t, :a, :inv, :sc, :band, CAST(:f AS JSONB), 'pending')
            """
        ),
        {"id": str(uuid4()), "t": str(tenant_id), "a": str(alert_id),
         "inv": str(s.investigation_id), "sc": s.score, "band": s.band,
         "f": json.dumps(s.features)},
    )


async def suggest_for_alert(
    db: AsyncSession, *, tenant_id: UUID, alert_id: UUID,
    alert_keys: list[tuple[str, str, str]], alert_ts: datetime, rule_id: str | None,
) -> Suggestion | None:
    """Find the best-scoring active investigation NOT already attached by the
    deterministic predicate, and record a review-only suggestion. Returns the
    top suggestion (or None). Called async in the settle window — never in the
    ingest transaction's critical path once enforced.
    """
    # Candidate active investigations sharing ANY key (the deterministic path
    # only attaches on strong/non-hub keys; the scorer considers the rest).
    if not alert_keys:
        return None
    values = ", ".join(f"(:kt{i}, :kv{i})" for i in range(len(alert_keys)))
    params: dict[str, Any] = {"t": str(tenant_id), "a": str(alert_id)}
    for i, (kt, kv, _) in enumerate(alert_keys):
        params[f"kt{i}"] = kt
        params[f"kv{i}"] = kv
    cand = (await db.execute(
        text(
            f"""
            SELECT DISTINCT k.investigation_id
            FROM alert_entity_keys k
            JOIN investigations i ON i.id = k.investigation_id
            WHERE k.tenant_id = :t AND i.status = 'active'
              AND k.expires_at > now()
              AND k.alert_id <> :a
              AND (k.key_type, k.key_value) IN ({values})
            """
        ),
        params,
    )).scalars().all()

    best: Suggestion | None = None
    for inv_id in cand:
        s = await score_candidate(
            db, tenant_id=tenant_id, alert_keys=alert_keys, alert_ts=alert_ts,
            rule_id=rule_id, investigation_id=UUID(str(inv_id)),
        )
        if s is not None and (best is None or s.score > best.score):
            best = s
    if best is not None:
        await record_suggestion(db, tenant_id=tenant_id, alert_id=alert_id, s=best)
    return best
