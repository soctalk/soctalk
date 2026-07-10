"""Entity-overlap correlation (issue #27).

Extracts typed correlation keys from an alert's entities + IOCs, maintains
the projected ``alert_entity_keys`` index and ``entity_key_stats``
frequency table, and finds an active investigation sharing a high-strength
key (rarity-demoted) to attach to.

Design constraints (from the correlation design + adversarial reviews):
- Keys are a DERIVED, rebuildable projection — never a source of truth.
- Entities stay OUT of ``alert_signature()``/``_reopen_fields()``:
  coalescing and reopen keep keying on asset_ids; correlation keys off
  entities. Deliberate separation.
- Hub keys (a key seen above a per-tenant frequency threshold — corporate
  proxy IP, DNS host) demote to non-attaching. Cold start fails closed:
  with no stats, only intrinsically strong keys (host/hash) attach.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from soctalk.core.ir.events import ioc_fingerprint

# key_type -> strength tier. Strong keys attach on their own; conditional
# keys attach only when not demoted by rarity; weak keys never auto-attach
# (they inform the learned layer later, #30).
_STRENGTH = {
    "host": "strong",
    "hash": "strong",
    "ip": "conditional",
    "domain": "conditional",
    "user": "weak",
    "process": "weak",
    "port": "weak",
    "rule": "weak",
}

# Per-key-type correlation windows (how long a key stays attach-eligible).
_WINDOW_MINUTES = {
    "host": 60,
    "hash": 24 * 60,
    "ip": 6 * 60,
    "domain": 6 * 60,
    "user": 60,
    "process": 30,
    "port": 30,
    "rule": 15,
}

# A key seen on more than this many distinct alerts (per tenant) is a hub —
# demoted to non-attaching. Tunable per tenant later.
_HUB_THRESHOLD = 200


def extract_keys(
    *,
    entities: list[dict[str, Any]] | None,
    initial_iocs: list[dict[str, Any]] | None,
    rule_id: str | None,
) -> list[tuple[str, str, str]]:
    """Return distinct (key_type, key_value, strength) tuples for an alert.

    Entities map their type to a correlation key_type; IOCs contribute
    fingerprinted ip/hash/domain keys; rule_id contributes a weak rule key.
    """
    out: dict[tuple[str, str], str] = {}

    def add(kt: str, kv: str | None) -> None:
        if not kv:
            return
        v = str(kv).strip().lower()
        if v:
            out.setdefault((kt, v), _STRENGTH.get(kt, "weak"))

    for e in entities or []:
        if not isinstance(e, dict):
            continue
        et = e.get("type")
        # entity types already align with key types except we treat host==host
        if et in _STRENGTH:
            add(et, e.get("value"))

    for i in initial_iocs or []:
        if not isinstance(i, dict):
            continue
        t, v = i.get("type"), i.get("value")
        if not (t and v):
            continue
        fp = ioc_fingerprint(t, v)
        if t == "ip":
            add("ip", fp)
        elif t.startswith("hash"):
            add("hash", fp)
        elif t in ("domain", "fqdn"):
            add("domain", fp)

    if rule_id:
        add("rule", rule_id)

    return [(kt, kv, strength) for (kt, kv), strength in out.items()]


async def record_keys(
    db: AsyncSession,
    *,
    tenant_id: UUID,
    alert_id: UUID,
    investigation_id: UUID | None,
    keys: list[tuple[str, str, str]],
    occurred_at,
) -> None:
    """Insert the alert's keys into the projected index and bump stats."""
    for kt, kv, strength in keys:
        window = _WINDOW_MINUTES.get(kt, 30)
        await db.execute(
            text(
                """
                INSERT INTO alert_entity_keys
                  (id, tenant_id, alert_id, investigation_id, key_type,
                   key_value, strength, occurred_at, expires_at)
                VALUES (:id, :t, :a, :c, :kt, :kv, :st,
                        CAST(:occ AS timestamptz),
                        CAST(:occ AS timestamptz) + make_interval(mins => :win))
                """
            ),
            {
                "id": str(uuid4()), "t": str(tenant_id), "a": str(alert_id),
                "c": str(investigation_id) if investigation_id else None,
                "kt": kt, "kv": kv, "st": strength, "occ": occurred_at,
                "win": window,
            },
        )
        await db.execute(
            text(
                """
                INSERT INTO entity_key_stats
                  (tenant_id, key_type, key_value, seen_count, last_seen)
                VALUES (:t, :kt, :kv, 1, now())
                ON CONFLICT (tenant_id, key_type, key_value) DO UPDATE SET
                    seen_count = entity_key_stats.seen_count + 1,
                    last_seen = now()
                """
            ),
            {"t": str(tenant_id), "kt": kt, "kv": kv},
        )


async def find_correlated_investigation(
    db: AsyncSession,
    *,
    tenant_id: UUID,
    keys: list[tuple[str, str, str]],
) -> UUID | None:
    """Find an ACTIVE investigation sharing an attach-eligible key.

    Eligibility: strong keys always; conditional keys unless the key is a
    hub (seen > _HUB_THRESHOLD times for this tenant). Weak keys never
    auto-attach. Returns the oldest matching active investigation, or None.
    """
    candidates = [(kt, kv) for kt, kv, st in keys if st in ("strong", "conditional")]
    if not candidates:
        return None

    # Filter out hub keys (rarity demotion). Strong keys bypass the hub
    # check — a shared file hash is meaningful even if common.
    strong = {(kt, kv) for kt, kv, st in keys if st == "strong"}
    eligible: list[tuple[str, str]] = []
    for kt, kv in candidates:
        if (kt, kv) in strong:
            eligible.append((kt, kv))
            continue
        seen = (
            await db.execute(
                text(
                    "SELECT seen_count FROM entity_key_stats "
                    "WHERE tenant_id = :t AND key_type = :kt AND key_value = :kv"
                ),
                {"t": str(tenant_id), "kt": kt, "kv": kv},
            )
        ).scalar_one_or_none()
        if seen is None or int(seen) <= _HUB_THRESHOLD:
            eligible.append((kt, kv))

    if not eligible:
        return None

    # Query the projected index for an active investigation sharing any
    # eligible key, still within its window, oldest first.
    values = ", ".join(
        f"(:kt{i}, :kv{i})" for i in range(len(eligible))
    )
    params: dict[str, Any] = {"t": str(tenant_id)}
    for i, (kt, kv) in enumerate(eligible):
        params[f"kt{i}"] = kt
        params[f"kv{i}"] = kv

    row = (
        await db.execute(
            text(
                f"""
                SELECT k.investigation_id
                FROM alert_entity_keys k
                JOIN investigations i ON i.id = k.investigation_id
                WHERE k.tenant_id = :t
                  AND i.status = 'active'
                  AND k.expires_at > now()
                  AND (k.key_type, k.key_value) IN ({values})
                ORDER BY i.opened_at ASC
                LIMIT 1
                """
            ),
            params,
        )
    ).scalar_one_or_none()
    return UUID(str(row)) if row else None
