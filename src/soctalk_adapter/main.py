"""SocTalk per-tenant adapter — heartbeat + Wazuh alert ingest to L1."""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import re
import time
from dataclasses import dataclass
from datetime import UTC, datetime, timezone
from pathlib import Path

import httpx
from fastapi import FastAPI

from soctalk_wire import (
    REDACTION_VERSION,
    SCHEMA_VERSION,
    TEMPLATE_VERSION,
    redact_text,
    template_hash,
)

logger = logging.getLogger("soctalk.adapter")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

VERSION = "0.2.2"

# Startup durable-checkpoint load: retry with a freshly read token so a token
# renewed just after pod start (see token_renewal) is picked up before we
# ingest from a stale local cursor. ~60s total covers Secret projection; a
# no-checkpoint tenant returns 200 (empty) and loads on the first try.
CHECKPOINT_LOAD_MAX_ATTEMPTS = 10
CHECKPOINT_LOAD_RETRY_SECONDS = 6.0

# Health reported on the heartbeat. ``failing`` after this many consecutive
# failed polls; one or two are ``degraded`` (a transient indexer/API blip).
POLL_FAILING_THRESHOLD = 3
# A poll loop that has not completed a poll for this long is ``failing`` even
# if no error was recorded (hung request, wedged loop, stuck at startup). The
# effective window is max(this, 3 x the ingest interval).
POLL_STALE_MIN_SECONDS = 120.0


def _read_token() -> str:
    path = Path(os.environ.get("ADAPTER_TOKEN_PATH", "/run/secrets/adapter/token"))
    return path.read_text().strip()


def _initial_alert_ts() -> str:
    """Initial cursor for alert ingestion.

    Defaults to epoch (full backfill). Set SOCTALK_INGEST_INITIAL_TS to
    an ISO-8601 timestamp to start ingesting from a specific point, or
    to the literal string ``"now"`` to skip backfill entirely (start
    from the moment the adapter boots).
    """
    raw = os.environ.get("SOCTALK_INGEST_INITIAL_TS", "").strip()
    if not raw:
        return "1970-01-01T00:00:00.000Z"
    if raw.lower() == "now":
        return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")[:-4] + "Z"
    return raw


class _State:
    def __init__(self) -> None:
        self.last_heartbeat_ok: datetime | None = None
        self.last_heartbeat_error: str | None = None
        self.last_alert_ts: str = _initial_alert_ts()
        # search_after tie-breaker: the ``id`` of the last event ingested at
        # last_alert_ts. None means "start of this timestamp".
        self.last_alert_id: str | None = None
        self.alerts_queried: int = 0
        self.alerts_forwarded: int = 0
        self.alerts_duplicate: int = 0
        # Shed mode only: events discarded past the bucket (legacy). In the
        # default defer mode this stays 0 — nothing is discarded.
        self.alerts_dropped_rate_limit: int = 0
        # Defer mode: cumulative count of events left on the indexer for the
        # next poll because the bucket was empty. Each deferred event counts
        # once per poll it waits, so this is a backlog-pressure signal, not a
        # loss count.
        self.alerts_deferred_rate_limit: int = 0
        self.batch_seq: int = 0
        self.checkpoint_loaded: bool = False
        self.last_ingest_error: str | None = None
        # Ingest health inputs (see _compute_health). ``ingest_phase`` is
        # ``starting`` until the checkpoint load finishes, then ``polling``;
        # ``disabled`` when ingest is switched off; ``stopped`` if the ingest
        # task exited on its own (it is meant to run forever).
        self.ingest_phase: str = "starting"
        self.ingest_phase_since: datetime = datetime.now(UTC)
        self.ingest_interval: float = 15.0
        self.last_poll_ok: datetime | None = None
        self.consecutive_poll_failures: int = 0
        self.checkpoint_save_failing: bool = False
        # A checkpoint save has succeeded since start: the durable cursor is
        # in sync even if the startup load never succeeded.
        self.checkpoint_saved: bool = False


_state = _State()


def _set_ingest_phase(phase: str) -> None:
    _state.ingest_phase = phase
    _state.ingest_phase_since = datetime.now(UTC)


def _compute_health(now: datetime | None = None) -> tuple[str, list[str]]:
    """Adapter health for the heartbeat: ``ok`` | ``degraded`` | ``failing``
    plus machine-readable reason codes.

    A heartbeat only proves the pod is up. What the control plane needs to
    know is whether alerts are flowing, so health follows the ingest loop:

    * ``failing`` — the ingest task stopped (``ingest_stopped``), polls have
      failed ``POLL_FAILING_THRESHOLD`` times in a row (``poll_failing``), or
      no poll has completed within the stale window (``poll_stale``).
    * ``degraded`` — a poll failed but fewer times than the threshold
      (``poll_failing``), the durable checkpoint never loaded so ingest
      resumed from the local cursor (``checkpoint_not_loaded``), or the last
      checkpoint save failed (``checkpoint_save_failing``).
    * ``ok`` — otherwise, including a quiet tenant whose polls succeed but
      return nothing, and an adapter with ingest disabled.
    """
    now = now or datetime.now(UTC)
    phase = _state.ingest_phase
    if phase == "disabled":
        return "ok", []

    failing: list[str] = []
    degraded: list[str] = []
    if phase == "stopped":
        failing.append("ingest_stopped")
    else:
        stale_after = max(POLL_STALE_MIN_SECONDS, 3 * _state.ingest_interval)
        since = _state.last_poll_ok or _state.ingest_phase_since
        if (now - since).total_seconds() > stale_after:
            failing.append("poll_stale")
    if _state.consecutive_poll_failures >= POLL_FAILING_THRESHOLD:
        failing.append("poll_failing")
    elif _state.consecutive_poll_failures > 0:
        degraded.append("poll_failing")
    if phase == "polling" and not (_state.checkpoint_loaded or _state.checkpoint_saved):
        degraded.append("checkpoint_not_loaded")
    if _state.checkpoint_save_failing:
        degraded.append("checkpoint_save_failing")

    if failing:
        return "failing", failing + degraded
    if degraded:
        return "degraded", degraded
    return "ok", []


class _TokenBucket:
    """Cooperative rate-limiter for per-tenant alert ingestion.

    The adapter is single-tenant (one process per tenant), so a process-
    local token bucket is the per-tenant cap by construction. ``rate``
    is alerts/sec, ``burst`` is the bucket size. What happens to the
    excess is decided by ``SOCTALK_ADAPTER_RATE_LIMIT_MODE`` in the ingest
    step, not here: ``defer`` (default) leaves it on the indexer for the
    next poll by not advancing the cursor past it; ``shed`` discards it
    and counts it on ``_state.alerts_dropped_rate_limit``.
    """

    def __init__(
        self, rate_per_sec: float, burst: int, clock=time.monotonic
    ) -> None:
        self.rate = max(rate_per_sec, 0.0)
        self.burst = max(burst, 1)
        self.tokens = float(self.burst)
        self._clock = clock
        self.last = clock()

    def _refill(self) -> None:
        now = self._clock()
        self.tokens = min(self.burst, self.tokens + (now - self.last) * self.rate)
        self.last = now

    def take(self, n: int) -> tuple[int, int]:
        """Take up to ``n`` tokens. Returns (allowed, excess)."""
        if self.rate <= 0:
            return n, 0  # rate-limiter disabled
        self._refill()
        allowed = min(n, int(self.tokens))
        self.tokens -= allowed
        return allowed, n - allowed

    def seconds_until(self, n: int) -> float:
        """Seconds until ``n`` tokens are available (0 when they already are)."""
        if self.rate <= 0:
            return 0.0
        self._refill()
        n = min(n, self.burst)
        if self.tokens >= n:
            return 0.0
        return (n - self.tokens) / self.rate


def _make_rate_limiter() -> _TokenBucket:
    per_min = float(os.environ.get("SOCTALK_ADAPTER_RATE_LIMIT_PER_MIN", "60"))
    burst = int(os.environ.get("SOCTALK_ADAPTER_RATE_LIMIT_BURST", "30"))
    return _TokenBucket(rate_per_sec=per_min / 60.0, burst=burst)


_rate_limiter = _make_rate_limiter()


def _rate_limit_mode() -> str:
    """``defer`` (default) or ``shed``.

    ``defer`` is lossless: a batch the bucket cannot admit in full is cut at
    the capacity and the keyset cursor advances only through the events that
    were actually forwarded, so the tail is re-read on the next poll. The
    ingest idempotency key on the control plane absorbs any re-read of an
    already-delivered event. ``shed`` is the pre-0.3 behaviour — discard the
    tail and move the cursor past it — kept for operators who would rather
    lose the tail of a flood than lag. A malformed value is treated as
    ``defer``: a typo must never turn on data loss.
    """
    raw = os.environ.get("SOCTALK_ADAPTER_RATE_LIMIT_MODE", "defer").strip().lower()
    if raw == "shed":
        return "shed"
    if raw != "defer":
        logger.warning("rate_limit_mode_invalid value=%r — using defer", raw)
    return "defer"


def _wazuh_indexer_url() -> str:
    return os.environ.get(
        "WAZUH_INDEXER_URL", "https://wazuh-indexer:9200"
    ).rstrip("/")


def _wazuh_indexer_creds() -> tuple[str, str]:
    return (
        os.environ.get("WAZUH_INDEXER_USERNAME", "admin"),
        os.environ.get("WAZUH_INDEXER_PASSWORD", "admin"),
    )


def _wazuh_indexer_verify_ssl() -> bool:
    """Resolve TLS verification for the Wazuh indexer httpx client.

    Reads ``WAZUH_INDEXER_VERIFY_SSL`` (default ``"true"``). Recognises the
    canonical spellings ``true``/``1`` (verify ON) and ``false``/``0`` (verify
    OFF), case-insensitive and whitespace-trimmed. Any other value is
    malformed: log a warning and fail safe to verification ON — a typo must
    never silently disable TLS verification against the indexer. The chart
    feeds this from ``IntegrationConfig.wazuh_verify_ssl`` so a tenant whose
    external (or in-cluster self-signed) indexer needs ``verify=False`` can
    opt out explicitly.
    """
    raw = os.environ.get("WAZUH_INDEXER_VERIFY_SSL", "true")
    normalized = raw.strip().lower()
    if normalized in {"true", "1"}:
        return True
    if normalized in {"false", "0"}:
        return False
    logger.warning(
        "WAZUH_INDEXER_VERIFY_SSL=%r is not a recognised boolean; "
        "defaulting to verify=True",
        raw,
    )
    return True


def _soctalk_api_verify_ssl() -> bool:
    """Resolve TLS verification for the SocTalk L1 (MSSP) API httpx clients.

    Reads ``SOCTALK_API_VERIFY_SSL`` (default ``"true"``) with the same
    spelling rules as ``WAZUH_INDEXER_VERIFY_SSL``. The provisioning controller
    sets this to ``"false"`` for cross-cluster tenants whose L1 serves a
    self-signed cert (launchpad demo / pending launchpad-owned certs): the
    adapter must reach L1 to heartbeat and forward alerts, so a self-signed L1
    can opt out of verification explicitly. A malformed value fails safe to
    verify=True — a typo must never silently disable TLS against L1.
    """
    raw = os.environ.get("SOCTALK_API_VERIFY_SSL", "true")
    normalized = raw.strip().lower()
    if normalized in {"true", "1"}:
        return True
    if normalized in {"false", "0"}:
        return False
    logger.warning(
        "SOCTALK_API_VERIFY_SSL=%r is not a recognised boolean; "
        "defaulting to verify=True",
        raw,
    )
    return True


def _severity_from_rule_level(level: int | None) -> int:
    if level is None:
        return 0
    return max(0, min(15, int(level)))


_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")
_MD5_RE = re.compile(r"\b[a-fA-F0-9]{32}\b")
_DOMAIN_RE = re.compile(
    r"\b(?:[a-z0-9-]+\.)+(?:com|net|org|io|ru|cn|tk|xyz|info|biz)\b",
    re.IGNORECASE,
)


def _is_routable_ip(ip: str) -> bool:
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        a, b, *_ = (int(p) for p in parts)
    except ValueError:
        return False
    if a in (10, 127, 0):
        return False
    if a == 172 and 16 <= b <= 31:
        return False
    if a == 192 and b == 168:
        return False
    if a == 169 and b == 254:
        return False
    return True


def _extract_iocs(text: str) -> list[dict]:
    if not text:
        return []
    seen: set[tuple[str, str]] = set()
    out: list[dict] = []
    for ip in _IPV4_RE.findall(text):
        if not _is_routable_ip(ip):
            continue
        key = ("ip", ip)
        if key in seen:
            continue
        seen.add(key)
        out.append({"type": "ip", "value": ip})
    for h in _SHA256_RE.findall(text):
        key = ("hash_sha256", h.lower())
        if key in seen:
            continue
        seen.add(key)
        out.append({"type": "hash_sha256", "value": h.lower()})
    for h in _MD5_RE.findall(text):
        if any(k[1] == h.lower() for k in seen):
            continue
        key = ("hash_md5", h.lower())
        if key in seen:
            continue
        seen.add(key)
        out.append({"type": "hash_md5", "value": h.lower()})
    for d in _DOMAIN_RE.findall(text):
        key = ("domain", d.lower())
        if key in seen:
            continue
        seen.add(key)
        out.append({"type": "domain", "value": d.lower()})
    return out[:32]


_NAME_KV_RE = re.compile(r"\bname=([A-Za-z0-9_\-.]+)")
_FIM_FILE_RE = re.compile(r"File '([^']+)' (?:was )?(?:modified|added|deleted|changed)", re.I)
_USERID_KV_RE = re.compile(r"\b(?:USER|user|uid)=([A-Za-z0-9_\-.]+)")
_IP_RE = re.compile(r"\b(?:from|src ip|source)\s*[=:]?\s*((?:\d{1,3}\.){3}\d{1,3})", re.I)


def _extract_subject(full_log: str) -> str | None:
    """Best-effort extraction of the alert's primary subject from
    Wazuh's ``full_log`` line. Handles common useradd / groupadd / FIM
    / authentication patterns. Returns ``None`` if no obvious subject
    found — the title falls back to rule description only.
    """
    if not full_log:
        return None
    for rx in (_FIM_FILE_RE, _NAME_KV_RE, _USERID_KV_RE, _IP_RE):
        m = rx.search(full_log)
        if m:
            return m.group(1)[:80]
    return None


def _compose_title(rule_desc: str, agent_name: str | None, subject: str | None) -> str:
    """Compose an analyst-friendly title: ``{rule_desc}[: subject][ on agent]``.

    Examples:
      - "New user added: attacker_test on linux-ep-0"
      - "Integrity checksum changed: /etc/passwd on linux-ep-0"
      - "Authentication failure on linux-ep-0"
    """
    base = (rule_desc or "Wazuh alert").strip().rstrip(".")
    if subject:
        base = f"{base}: {subject}"
    if agent_name:
        base = f"{base} on {agent_name}"
    return base[:255]


def _extract_entities(src: dict, agent: dict, agent_name: str | None) -> list[dict]:
    """Typed, role-carrying entities from fields the Wazuh decoder already
    parsed (issue #17 fix 1). ``source_field`` preserves provenance.

    Wazuh puts decoded fields under ``data`` (data.srcuser, data.srcip,
    data.dstuser, data.win.eventdata.*). We map the common ones; unknown
    shapes are simply not emitted rather than guessed.
    """
    ents: list[dict] = []

    def add(t: str, v, role: str | None, field: str) -> None:
        if v is None:
            return
        s = str(v).strip()
        if s:
            ents.append({"type": t, "value": s[:512], "role": role, "source_field": field})

    if isinstance(agent, dict) and agent.get("id"):
        add("host", agent.get("name") or agent.get("id"), "target", "agent.name")
    data = src.get("data") or {}
    if isinstance(data, dict):
        add("user", data.get("srcuser"), "actor", "data.srcuser")
        add("user", data.get("dstuser"), "target", "data.dstuser")
        add("user", data.get("user"), "actor", "data.user")
        add("ip", data.get("srcip"), "src", "data.srcip")
        add("ip", data.get("dstip"), "dst", "data.dstip")
        add("port", data.get("srcport"), "src", "data.srcport")
        add("port", data.get("dstport"), "dst", "data.dstport")
        add("process", data.get("process") or data.get("command"), "actor", "data.process")
    # dedupe on (type, value, role)
    seen: set[tuple] = set()
    out: list[dict] = []
    for e in ents:
        k = (e["type"], e["value"], e["role"])
        if k not in seen:
            seen.add(k)
            out.append(e)
    return out[:64]


def _extract_mitre(rule: dict) -> dict:
    """Pull MITRE ATT&CK refs from the rule (issue #17 fix 2)."""
    mitre = rule.get("mitre") or {}
    if not isinstance(mitre, dict):
        return {}
    def _cap(v):
        return [str(x)[:32] for x in (v or [])][:16]
    out = {
        "ids": _cap(mitre.get("id")),
        "tactics": _cap(mitre.get("tactic")),
        "techniques": _cap(mitre.get("technique")),
    }
    return out if any(out.values()) else {}


def _hit_to_event(hit: dict) -> dict | None:
    src = hit.get("_source") or {}
    source_id = src.get("id") or hit.get("_id")
    if not source_id:
        return None
    rule = src.get("rule") or {}
    agent = src.get("agent") or {}
    full_log = src.get("full_log") or ""
    rule_desc = rule.get("description") or ""
    agent_name = agent.get("name") if isinstance(agent, dict) else None
    asset_ids: list[str] = []
    if isinstance(agent, dict) and agent.get("id"):
        asset_ids.append(agent["id"][:64])
    if agent_name:
        asset_ids.append(agent_name[:64])

    # IOC extraction reads the RAW text (must run before redaction).
    iocs = _extract_iocs(f"{rule_desc} {full_log}")
    entities = _extract_entities(src, agent, agent_name)

    # Redaction (issue #17 fix 9): strip secrets from every outbound text
    # path AFTER IOC extraction, BEFORE anything leaves the tenant. Redact
    # on the FULL text, THEN truncate — truncating first could cut a
    # multi-line secret (e.g. a PEM block) before its END marker so the
    # pattern never matches.
    full_log_red = redact_text(full_log)[:4096] if full_log else ""
    rule_desc_red = redact_text(rule_desc)[:512] if rule_desc else ""
    description = redact_text((full_log or rule_desc).strip())[:1024] or None
    title = redact_text(
        _compose_title(rule_desc, agent_name, _extract_subject(full_log))
    )
    # Template hash over REDACTED text: masking secrets out of the hash
    # keeps the fingerprint secret-free AND stable when only a secret varies.
    thash = template_hash(full_log_red)

    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    return {
        "source_event_id": str(source_id)[:128],
        "source": "wazuh",
        "rule_id": (str(rule.get("id"))[:64] if rule.get("id") else None),
        "severity": _severity_from_rule_level(rule.get("level")),
        "asset_ids": asset_ids[:8],
        "initial_iocs": iocs,
        "ts": src.get("@timestamp") or src.get("timestamp"),
        "observed_at": now_iso,
        "description": description,
        "title": title,
        # v2 evidence sidecar
        "entities": entities,
        "mitre": _extract_mitre(rule),
        "rule_groups": [str(g)[:64] for g in (rule.get("groups") or [])][:16],
        "decoder": (src.get("decoder") or {}).get("name"),
        "full_log": full_log_red,
        "template_hash": thash,
        "template_version": TEMPLATE_VERSION,
        "redaction_version": REDACTION_VERSION,
        "raw": {
            "rule_description": rule_desc_red,
            "rule_groups": rule.get("groups") or [],
            "decoder_name": (src.get("decoder") or {}).get("name"),
            "location": src.get("location"),
            "manager_name": (src.get("manager") or {}).get("name"),
            "full_log": full_log_red,
        },
    }


def _min_severity() -> int:
    raw = os.environ.get("SOCTALK_ADAPTER_MIN_SEVERITY", "10")
    try:
        v = int(raw)
    except ValueError:
        return 10
    return max(0, min(15, v))


async def _query_alerts(
    client: httpx.AsyncClient, since_ts: str, since_id: str | None, limit: int
) -> list[dict]:
    user, pw = _wazuh_indexer_creds()
    # Keyset pagination (issue #17 fix 6): sort by (@timestamp, id) and use
    # ``search_after`` so a page that ends mid-timestamp resumes exactly
    # after the last event — no skipping same-timestamp events, and no
    # livelock when more than ``limit`` alerts share one timestamp. Re-reads
    # are still absorbed by the control-plane idempotency constraint.
    filters: list[dict] = [
        {"range": {"@timestamp": {"gte": since_ts}}},
        {"range": {"rule.level": {"gte": _min_severity()}}},
    ]
    must_not: list[dict] = []
    # By default the Wazuh manager pod's agent (id 000) flood-generates
    # FIM/monitord self-alerts (rules 510/550/553/...) that aren't
    # security signals. Default behaviour is to skip them; flip the
    # env var to "0" to ingest manager-self alerts too.
    if os.environ.get("SOCTALK_ADAPTER_EXCLUDE_MANAGER_AGENT", "1") in {"1", "true"}:
        must_not.append({"term": {"agent.id": "000"}})
    # Optional allowlist by agent.name prefix — when set, only agents
    # whose name starts with the prefix are ingested. Useful to scope
    # ingestion to docker-based endpoints like ``linux-ep-*``.
    prefix = os.environ.get("SOCTALK_ADAPTER_AGENT_PREFIX")
    if prefix:
        filters.append({"prefix": {"agent.name": prefix}})
    bool_query: dict = {"filter": filters}
    if must_not:
        bool_query["must_not"] = must_not
    body: dict = {
        "size": limit,
        # id.keyword is the stable secondary sort so ``search_after`` gives a
        # total order across equal timestamps.
        "sort": [{"@timestamp": {"order": "asc"}}, {"id": {"order": "asc"}}],
        "query": {"bool": bool_query},
    }
    if since_id is not None:
        body["search_after"] = [since_ts, since_id]
    resp = await client.post(
        f"{_wazuh_indexer_url()}/wazuh-alerts-*/_search",
        auth=(user, pw),
        json=body,
        timeout=15.0,
    )
    resp.raise_for_status()
    data = resp.json()
    return list(data.get("hits", {}).get("hits", []))


async def _load_checkpoint(
    client: httpx.AsyncClient, api_url: str, tenant_id: str, token: str
) -> None:
    try:
        resp = await client.get(
            f"{api_url}/api/internal/adapter/checkpoint?source=wazuh",
            headers={"Authorization": f"Bearer {token}"},
            timeout=10.0,
        )
        resp.raise_for_status()
        cp = resp.json()
        if cp.get("cursor_ts"):
            _state.last_alert_ts = cp["cursor_ts"]
        _state.last_alert_id = cp.get("cursor_event_id")
        _state.batch_seq = int(cp.get("batch_seq") or 0)
        _state.checkpoint_loaded = True
        logger.info("checkpoint_loaded cursor=%s id=%s batch_seq=%d",
                    _state.last_alert_ts, _state.last_alert_id, _state.batch_seq)
    except Exception as e:  # noqa: BLE001
        logger.warning("checkpoint_load_failed: %s (starting from local cursor)", e)


async def _save_checkpoint(
    client: httpx.AsyncClient, api_url: str, tenant_id: str, token: str,
    cursor_ts: str, cursor_event_id: str | None,
) -> None:
    try:
        resp = await client.put(
            f"{api_url}/api/internal/adapter/checkpoint",
            headers={"Authorization": f"Bearer {token}"},
            json={
                "tenant_id": tenant_id,
                "source": "wazuh",
                "cursor_ts": cursor_ts,
                "cursor_event_id": cursor_event_id,
                "batch_seq": _state.batch_seq,
                "dropped_total": _state.alerts_dropped_rate_limit,
            },
            timeout=10.0,
        )
        resp.raise_for_status()
        _state.checkpoint_save_failing = False
        _state.checkpoint_saved = True
    except Exception as e:  # noqa: BLE001
        _state.checkpoint_save_failing = True
        logger.warning("checkpoint_save_failed: %s", e)


async def _heartbeat_once(client: httpx.AsyncClient) -> None:
    api_url = os.environ["SOCTALK_API_URL"].rstrip("/")
    tenant_id = os.environ["SOCTALK_TENANT_ID"]
    token = _read_token()
    # Coverage metrics on the heartbeat (issue #17 fix 10, Alertmanager-style
    # loss accounting): the control plane can tell a quiet tenant from a
    # dropping one, and see ingest throughput without a separate channel.
    metrics = {
        "alerts_queried": _state.alerts_queried,
        "alerts_forwarded": _state.alerts_forwarded,
        "alerts_duplicate": _state.alerts_duplicate,
        "alerts_dropped_rate_limit": _state.alerts_dropped_rate_limit,
        "alerts_deferred_rate_limit": _state.alerts_deferred_rate_limit,
        "batch_seq": _state.batch_seq,
        "last_alert_ts": _state.last_alert_ts,
        "last_ingest_error": _state.last_ingest_error,
        "ingest_phase": _state.ingest_phase,
        "last_poll_ok_at": _state.last_poll_ok.isoformat() if _state.last_poll_ok else None,
        "consecutive_poll_failures": _state.consecutive_poll_failures,
    }
    # Health follows the ingest loop, not just "the process is up": a fresh
    # heartbeat from an adapter whose every poll fails used to read as ok.
    health, reasons = _compute_health()
    metrics["health_reasons"] = reasons
    resp = await client.post(
        f"{api_url}/api/internal/adapter/heartbeat",
        headers={"Authorization": f"Bearer {token}"},
        json={"tenant_id": tenant_id, "version": VERSION, "health": health,
              "metrics": metrics},
        timeout=10.0,
    )
    resp.raise_for_status()


async def _heartbeat_loop() -> None:
    interval = float(os.environ.get("SOCTALK_HEARTBEAT_INTERVAL_SECONDS", "30"))
    async with httpx.AsyncClient(verify=_soctalk_api_verify_ssl()) as client:
        while True:
            try:
                await _heartbeat_once(client)
                _state.last_heartbeat_ok = datetime.now(timezone.utc)
                _state.last_heartbeat_error = None
                logger.info("heartbeat_ok")
            except Exception as e:  # noqa: BLE001
                _state.last_heartbeat_error = str(e)
                logger.warning("heartbeat_failed: %s", e)
            await asyncio.sleep(interval)


async def _ingest_loop() -> None:
    if os.environ.get("SOCTALK_INGEST_DISABLED", "0") in {"1", "true"}:
        _set_ingest_phase("disabled")
        logger.info("ingest_disabled")
        return
    interval = float(os.environ.get("SOCTALK_INGEST_INTERVAL_SECONDS", "15"))
    _state.ingest_interval = interval
    _set_ingest_phase("starting")
    batch_size = int(os.environ.get("SOCTALK_INGEST_BATCH_SIZE", "100"))
    api_url = os.environ["SOCTALK_API_URL"].rstrip("/")
    tenant_id = os.environ["SOCTALK_TENANT_ID"]

    # TLS verification against the indexer is tenant-controlled via
    # WAZUH_INDEXER_VERIFY_SSL (default on); resolved once here instead of the
    # former hard-coded verify=False so externally-provided CA-signed indexers
    # are verified while self-signed in-cluster ones can opt out.
    verify_indexer_tls = _wazuh_indexer_verify_ssl()
    verify_api_tls = _soctalk_api_verify_ssl()
    async with (
        httpx.AsyncClient(verify=verify_api_tls) as api_client,
        httpx.AsyncClient(verify=verify_indexer_tls) as wazuh_client,
    ):
        # Durable checkpoint resume (issue #17 fix 6): pull the server-side
        # cursor once at start so a pod restart continues instead of
        # replaying from the in-memory initial cursor.
        # Load the durable cursor BEFORE ingesting, retrying with a freshly
        # read token each attempt. If the pod started with an about-to-expire
        # token that the control plane then renewed, the first load 401s;
        # proceeding from the local (epoch/now) cursor would replay weeks of
        # alerts or skip history. Retry so we resume from the true checkpoint
        # once the renewed token projects into the mounted Secret (~60s).
        for _attempt in range(CHECKPOINT_LOAD_MAX_ATTEMPTS):
            await _load_checkpoint(api_client, api_url, tenant_id, _read_token())
            if _state.checkpoint_loaded:
                break
            await asyncio.sleep(CHECKPOINT_LOAD_RETRY_SECONDS)
        else:
            logger.warning(
                "checkpoint_never_loaded attempts=%d — starting from local cursor",
                CHECKPOINT_LOAD_MAX_ATTEMPTS,
            )
        _set_ingest_phase("polling")
        while True:
            result = await _poll_cycle(
                api_client, wazuh_client, api_url, tenant_id, batch_size
            )
            await asyncio.sleep(_next_sleep(result, interval))


async def _poll_cycle(
    api_client: httpx.AsyncClient,
    wazuh_client: httpx.AsyncClient,
    api_url: str,
    tenant_id: str,
    batch_size: int,
) -> _PollResult | None:
    """One loop iteration with health bookkeeping. Never raises (other than
    cancellation): a failure is recorded and the loop carries on."""
    try:
        # Re-read the token each cycle so a renewed ``adapter-token`` Secret
        # (the control plane re-mints it before the TTL elapses) is picked
        # up without a pod restart — the mounted file updates in place. Read
        # inside the try: a transient read error is a failed poll, not a
        # dead ingest task.
        token = _read_token()
        result = await _ingest_once(
            api_client, wazuh_client, api_url, tenant_id, token, batch_size
        )
    except Exception as e:  # noqa: BLE001
        _state.last_ingest_error = str(e)
        _state.consecutive_poll_failures += 1
        logger.warning(
            "ingest_failed consecutive=%d: %s", _state.consecutive_poll_failures, e
        )
        return None
    # A completed poll — including an empty one — is a healthy poll.
    _state.last_poll_ok = datetime.now(UTC)
    _state.consecutive_poll_failures = 0
    _state.last_ingest_error = None
    # Recover the durable checkpoint without waiting for the cursor to move:
    # retry a save that failed, or establish one when the startup load never
    # succeeded. The control plane keeps the stored cursor monotonic
    # (GREATEST), so persisting the current cursor can never move it back.
    # In sync and not failing (the normal case) this writes nothing.
    if _state.checkpoint_save_failing or not (
        _state.checkpoint_loaded or _state.checkpoint_saved
    ):
        await _save_checkpoint(
            api_client, api_url, tenant_id, token,
            _state.last_alert_ts, _state.last_alert_id,
        )
    return result


@dataclass
class _PollResult:
    """Outcome of one ingest poll, for pacing and tests."""

    queried: int = 0
    forwarded: int = 0
    #: events left on the indexer for the next poll (defer mode)
    deferred: int = 0
    #: events discarded past the bucket (shed mode only)
    dropped: int = 0
    advanced: bool = False


def _next_sleep(result: _PollResult | None, interval: float) -> float:
    """Pacing after a poll.

    A deferred tail means the indexer holds more than the bucket admitted,
    so poll again as soon as the bucket can take another batch (capped at
    the regular interval) instead of waiting the full interval: a backlog
    then drains at the configured rate rather than one burst per interval.
    Everything else — empty poll, full delivery, failure — keeps the cadence.
    """
    if result is None or result.deferred <= 0:
        return interval
    want = min(result.deferred, _rate_limiter.burst)
    return max(0.0, min(interval, _rate_limiter.seconds_until(want)))


async def _ingest_once(
    api_client: httpx.AsyncClient,
    wazuh_client: httpx.AsyncClient,
    api_url: str,
    tenant_id: str,
    token: str,
    batch_size: int,
) -> _PollResult:
    """One poll: query from the cursor, forward what the bucket admits,
    advance the durable cursor through what was forwarded.

    The cursor is the keyset ``(ts, id)`` of the LAST event the control
    plane accepted. In ``defer`` mode an unforwarded tail therefore stays
    ahead of the cursor and is re-read next poll — nothing is lost, and the
    ``search_after`` tie-breaker still moves past same-timestamp runs. In
    ``shed`` mode the cursor jumps past the discarded tail (legacy). A
    failed POST raises before the cursor moves, so the batch is retried
    whole and the control plane's idempotency key absorbs any re-delivery.
    """
    result = _PollResult()
    hits = await _query_alerts(
        wazuh_client, _state.last_alert_ts, _state.last_alert_id, batch_size
    )
    result.queried = len(hits)
    _state.alerts_queried += len(hits)
    if not hits:
        return result

    events: list[dict] = []
    for h in hits:
        ev = _hit_to_event(h)
        if ev is not None:
            events.append(ev)
    if not events:
        return result

    new_cursor_ts = _state.last_alert_ts
    new_cursor_id = _state.last_alert_id

    allowed, excess = _rate_limiter.take(len(events))
    if excess > 0:
        if _rate_limit_mode() == "shed":
            # Legacy: the cursor passes the discarded tail. Recorded as a
            # loss fact so a quiet tenant is distinguishable from a shed one.
            _state.alerts_dropped_rate_limit += excess
            result.dropped = excess
            tail = events[-1]
            new_cursor_ts = tail["ts"] or new_cursor_ts
            new_cursor_id = tail["source_event_id"]
            logger.warning(
                "rate_limited dropped=%d total_dropped=%d batch=%d",
                excess, _state.alerts_dropped_rate_limit, len(events),
            )
        else:
            _state.alerts_deferred_rate_limit += excess
            result.deferred = excess
            logger.info(
                "rate_limited deferred=%d allowed=%d batch=%d",
                excess, allowed, len(events),
            )
    events = events[:allowed]

    if events:
        _state.batch_seq += 1
        resp = await api_client.post(
            f"{api_url}/api/internal/adapter/events",
            headers={"Authorization": f"Bearer {token}"},
            json={
                "tenant_id": tenant_id,
                "events": events,
                "schema_version": SCHEMA_VERSION,
                "batch_seq": _state.batch_seq,
            },
            timeout=30.0,
        )
        resp.raise_for_status()
        body = resp.json()
        dup = (body.get("action_counts") or {}).get("duplicate", 0)
        _state.alerts_duplicate += dup
        _state.alerts_forwarded += len(events) - dup
        _state.last_ingest_error = None
        result.forwarded = len(events)
        # Keyset cursor: the resume point is the LAST FORWARDED event's
        # (ts, id) regardless of whether the timestamp advanced — the id
        # tie-breaker always moves forward even when many alerts share one
        # timestamp, which is what breaks the same-timestamp livelock.
        # (Shed mode already pointed the cursor past the discarded tail,
        # which is further along; leave it there.)
        if result.dropped == 0:
            last = events[-1]
            new_cursor_ts = last["ts"] or new_cursor_ts
            new_cursor_id = last["source_event_id"]

    if (new_cursor_ts, new_cursor_id) != (_state.last_alert_ts, _state.last_alert_id):
        _state.last_alert_ts = new_cursor_ts
        _state.last_alert_id = new_cursor_id
        result.advanced = True
        await _save_checkpoint(
            api_client, api_url, tenant_id, token, new_cursor_ts, new_cursor_id
        )
        logger.info(
            "ingest_ok forwarded=%d deferred=%d dropped=%d total_forwarded=%d "
            "duplicate=%d cursor=%s/%s",
            result.forwarded, result.deferred, result.dropped,
            _state.alerts_forwarded, _state.alerts_duplicate,
            new_cursor_ts, new_cursor_id,
        )
    return result


@contextlib.asynccontextmanager
async def _lifespan(app: FastAPI):
    del app
    hb = asyncio.create_task(_heartbeat_loop(), name="adapter-heartbeat")
    ig = asyncio.create_task(_ingest_loop(), name="adapter-ingest")
    ig.add_done_callback(_on_ingest_task_done)
    try:
        yield
    finally:
        for t in (hb, ig):
            t.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await t


def _on_ingest_task_done(task: asyncio.Task) -> None:
    """The ingest loop runs until cancelled; if it ends any other way (an
    exception outside the per-poll guard, e.g. the token file missing at
    startup) report it as stopped instead of heartbeating ``ok`` forever."""
    if task.cancelled() or _state.ingest_phase == "disabled":
        return
    exc = task.exception()
    _set_ingest_phase("stopped")
    if exc is not None:
        _state.last_ingest_error = f"ingest task stopped: {exc}"
        logger.error("ingest_task_stopped: %r", exc)
    else:
        logger.error("ingest_task_stopped")


app = FastAPI(lifespan=_lifespan)


@app.get("/health/live")
async def live() -> dict:
    return {"ok": True, "version": VERSION}


@app.get("/health/ready")
async def ready() -> dict:
    # Ready as soon as the server is up; heartbeat + ingest status are
    # informational. The chart's readiness probe just needs the process
    # to be serving HTTP — ``health`` is reported, not gated on, so a
    # failing indexer does not pull the pod out of service.
    health, reasons = _compute_health()
    return {
        "ok": True,
        "last_heartbeat_ok": _state.last_heartbeat_ok.isoformat()
        if _state.last_heartbeat_ok
        else None,
        "last_heartbeat_error": _state.last_heartbeat_error,
        "alerts_queried": _state.alerts_queried,
        "alerts_forwarded": _state.alerts_forwarded,
        "alerts_duplicate": _state.alerts_duplicate,
        "alerts_dropped_rate_limit": _state.alerts_dropped_rate_limit,
        "alerts_deferred_rate_limit": _state.alerts_deferred_rate_limit,
        "batch_seq": _state.batch_seq,
        "checkpoint_loaded": _state.checkpoint_loaded,
        "last_alert_ts": _state.last_alert_ts,
        "last_ingest_error": _state.last_ingest_error,
        "health": health,
        "health_reasons": reasons,
        "ingest_phase": _state.ingest_phase,
        "last_poll_ok": _state.last_poll_ok.isoformat() if _state.last_poll_ok else None,
        "consecutive_poll_failures": _state.consecutive_poll_failures,
    }
