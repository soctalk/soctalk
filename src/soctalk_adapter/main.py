"""SocTalk per-tenant adapter — heartbeat + Wazuh alert ingest to L1."""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import re
import time
from datetime import datetime, timezone
from pathlib import Path

import httpx
from fastapi import FastAPI

logger = logging.getLogger("soctalk.adapter")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

VERSION = "0.1.0"


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
        self.alerts_forwarded: int = 0
        self.alerts_dropped_rate_limit: int = 0
        self.last_ingest_error: str | None = None


_state = _State()


class _TokenBucket:
    """Cooperative rate-limiter for per-tenant alert ingestion.

    The adapter is single-tenant (one process per tenant), so a process-
    local token bucket is the per-tenant cap by construction. ``rate``
    is alerts/sec, ``burst`` is the bucket size. Excess alerts are
    dropped (and counted on ``_state.alerts_dropped_rate_limit``) rather
    than queued — better to lose a tail of a flood than to lag forever.
    """

    def __init__(self, rate_per_sec: float, burst: int) -> None:
        self.rate = max(rate_per_sec, 0.0)
        self.burst = max(burst, 1)
        self.tokens = float(self.burst)
        self.last = time.monotonic()

    def take(self, n: int) -> tuple[int, int]:
        """Take up to ``n`` tokens. Returns (allowed, dropped)."""
        if self.rate <= 0:
            return n, 0  # rate-limiter disabled
        now = time.monotonic()
        self.tokens = min(self.burst, self.tokens + (now - self.last) * self.rate)
        self.last = now
        allowed = min(n, int(self.tokens))
        self.tokens -= allowed
        return allowed, n - allowed


def _make_rate_limiter() -> _TokenBucket:
    per_min = float(os.environ.get("SOCTALK_ADAPTER_RATE_LIMIT_PER_MIN", "60"))
    burst = int(os.environ.get("SOCTALK_ADAPTER_RATE_LIMIT_BURST", "30"))
    return _TokenBucket(rate_per_sec=per_min / 60.0, burst=burst)


_rate_limiter = _make_rate_limiter()


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
    description = (full_log or rule_desc).strip()[:1024]
    title = _compose_title(rule_desc, agent_name, _extract_subject(full_log))
    return {
        "source_event_id": str(source_id)[:128],
        "source": "wazuh",
        "rule_id": (str(rule.get("id"))[:64] if rule.get("id") else None),
        "severity": _severity_from_rule_level(rule.get("level")),
        "asset_ids": asset_ids[:8],
        "initial_iocs": _extract_iocs(f"{rule_desc} {full_log}"),
        "ts": src.get("@timestamp") or src.get("timestamp"),
        "description": description,
        "title": title,
        "raw": {
            "rule_description": rule_desc[:512],
            "rule_groups": rule.get("groups") or [],
            "decoder_name": (src.get("decoder") or {}).get("name"),
            "location": src.get("location"),
            "manager_name": (src.get("manager") or {}).get("name"),
            "full_log": full_log[:1024],
        },
    }


def _min_severity() -> int:
    raw = os.environ.get("SOCTALK_ADAPTER_MIN_SEVERITY", "10")
    try:
        v = int(raw)
    except ValueError:
        return 10
    return max(0, min(15, v))


async def _query_alerts(client: httpx.AsyncClient, since_ts: str, limit: int) -> list[dict]:
    user, pw = _wazuh_indexer_creds()
    filters: list[dict] = [
        {"range": {"@timestamp": {"gt": since_ts}}},
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
    body = {
        "size": limit,
        "sort": [{"@timestamp": {"order": "asc"}}],
        "query": {"bool": bool_query},
    }
    resp = await client.post(
        f"{_wazuh_indexer_url()}/wazuh-alerts-*/_search",
        auth=(user, pw),
        json=body,
        timeout=15.0,
    )
    resp.raise_for_status()
    data = resp.json()
    return list(data.get("hits", {}).get("hits", []))


async def _heartbeat_once(client: httpx.AsyncClient) -> None:
    api_url = os.environ["SOCTALK_API_URL"].rstrip("/")
    tenant_id = os.environ["SOCTALK_TENANT_ID"]
    token = _read_token()
    resp = await client.post(
        f"{api_url}/api/internal/adapter/heartbeat",
        headers={"Authorization": f"Bearer {token}"},
        json={"tenant_id": tenant_id, "version": VERSION, "health": "ok"},
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
        logger.info("ingest_disabled")
        return
    interval = float(os.environ.get("SOCTALK_INGEST_INTERVAL_SECONDS", "15"))
    batch_size = int(os.environ.get("SOCTALK_INGEST_BATCH_SIZE", "100"))
    api_url = os.environ["SOCTALK_API_URL"].rstrip("/")
    tenant_id = os.environ["SOCTALK_TENANT_ID"]
    token = _read_token()

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
        while True:
            try:
                hits = await _query_alerts(wazuh_client, _state.last_alert_ts, batch_size)
                if hits:
                    events: list[dict] = []
                    new_high = _state.last_alert_ts
                    for h in hits:
                        ev = _hit_to_event(h)
                        if ev is None:
                            continue
                        if ev["ts"] and ev["ts"] > new_high:
                            new_high = ev["ts"]
                        events.append(ev)
                    # Per-tenant rate limit — drop the tail past the
                    # bucket capacity. The high-water cursor (new_high)
                    # still advances past the dropped events so we don't
                    # replay them next tick; the goal here is to refuse
                    # work, not to defer it.
                    if events:
                        allowed, dropped = _rate_limiter.take(len(events))
                        if dropped > 0:
                            _state.alerts_dropped_rate_limit += dropped
                            logger.warning(
                                "rate_limited dropped=%d total_dropped=%d batch=%d",
                                dropped,
                                _state.alerts_dropped_rate_limit,
                                len(events),
                            )
                        events = events[:allowed]
                        # If the rate-limiter dropped the entire batch
                        # the POST below is skipped, but the cursor
                        # still needs to advance — otherwise next tick
                        # re-fetches and re-drops the same hits forever
                        # while newer alerts queue behind them.
                        if allowed == 0 and new_high > _state.last_alert_ts:
                            _state.last_alert_ts = new_high
                    if events:
                        resp = await api_client.post(
                            f"{api_url}/api/internal/adapter/events",
                            headers={"Authorization": f"Bearer {token}"},
                            json={"tenant_id": tenant_id, "events": events},
                            timeout=30.0,
                        )
                        resp.raise_for_status()
                        _state.alerts_forwarded += len(events)
                        _state.last_alert_ts = new_high
                        _state.last_ingest_error = None
                        logger.info(
                            "ingest_ok forwarded=%d total=%d highwater=%s",
                            len(events),
                            _state.alerts_forwarded,
                            new_high,
                        )
            except Exception as e:
                _state.last_ingest_error = str(e)
                logger.warning("ingest_failed: %s", e)
            await asyncio.sleep(interval)


@contextlib.asynccontextmanager
async def _lifespan(app: FastAPI):
    del app
    hb = asyncio.create_task(_heartbeat_loop(), name="adapter-heartbeat")
    ig = asyncio.create_task(_ingest_loop(), name="adapter-ingest")
    try:
        yield
    finally:
        for t in (hb, ig):
            t.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await t


app = FastAPI(lifespan=_lifespan)


@app.get("/health/live")
async def live() -> dict:
    return {"ok": True, "version": VERSION}


@app.get("/health/ready")
async def ready() -> dict:
    # Ready as soon as the server is up; heartbeat + ingest status are
    # informational. The chart's readiness probe just needs the process
    # to be serving HTTP.
    return {
        "ok": True,
        "last_heartbeat_ok": _state.last_heartbeat_ok.isoformat()
        if _state.last_heartbeat_ok
        else None,
        "last_heartbeat_error": _state.last_heartbeat_error,
        "alerts_forwarded": _state.alerts_forwarded,
        "alerts_dropped_rate_limit": _state.alerts_dropped_rate_limit,
        "last_alert_ts": _state.last_alert_ts,
        "last_ingest_error": _state.last_ingest_error,
    }
