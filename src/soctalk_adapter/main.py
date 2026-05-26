"""SocTalk per-tenant adapter — heartbeat + Wazuh alert ingest to L1."""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import re
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


class _State:
    def __init__(self) -> None:
        self.last_heartbeat_ok: datetime | None = None
        self.last_heartbeat_error: str | None = None
        self.last_alert_ts: str = "1970-01-01T00:00:00.000Z"
        self.alerts_forwarded: int = 0
        self.last_ingest_error: str | None = None


_state = _State()


def _wazuh_indexer_url() -> str:
    return os.environ.get(
        "WAZUH_INDEXER_URL", "https://wazuh-indexer:9200"
    ).rstrip("/")


def _wazuh_indexer_creds() -> tuple[str, str]:
    return (
        os.environ.get("WAZUH_INDEXER_USERNAME", "admin"),
        os.environ.get("WAZUH_INDEXER_PASSWORD", "admin"),
    )


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


def _hit_to_event(hit: dict) -> dict | None:
    src = hit.get("_source") or {}
    source_id = src.get("id") or hit.get("_id")
    if not source_id:
        return None
    rule = src.get("rule") or {}
    agent = src.get("agent") or {}
    full_log = src.get("full_log") or ""
    rule_desc = rule.get("description") or ""
    asset_ids: list[str] = []
    if isinstance(agent, dict) and agent.get("id"):
        asset_ids.append(agent["id"][:64])
    if isinstance(agent, dict) and agent.get("name"):
        asset_ids.append(agent["name"][:64])
    description = (full_log or rule_desc).strip()[:1024]
    return {
        "source_event_id": str(source_id)[:128],
        "source": "wazuh",
        "rule_id": (str(rule.get("id"))[:64] if rule.get("id") else None),
        "severity": _severity_from_rule_level(rule.get("level")),
        "asset_ids": asset_ids[:8],
        "initial_iocs": _extract_iocs(f"{rule_desc} {full_log}"),
        "ts": src.get("@timestamp") or src.get("timestamp"),
        "description": description,
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
    async with httpx.AsyncClient() as client:
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

    async with (
        httpx.AsyncClient() as api_client,
        httpx.AsyncClient(verify=False) as wazuh_client,
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
        "last_alert_ts": _state.last_alert_ts,
        "last_ingest_error": _state.last_ingest_error,
    }
