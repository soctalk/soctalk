"""Native Python wrappers for the Wazuh Manager + Indexer APIs.

Implements the same 14 tools that ``mcp-server-wazuh`` exposes, but
in-process Python (no Rust binary to ship, no MCP protocol bridge).
This is the load-bearing path the chat agent uses for Wazuh
introspection — see ``docs/chat-interface-plan.md`` §"Tool surface"
and the architectural note in
``chat/mcp_tools.py`` for why both paths coexist.

Two upstream APIs:

* **Wazuh Manager API** (default port 55000). JWT-bearer auth obtained
  by POST /security/user/authenticate with HTTP Basic. Tokens last
  ~15 min by default; we cache for 10 min to leave headroom.
* **Wazuh Indexer** (default port 9200, OpenSearch-compatible). HTTP
  Basic auth. Hosts the ``wazuh-alerts-*`` and
  ``wazuh-states-vulnerabilities-*`` indices.

Config resolution (precedence high → low):

1. **Per-tenant** (chat dispatcher injects ``target_tenant_id``): read
   ``integration_configs.wazuh_url`` + ``wazuh_indexer_url`` + the
   ``tenant_secrets`` row with ``purpose='wazuh-api'``, then read the
   referenced k8s Secret cross-namespace for ``WAZUH_API_USERNAME``,
   ``WAZUH_API_PASSWORD``, ``INDEXER_USERNAME``, ``INDEXER_PASSWORD``.
   Cached per-tenant for ``_CONFIG_TTL_S`` seconds; 401 from the
   Manager evicts that one entry. See ``docs/mssp-chat-plan.md``.
2. **Env-fallback** (no ``target_tenant_id``): ``WAZUH_URL``,
   ``WAZUH_API_USERNAME``, ``WAZUH_API_PASSWORD``, ``WAZUH_INDEXER_URL``,
   ``WAZUH_INDEXER_USERNAME``, ``WAZUH_INDEXER_PASSWORD``,
   ``WAZUH_VERIFY_SSL``. Single-process / local-dev path.

Failure handling: tools return a ``ToolResult`` with ``{"error": ...}``
on transport / auth / 5xx failures. The agent's system prompt knows
to relay these as "Wazuh appears unreachable" without inventing data.
"""

from __future__ import annotations

import asyncio
import base64
import os
import ssl
import time
from dataclasses import dataclass
from typing import Any
from uuid import UUID

import httpx
import structlog
from sqlalchemy import text as sql_text
from sqlalchemy.ext.asyncio import AsyncSession

from soctalk.chat.tools import (
    _TENANT_SLUG_PROP,
    ChatTool,
    ToolResult,
    _enforce_size,
)


class WazuhNotConfigured(RuntimeError):
    """Raised when per-tenant Wazuh resolution fails — missing
    integration_configs row, missing tenant_secrets pointer, k8s secret
    not readable, etc. Surfaced to the model as the tool's error result.
    """


logger = structlog.get_logger()


# Token cache TTL in seconds; Wazuh defaults to 900 (15 min). Refresh
# slightly early so we don't race the server clock.
_TOKEN_TTL_S = 600


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class WazuhConfig:
    """Resolved Wazuh Manager + Indexer endpoints + credentials."""

    manager_url: str
    manager_user: str
    manager_password: str
    indexer_url: str
    indexer_user: str
    indexer_password: str
    verify_ssl: bool

    @classmethod
    def from_env(cls) -> "WazuhConfig | None":
        manager_url = os.getenv("WAZUH_URL", "").rstrip("/")
        if not manager_url:
            return None
        return cls(
            manager_url=manager_url,
            manager_user=os.getenv("WAZUH_API_USERNAME", ""),
            manager_password=os.getenv("WAZUH_API_PASSWORD", ""),
            indexer_url=os.getenv(
                "WAZUH_INDEXER_URL",
                # Derive from manager URL if not set: same host, port 9200.
                _derive_indexer(manager_url),
            ).rstrip("/"),
            indexer_user=os.getenv(
                "WAZUH_INDEXER_USERNAME",
                # Indexer commonly shares creds with the dashboard; the
                # demo + lab clusters both use ``admin``.
                os.getenv("INDEXER_USERNAME", "admin"),
            ),
            indexer_password=os.getenv(
                "WAZUH_INDEXER_PASSWORD",
                os.getenv("INDEXER_PASSWORD", "admin"),
            ),
            verify_ssl=os.getenv("WAZUH_VERIFY_SSL", "false").lower()
            not in {"0", "false", "no"},
        )


def _derive_indexer(manager_url: str) -> str:
    """``https://wazuh-manager:55000`` → ``https://wazuh-indexer:9200``."""
    try:
        scheme, rest = manager_url.split("://", 1)
        host = rest.split(":", 1)[0].split("/", 1)[0]
        # Demo + lab convention: the indexer service shares the manager's
        # base hostname with ``-manager`` replaced by ``-indexer``.
        if "-manager" in host:
            host = host.replace("-manager", "-indexer")
        return f"{scheme}://{host}:9200"
    except Exception:  # noqa: BLE001
        return ""


def _client_kwargs(cfg: WazuhConfig) -> dict[str, Any]:
    """Build the kwargs shared by every httpx client we create."""
    return {
        "timeout": httpx.Timeout(15.0, connect=5.0),
        # Wazuh's TLS cert is self-signed in lab + demo. The
        # verify_ssl flag controls whether we validate.
        "verify": cfg.verify_ssl,
    }


# ---------------------------------------------------------------------------
# Manager API client (JWT-bearer)
# ---------------------------------------------------------------------------


class _ManagerClient:
    """Lightweight Wazuh Manager API client.

    Caches the JWT for ``_TOKEN_TTL_S`` seconds. Re-auths on 401 once.
    Thread-safe via an asyncio.Lock so concurrent chat turns don't
    fire multiple auth requests.
    """

    def __init__(self, cfg: WazuhConfig) -> None:
        self._cfg = cfg
        self._token: str | None = None
        self._token_ts: float = 0.0
        self._lock = asyncio.Lock()

    async def _auth(self, client: httpx.AsyncClient) -> str:
        async with self._lock:
            if self._token and (time.monotonic() - self._token_ts) < _TOKEN_TTL_S:
                return self._token
            r = await client.post(
                f"{self._cfg.manager_url}/security/user/authenticate",
                auth=(self._cfg.manager_user, self._cfg.manager_password),
                headers={"Content-Type": "application/json"},
            )
            r.raise_for_status()
            self._token = r.json()["data"]["token"]
            self._token_ts = time.monotonic()
            return self._token

    async def get(
        self, path: str, *, params: dict[str, Any] | None = None
    ) -> Any:
        """GET <manager_url><path>?<params>, returning the JSON body."""
        async with httpx.AsyncClient(**_client_kwargs(self._cfg)) as client:
            token = await self._auth(client)
            r = await client.get(
                f"{self._cfg.manager_url}{path}",
                params=params or {},
                headers={"Authorization": f"Bearer {token}"},
            )
            if r.status_code == 401:
                # Token expired — clear cache + retry once.
                self._token = None
                token = await self._auth(client)
                r = await client.get(
                    f"{self._cfg.manager_url}{path}",
                    params=params or {},
                    headers={"Authorization": f"Bearer {token}"},
                )
            r.raise_for_status()
            return r.json()


# ---------------------------------------------------------------------------
# Indexer client (HTTP Basic)
# ---------------------------------------------------------------------------


class _IndexerClient:
    def __init__(self, cfg: WazuhConfig) -> None:
        self._cfg = cfg

    async def search(
        self, *, index: str, body: dict[str, Any]
    ) -> Any:
        """POST <indexer_url>/<index>/_search."""
        async with httpx.AsyncClient(**_client_kwargs(self._cfg)) as client:
            r = await client.post(
                f"{self._cfg.indexer_url}/{index}/_search",
                json=body,
                auth=(self._cfg.indexer_user, self._cfg.indexer_password),
                headers={"Content-Type": "application/json"},
            )
            r.raise_for_status()
            return r.json()


# ---------------------------------------------------------------------------
# Per-tenant resolution: read integration_configs + tenant_secrets, then
# the cross-namespace k8s Secret. Cached per-tenant for _CONFIG_TTL_S.
# ---------------------------------------------------------------------------


# Cache TTL for resolved Wazuh creds (config + JWT). Short enough that a
# rotated tenant password drains within a few minutes; long enough that
# typical chat usage doesn't pay the k8s + DB round-trip per call.
_CONFIG_TTL_S = 300


@dataclass
class _CachedTenantClients:
    cfg: WazuhConfig
    manager_client: _ManagerClient
    expires_at: float


_PER_TENANT_CACHE: dict[UUID, _CachedTenantClients] = {}
_PER_TENANT_LOCK = asyncio.Lock()


def _evict_tenant(tenant_id: UUID) -> None:
    _PER_TENANT_CACHE.pop(tenant_id, None)


async def _k8s_secret_read(namespace: str, name: str) -> dict[str, str]:
    """Read a k8s Secret cross-namespace, return decoded data dict.

    Lazy-imports ``kubernetes_asyncio`` so unit tests don't have to
    install it. Requires the API pod's ServiceAccount to have
    ``get`` on that Secret (chart's Phase-5 per-tenant RoleBinding).
    """
    try:
        from kubernetes_asyncio import client as k8s_client
        from kubernetes_asyncio import config as k8s_config
    except ImportError as e:
        raise WazuhNotConfigured(
            "kubernetes_asyncio not installed; cannot read tenant Wazuh creds"
        ) from e

    try:
        k8s_config.load_incluster_config()
    except k8s_config.ConfigException:
        # Local dev / tests: try the default kubeconfig as a fallback.
        try:
            await k8s_config.load_kube_config()
        except Exception as e:  # noqa: BLE001
            raise WazuhNotConfigured(
                "no kube config available (not in-cluster, no kubeconfig); "
                "tenant Wazuh routing requires a k8s context"
            ) from e

    async with k8s_client.ApiClient() as api:
        v1 = k8s_client.CoreV1Api(api)
        try:
            sec = await v1.read_namespaced_secret(name=name, namespace=namespace)
        except Exception as e:  # noqa: BLE001
            raise WazuhNotConfigured(
                f"k8s secret {namespace}/{name} not readable: "
                f"{type(e).__name__}"
            ) from e
        return {
            k: base64.b64decode(v).decode("utf-8")
            for k, v in (sec.data or {}).items()
        }


async def _load_wazuh_config(
    db: AsyncSession, tenant_id: UUID
) -> WazuhConfig:
    """Resolve a tenant's WazuhConfig from integration_configs + tenant_secrets + k8s."""
    row = (
        await db.execute(
            sql_text(
                "SELECT wazuh_enabled, wazuh_url, wazuh_indexer_url, "
                "       wazuh_verify_ssl "
                "FROM integration_configs WHERE tenant_id = :t"
            ),
            {"t": str(tenant_id)},
        )
    ).mappings().first()
    if not row or not row["wazuh_enabled"] or not row["wazuh_url"]:
        raise WazuhNotConfigured(
            f"Wazuh not enabled / URL missing for tenant {tenant_id}"
        )

    sec = (
        await db.execute(
            sql_text(
                "SELECT k8s_namespace, k8s_secret_name "
                "FROM tenant_secrets "
                "WHERE tenant_id = :t AND purpose = 'wazuh-api' "
                "LIMIT 1"
            ),
            {"t": str(tenant_id)},
        )
    ).mappings().first()
    if not sec:
        raise WazuhNotConfigured(
            f"tenant_secrets row missing for tenant {tenant_id} "
            "(purpose='wazuh-api') — run scripts/ops/"
            "backfill_wazuh_tenant_secrets.py for existing tenants"
        )

    creds = await _k8s_secret_read(sec["k8s_namespace"], sec["k8s_secret_name"])
    mgr_user = creds.get("WAZUH_API_USERNAME") or creds.get("username")
    mgr_pw = creds.get("WAZUH_API_PASSWORD") or creds.get("password")
    idx_user = (
        creds.get("INDEXER_USERNAME")
        or creds.get("WAZUH_INDEXER_USERNAME")
    )
    idx_pw = (
        creds.get("INDEXER_PASSWORD")
        or creds.get("WAZUH_INDEXER_PASSWORD")
    )
    if not (mgr_user and mgr_pw and idx_user and idx_pw):
        raise WazuhNotConfigured(
            f"wazuh-api secret {sec['k8s_namespace']}/"
            f"{sec['k8s_secret_name']} missing required keys "
            "(WAZUH_API_USERNAME/PASSWORD + INDEXER_USERNAME/PASSWORD)"
        )

    manager_url = row["wazuh_url"].rstrip("/")
    indexer_url = (row["wazuh_indexer_url"] or _derive_indexer(manager_url)).rstrip("/")
    return WazuhConfig(
        manager_url=manager_url,
        manager_user=mgr_user,
        manager_password=mgr_pw,
        indexer_url=indexer_url,
        indexer_user=idx_user,
        indexer_password=idx_pw,
        verify_ssl=bool(row["wazuh_verify_ssl"]),
    )


async def _resolved_for_tenant(
    db: AsyncSession, tenant_id: UUID
) -> tuple[_ManagerClient, _IndexerClient]:
    """Return cached or freshly resolved (manager, indexer) for a tenant."""
    now = time.monotonic()
    cached = _PER_TENANT_CACHE.get(tenant_id)
    if cached and cached.expires_at > now:
        return cached.manager_client, _IndexerClient(cached.cfg)

    async with _PER_TENANT_LOCK:
        cached = _PER_TENANT_CACHE.get(tenant_id)
        if cached and cached.expires_at > now:
            return cached.manager_client, _IndexerClient(cached.cfg)
        cfg = await _load_wazuh_config(db, tenant_id)
        mgr = _ManagerClient(cfg)
        _PER_TENANT_CACHE[tenant_id] = _CachedTenantClients(
            cfg=cfg,
            manager_client=mgr,
            expires_at=now + _CONFIG_TTL_S,
        )
        return mgr, _IndexerClient(cfg)


async def _resolved(
    db: AsyncSession | None = None,
    target_tenant_id: UUID | None = None,
) -> tuple[_ManagerClient, _IndexerClient] | None:
    """Pick the resolution path: per-tenant if both args present, else env.

    Returns None only when env-fallback fails (no ``WAZUH_URL`` set).
    Per-tenant failures raise ``WazuhNotConfigured`` so callers can
    surface a precise reason to the model.
    """
    if target_tenant_id is not None and db is not None:
        return await _resolved_for_tenant(db, target_tenant_id)
    cfg = WazuhConfig.from_env()
    if cfg is None:
        return None
    return _ManagerClient(cfg), _IndexerClient(cfg)


def _err_no_wazuh() -> ToolResult:
    return ToolResult(
        data={
            "error": (
                "Wazuh not configured: set WAZUH_URL + WAZUH_API_USERNAME / "
                "WAZUH_API_PASSWORD (and WAZUH_INDEXER_URL / creds if the "
                "indexer is on a non-default host) on the API process."
            )
        }
    )


def _wrap_error(e: Exception, *, op: str) -> ToolResult:
    if isinstance(e, httpx.HTTPStatusError):
        msg = f"Wazuh {op} HTTP {e.response.status_code}"
        try:
            body = e.response.json()
            if isinstance(body, dict) and "message" in body:
                msg += f": {str(body['message'])[:200]}"
        except Exception:  # noqa: BLE001
            pass
    elif isinstance(e, httpx.RequestError):
        msg = f"Wazuh {op} transport error: {type(e).__name__}"
    else:
        msg = f"Wazuh {op} failed: {type(e).__name__}: {str(e)[:200]}"
    return ToolResult(data={"error": msg})


def _agent_id_3(agent_id: str) -> str:
    """Wazuh wants ``001`` not ``1``. Pad if numeric."""
    try:
        return f"{int(agent_id):03d}"
    except (TypeError, ValueError):
        return agent_id


# ---------------------------------------------------------------------------
# Tool implementations (14, matching mcp-server-wazuh names)
# ---------------------------------------------------------------------------


async def get_wazuh_alert_summary(
    db: AsyncSession,
    *,
    limit: int = 50,
    target_tenant_id: UUID | None = None,
) -> ToolResult:
    """Recent Wazuh alerts from the indexer (wazuh-alerts-*)."""
    try:
        resolved = await _resolved(db, target_tenant_id)
    except WazuhNotConfigured as e:
        return ToolResult(data={"error": str(e)})
    if resolved is None:
        return _err_no_wazuh()
    _, idx = resolved
    try:
        body = {
            "size": max(1, min(300, int(limit))),
            "sort": [{"timestamp": "desc"}],
            "_source": [
                "id", "timestamp", "agent", "rule", "data", "decoder",
            ],
        }
        result = await idx.search(index="wazuh-alerts-*", body=body)
        hits = result.get("hits", {}).get("hits", [])
        rows = []
        for h in hits:
            s = h.get("_source", {}) or {}
            rows.append({
                "id": h.get("_id") or s.get("id"),
                "timestamp": s.get("timestamp"),
                "agent": (s.get("agent") or {}).get("name"),
                "rule_id": (s.get("rule") or {}).get("id"),
                "rule_level": (s.get("rule") or {}).get("level"),
                "rule_description": (s.get("rule") or {}).get("description"),
                "src_ip": (s.get("data") or {}).get("srcip")
                          or (s.get("data") or {}).get("src_ip"),
                "dst_ip": (s.get("data") or {}).get("dstip")
                          or (s.get("data") or {}).get("dst_ip"),
                "user": (s.get("data") or {}).get("srcuser")
                          or (s.get("data") or {}).get("dstuser"),
            })
        return _enforce_size(rows)
    except Exception as e:  # noqa: BLE001
        return _wrap_error(e, op="alert_summary")


async def get_wazuh_rules_summary(
    db: AsyncSession,
    *,
    limit: int = 100,
    level: int | None = None,
    group: str | None = None,
    filename: str | None = None,
    target_tenant_id: UUID | None = None,
) -> ToolResult:
    """Wazuh rules with optional filters on level/group/filename."""
    try:
        resolved = await _resolved(db, target_tenant_id)
    except WazuhNotConfigured as e:
        return ToolResult(data={"error": str(e)})
    if resolved is None:
        return _err_no_wazuh()
    mgr, _ = resolved
    try:
        params: dict[str, Any] = {"limit": max(1, min(500, int(limit)))}
        if level is not None:
            params["level"] = int(level)
        if group:
            params["group"] = group
        if filename:
            params["filename"] = filename
        result = await mgr.get("/rules", params=params)
        rows = (result.get("data") or {}).get("affected_items") or []
        clean = []
        for r in rows:
            clean.append({
                "id": r.get("id"),
                "level": r.get("level"),
                "description": r.get("description"),
                "groups": r.get("groups"),
                "filename": r.get("filename"),
                "gdpr": r.get("gdpr"),
                "pci_dss": r.get("pci_dss"),
                "hipaa": r.get("hipaa"),
                "nist_800_53": r.get("nist_800_53"),
                "mitre": r.get("mitre"),
            })
        return _enforce_size(clean)
    except Exception as e:  # noqa: BLE001
        return _wrap_error(e, op="rules_summary")


async def get_wazuh_vulnerability_summary(
    db: AsyncSession,
    *,
    agent_id: str,
    limit: int = 100,
    severity: str | None = None,
    cve: str | None = None,
    target_tenant_id: UUID | None = None,
) -> ToolResult:
    """Vulnerability records for an agent from the indexer."""
    try:
        resolved = await _resolved(db, target_tenant_id)
    except WazuhNotConfigured as e:
        return ToolResult(data={"error": str(e)})
    if resolved is None:
        return _err_no_wazuh()
    _, idx = resolved
    try:
        must: list[dict[str, Any]] = [
            {"term": {"agent.id": _agent_id_3(agent_id)}},
        ]
        if severity:
            must.append({"term": {"vulnerability.severity": severity}})
        if cve:
            must.append({"term": {"vulnerability.id": cve}})
        body = {
            "size": max(1, min(300, int(limit))),
            "query": {"bool": {"must": must}},
            "sort": [{"vulnerability.score.base": "desc"}],
        }
        result = await idx.search(
            index="wazuh-states-vulnerabilities-*", body=body
        )
        hits = result.get("hits", {}).get("hits", [])
        rows = []
        for h in hits:
            s = h.get("_source", {}) or {}
            v = s.get("vulnerability") or {}
            rows.append({
                "cve": v.get("id"),
                "severity": v.get("severity"),
                "score": (v.get("score") or {}).get("base"),
                "package": (s.get("package") or {}).get("name"),
                "package_version": (s.get("package") or {}).get("version"),
                "agent": (s.get("agent") or {}).get("name"),
                "detected_at": v.get("detected_at"),
                "published": v.get("published_at"),
            })
        return _enforce_size(rows)
    except Exception as e:  # noqa: BLE001
        return _wrap_error(e, op="vulnerability_summary")


async def get_wazuh_critical_vulnerabilities(
    db: AsyncSession,
    *,
    agent_id: str,
    limit: int = 100,
    target_tenant_id: UUID | None = None,
) -> ToolResult:
    """Shortcut: vulnerability_summary with severity=Critical."""
    return await get_wazuh_vulnerability_summary(
        db,
        agent_id=agent_id,
        limit=limit,
        severity="Critical",
        target_tenant_id=target_tenant_id,
    )


async def get_wazuh_agents(
    db: AsyncSession,
    *,
    limit: int = 100,
    status: str | None = None,
    name: str | None = None,
    ip: str | None = None,
    group: str | None = None,
    os_platform: str | None = None,
    version: str | None = None,
    target_tenant_id: UUID | None = None,
) -> ToolResult:
    """List Wazuh agents with optional filters."""
    try:
        resolved = await _resolved(db, target_tenant_id)
    except WazuhNotConfigured as e:
        return ToolResult(data={"error": str(e)})
    if resolved is None:
        return _err_no_wazuh()
    mgr, _ = resolved
    try:
        params: dict[str, Any] = {"limit": max(1, min(500, int(limit)))}
        for k, v in (
            ("status", status), ("name", name), ("ip", ip),
            ("group", group), ("os.platform", os_platform),
            ("version", version),
        ):
            if v:
                params[k] = v
        result = await mgr.get("/agents", params=params)
        rows = (result.get("data") or {}).get("affected_items") or []
        return _enforce_size([
            {
                "id": r.get("id"),
                "name": r.get("name"),
                "status": r.get("status"),
                "ip": r.get("ip"),
                "register_ip": r.get("registerIP"),
                "group": r.get("group"),
                "os": (r.get("os") or {}).get("platform"),
                "os_name": (r.get("os") or {}).get("name"),
                "os_version": (r.get("os") or {}).get("version"),
                "version": r.get("version"),
                "last_keep_alive": r.get("lastKeepAlive"),
                "node_name": r.get("node_name"),
            }
            for r in rows
        ])
    except Exception as e:  # noqa: BLE001
        return _wrap_error(e, op="agents")


async def get_wazuh_agent_processes(
    db: AsyncSession,
    *,
    agent_id: str,
    limit: int = 100,
    search: str | None = None,
    target_tenant_id: UUID | None = None,
) -> ToolResult:
    """Processes seen on an agent (via Wazuh syscollector)."""
    try:
        resolved = await _resolved(db, target_tenant_id)
    except WazuhNotConfigured as e:
        return ToolResult(data={"error": str(e)})
    if resolved is None:
        return _err_no_wazuh()
    mgr, _ = resolved
    try:
        params: dict[str, Any] = {"limit": max(1, min(500, int(limit)))}
        if search:
            params["search"] = search
        result = await mgr.get(
            f"/syscollector/{_agent_id_3(agent_id)}/processes",
            params=params,
        )
        rows = (result.get("data") or {}).get("affected_items") or []
        return _enforce_size([
            {
                "pid": r.get("pid"),
                "name": r.get("name"),
                "user": r.get("euser") or r.get("ruser"),
                "command": r.get("cmd"),
                "start_time": r.get("start_time"),
                "state": r.get("state"),
            }
            for r in rows
        ])
    except Exception as e:  # noqa: BLE001
        return _wrap_error(e, op="agent_processes")


async def get_wazuh_cluster_health(
    db: AsyncSession, *, target_tenant_id: UUID | None = None
) -> ToolResult:
    """Wazuh cluster health summary."""
    try:
        resolved = await _resolved(db, target_tenant_id)
    except WazuhNotConfigured as e:
        return ToolResult(data={"error": str(e)})
    if resolved is None:
        return _err_no_wazuh()
    mgr, _ = resolved
    try:
        result = await mgr.get("/cluster/healthcheck")
        return _enforce_size(result.get("data") or {})
    except Exception as e:  # noqa: BLE001
        return _wrap_error(e, op="cluster_health")


async def get_wazuh_cluster_nodes(
    db: AsyncSession,
    *,
    limit: int = 100,
    offset: int = 0,
    type: str | None = None,
    target_tenant_id: UUID | None = None,
) -> ToolResult:
    """List cluster nodes."""
    try:
        resolved = await _resolved(db, target_tenant_id)
    except WazuhNotConfigured as e:
        return ToolResult(data={"error": str(e)})
    if resolved is None:
        return _err_no_wazuh()
    mgr, _ = resolved
    try:
        params: dict[str, Any] = {
            "limit": max(1, min(500, int(limit))),
            "offset": max(0, int(offset)),
        }
        if type:
            params["type"] = type
        result = await mgr.get("/cluster/nodes", params=params)
        rows = (result.get("data") or {}).get("affected_items") or []
        return _enforce_size([
            {
                "name": r.get("name"),
                "type": r.get("type"),
                "version": r.get("version"),
                "ip": r.get("ip"),
            }
            for r in rows
        ])
    except Exception as e:  # noqa: BLE001
        return _wrap_error(e, op="cluster_nodes")


async def search_wazuh_manager_logs(
    db: AsyncSession,
    *,
    limit: int = 100,
    offset: int = 0,
    level: str | None = None,
    tag: str | None = None,
    search: str | None = None,
    target_tenant_id: UUID | None = None,
) -> ToolResult:
    """Search the manager's ossec.log."""
    try:
        resolved = await _resolved(db, target_tenant_id)
    except WazuhNotConfigured as e:
        return ToolResult(data={"error": str(e)})
    if resolved is None:
        return _err_no_wazuh()
    mgr, _ = resolved
    try:
        params: dict[str, Any] = {
            "limit": max(1, min(500, int(limit))),
            "offset": max(0, int(offset)),
        }
        if level:
            params["level"] = level
        if tag:
            params["tag"] = tag
        if search:
            params["search"] = search
        result = await mgr.get("/manager/logs", params=params)
        rows = (result.get("data") or {}).get("affected_items") or []
        return _enforce_size([
            {
                "timestamp": r.get("timestamp"),
                "tag": r.get("tag"),
                "level": r.get("level"),
                "description": r.get("description"),
            }
            for r in rows
        ])
    except Exception as e:  # noqa: BLE001
        return _wrap_error(e, op="manager_logs_search")


async def get_wazuh_manager_error_logs(
    db: AsyncSession,
    *,
    limit: int = 100,
    target_tenant_id: UUID | None = None,
) -> ToolResult:
    """Manager logs filtered to level=error (convenience wrapper)."""
    return await search_wazuh_manager_logs(
        db, limit=limit, level="error", target_tenant_id=target_tenant_id
    )


async def get_wazuh_log_collector_stats(
    db: AsyncSession,
    *,
    agent_id: str,
    target_tenant_id: UUID | None = None,
) -> ToolResult:
    """Log-collector stats for a specific agent."""
    try:
        resolved = await _resolved(db, target_tenant_id)
    except WazuhNotConfigured as e:
        return ToolResult(data={"error": str(e)})
    if resolved is None:
        return _err_no_wazuh()
    mgr, _ = resolved
    try:
        result = await mgr.get(
            f"/agents/{_agent_id_3(agent_id)}/stats/logcollector"
        )
        return _enforce_size((result.get("data") or {}).get("affected_items") or [])
    except Exception as e:  # noqa: BLE001
        return _wrap_error(e, op="log_collector_stats")


async def get_wazuh_remoted_stats(
    db: AsyncSession, *, target_tenant_id: UUID | None = None
) -> ToolResult:
    """Manager remoted-daemon stats."""
    try:
        resolved = await _resolved(db, target_tenant_id)
    except WazuhNotConfigured as e:
        return ToolResult(data={"error": str(e)})
    if resolved is None:
        return _err_no_wazuh()
    mgr, _ = resolved
    try:
        result = await mgr.get("/manager/stats/remoted")
        return _enforce_size((result.get("data") or {}).get("affected_items") or [])
    except Exception as e:  # noqa: BLE001
        return _wrap_error(e, op="remoted_stats")


async def get_wazuh_agent_ports(
    db: AsyncSession,
    *,
    agent_id: str,
    limit: int = 100,
    protocol: str | None = None,
    state: str | None = None,
    target_tenant_id: UUID | None = None,
) -> ToolResult:
    """Network ports seen on an agent."""
    try:
        resolved = await _resolved(db, target_tenant_id)
    except WazuhNotConfigured as e:
        return ToolResult(data={"error": str(e)})
    if resolved is None:
        return _err_no_wazuh()
    mgr, _ = resolved
    try:
        params: dict[str, Any] = {"limit": max(1, min(500, int(limit)))}
        if protocol:
            params["protocol"] = protocol
        if state:
            params["state"] = state
        result = await mgr.get(
            f"/syscollector/{_agent_id_3(agent_id)}/ports",
            params=params,
        )
        rows = (result.get("data") or {}).get("affected_items") or []
        return _enforce_size([
            {
                "protocol": r.get("protocol"),
                "local_ip": (r.get("local") or {}).get("ip"),
                "local_port": (r.get("local") or {}).get("port"),
                "remote_ip": (r.get("remote") or {}).get("ip"),
                "remote_port": (r.get("remote") or {}).get("port"),
                "state": r.get("state"),
                "process": r.get("process"),
                "pid": r.get("pid"),
            }
            for r in rows
        ])
    except Exception as e:  # noqa: BLE001
        return _wrap_error(e, op="agent_ports")


async def get_wazuh_weekly_stats(
    db: AsyncSession, *, target_tenant_id: UUID | None = None
) -> ToolResult:
    """Manager weekly activity stats."""
    try:
        resolved = await _resolved(db, target_tenant_id)
    except WazuhNotConfigured as e:
        return ToolResult(data={"error": str(e)})
    if resolved is None:
        return _err_no_wazuh()
    mgr, _ = resolved
    try:
        result = await mgr.get("/manager/stats/weekly")
        return _enforce_size((result.get("data") or {}).get("affected_items") or [])
    except Exception as e:  # noqa: BLE001
        return _wrap_error(e, op="weekly_stats")


# ---------------------------------------------------------------------------
# ChatTool registry — exported for chat/tools.py to merge into AVAILABLE_TOOLS.
# ---------------------------------------------------------------------------


WAZUH_CHAT_TOOLS: tuple[ChatTool, ...] = (
    ChatTool(
        name="get_wazuh_alert_summary",
        description=(
            "Recent Wazuh alerts from the wazuh-alerts indexer. Returns rule ID, "
            "level, description, agent, src/dst IP, and timestamp. Use for "
            "questions about specific alert content or recent alert volume."
        ),
        schema={
            "type": "object",
            "properties": {
                "limit": {"type": "integer", "minimum": 1, "maximum": 300},
                **_TENANT_SLUG_PROP,
            },
        },
        func=get_wazuh_alert_summary,
    ),
    ChatTool(
        name="get_wazuh_rules_summary",
        description=(
            "Wazuh rule definitions. Filter by level (e.g. 12+ for high-sev), "
            "group (e.g. 'authentication_failed', 'mitre'), or filename. Use "
            "when the user asks 'what rule fired' or 'show rules matching X'."
        ),
        schema={
            "type": "object",
            "properties": {
                "limit": {"type": "integer", "minimum": 1, "maximum": 500},
                "level": {"type": "integer", "minimum": 0, "maximum": 16},
                "group": {"type": "string"},
                "filename": {"type": "string"},
                **_TENANT_SLUG_PROP,
            },
        },
        func=get_wazuh_rules_summary,
    ),
    ChatTool(
        name="get_wazuh_vulnerability_summary",
        description=(
            "Vulnerability records for one agent. Filter by severity "
            "(Low|Medium|High|Critical) or CVE ID."
        ),
        schema={
            "type": "object",
            "properties": {
                "agent_id": {"type": "string"},
                "limit": {"type": "integer", "minimum": 1, "maximum": 300},
                "severity": {
                    "type": "string",
                    "enum": ["Low", "Medium", "High", "Critical"],
                },
                "cve": {"type": "string"},
                **_TENANT_SLUG_PROP,
            },
            "required": ["agent_id"],
        },
        func=get_wazuh_vulnerability_summary,
    ),
    ChatTool(
        name="get_wazuh_critical_vulnerabilities",
        description="Critical-severity vulnerabilities for one agent.",
        schema={
            "type": "object",
            "properties": {
                "agent_id": {"type": "string"},
                "limit": {"type": "integer", "minimum": 1, "maximum": 300},
                **_TENANT_SLUG_PROP,
            },
            "required": ["agent_id"],
        },
        func=get_wazuh_critical_vulnerabilities,
    ),
    ChatTool(
        name="get_wazuh_agents",
        description=(
            "List Wazuh agents. Filters: status (active|disconnected|pending|"
            "never_connected), name, ip, group, os_platform, version."
        ),
        schema={
            "type": "object",
            "properties": {
                "limit": {"type": "integer", "minimum": 1, "maximum": 500},
                "status": {
                    "type": "string",
                    "enum": ["active", "disconnected", "pending", "never_connected"],
                },
                "name": {"type": "string"},
                "ip": {"type": "string"},
                "group": {"type": "string"},
                "os_platform": {"type": "string"},
                "version": {"type": "string"},
                **_TENANT_SLUG_PROP,
            },
        },
        func=get_wazuh_agents,
    ),
    ChatTool(
        name="get_wazuh_agent_processes",
        description=(
            "Processes the Wazuh syscollector recorded for an agent. Optional "
            "search filter on process name / command."
        ),
        schema={
            "type": "object",
            "properties": {
                "agent_id": {"type": "string"},
                "limit": {"type": "integer", "minimum": 1, "maximum": 500},
                "search": {"type": "string"},
                **_TENANT_SLUG_PROP,
            },
            "required": ["agent_id"],
        },
        func=get_wazuh_agent_processes,
    ),
    ChatTool(
        name="get_wazuh_cluster_health",
        description="Wazuh cluster health summary.",
        schema={
            "type": "object",
            "properties": {**_TENANT_SLUG_PROP},
        },
        func=get_wazuh_cluster_health,
    ),
    ChatTool(
        name="get_wazuh_cluster_nodes",
        description="List Wazuh cluster nodes.",
        schema={
            "type": "object",
            "properties": {
                "limit": {"type": "integer", "minimum": 1, "maximum": 500},
                "offset": {"type": "integer", "minimum": 0},
                "type": {"type": "string", "enum": ["master", "worker"]},
                **_TENANT_SLUG_PROP,
            },
        },
        func=get_wazuh_cluster_nodes,
    ),
    ChatTool(
        name="search_wazuh_manager_logs",
        description=(
            "Search the manager's ossec.log. Filter by level "
            "(error|warning|info), tag (e.g. 'wazuh-modulesd'), and free-text "
            "search."
        ),
        schema={
            "type": "object",
            "properties": {
                "limit": {"type": "integer", "minimum": 1, "maximum": 500},
                "offset": {"type": "integer", "minimum": 0},
                "level": {"type": "string", "enum": ["error", "warning", "info"]},
                "tag": {"type": "string"},
                "search": {"type": "string"},
                **_TENANT_SLUG_PROP,
            },
        },
        func=search_wazuh_manager_logs,
    ),
    ChatTool(
        name="get_wazuh_manager_error_logs",
        description="Convenience wrapper: manager log lines filtered to level=error.",
        schema={
            "type": "object",
            "properties": {
                "limit": {"type": "integer", "minimum": 1, "maximum": 500},
                **_TENANT_SLUG_PROP,
            },
        },
        func=get_wazuh_manager_error_logs,
    ),
    ChatTool(
        name="get_wazuh_log_collector_stats",
        description="Log-collector stats for one agent.",
        schema={
            "type": "object",
            "properties": {
                "agent_id": {"type": "string"},
                **_TENANT_SLUG_PROP,
            },
            "required": ["agent_id"],
        },
        func=get_wazuh_log_collector_stats,
    ),
    ChatTool(
        name="get_wazuh_remoted_stats",
        description="Manager remoted-daemon stats (connection / message counts).",
        schema={
            "type": "object",
            "properties": {**_TENANT_SLUG_PROP},
        },
        func=get_wazuh_remoted_stats,
    ),
    ChatTool(
        name="get_wazuh_agent_ports",
        description=(
            "Network ports seen on an agent. Filter by protocol "
            "(tcp|udp) and state (LISTENING|ESTABLISHED|…)."
        ),
        schema={
            "type": "object",
            "properties": {
                "agent_id": {"type": "string"},
                "limit": {"type": "integer", "minimum": 1, "maximum": 500},
                "protocol": {"type": "string", "enum": ["tcp", "udp"]},
                "state": {"type": "string"},
                **_TENANT_SLUG_PROP,
            },
            "required": ["agent_id"],
        },
        func=get_wazuh_agent_ports,
    ),
    ChatTool(
        name="get_wazuh_weekly_stats",
        description="Manager weekly activity stats.",
        schema={
            "type": "object",
            "properties": {**_TENANT_SLUG_PROP},
        },
        func=get_wazuh_weekly_stats,
    ),
)
