"""Integration settings for MCP servers and notifications.

The Settings UI persists non-secret runtime preferences (enabled flags, URLs, and
toggles) in the database. Secrets (API keys, passwords, webhook URLs) are read
from environment variables only.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional
from urllib.parse import urlsplit

import structlog

from soctalk.config import MCPServerConfig

logger = structlog.get_logger()


@dataclass
class IntegrationSettings:
    """Non-secret integration settings (DB-backed, env-seeded)."""

    # Wazuh SIEM
    wazuh_enabled: bool = False
    wazuh_url: Optional[str] = None
    wazuh_verify_ssl: bool = True

    # Cortex
    cortex_enabled: bool = False
    cortex_url: Optional[str] = None
    cortex_verify_ssl: bool = True

    # TheHive
    thehive_enabled: bool = False
    thehive_url: Optional[str] = None
    thehive_organisation: Optional[str] = None
    thehive_verify_ssl: bool = True

    # MISP
    misp_enabled: bool = False
    misp_url: Optional[str] = None
    misp_verify_ssl: bool = True

    # Slack
    slack_enabled: bool = False
    slack_channel: Optional[str] = None
    slack_notify_on_escalation: bool = True
    slack_notify_on_verdict: bool = True


def _parse_bool(value: str | None, default: bool) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def load_integration_settings_from_env() -> IntegrationSettings:
    """Load non-secret integration settings from environment variables."""
    wazuh_url = os.getenv("WAZUH_URL")
    if not wazuh_url:
        host = os.getenv("WAZUH_API_HOST")
        port = os.getenv("WAZUH_API_PORT")
        if host and port:
            wazuh_url = f"https://{host}:{port}"

    cortex_url = os.getenv("CORTEX_URL") or os.getenv("CORTEX_ENDPOINT")

    return IntegrationSettings(
        # Wazuh
        wazuh_enabled=_parse_bool(os.getenv("WAZUH_ENABLED"), False),
        wazuh_url=wazuh_url,
        wazuh_verify_ssl=_parse_bool(os.getenv("WAZUH_VERIFY_SSL"), True),
        # Cortex
        cortex_enabled=_parse_bool(os.getenv("CORTEX_ENABLED"), False),
        cortex_url=cortex_url,
        cortex_verify_ssl=_parse_bool(os.getenv("CORTEX_VERIFY_SSL"), True),
        # TheHive
        thehive_enabled=_parse_bool(os.getenv("THEHIVE_ENABLED"), False),
        thehive_url=os.getenv("THEHIVE_URL"),
        thehive_organisation=os.getenv("THEHIVE_ORGANISATION"),
        thehive_verify_ssl=_parse_bool(os.getenv("THEHIVE_VERIFY_SSL"), True),
        # MISP
        misp_enabled=_parse_bool(os.getenv("MISP_ENABLED"), False),
        misp_url=os.getenv("MISP_URL"),
        misp_verify_ssl=_parse_bool(os.getenv("MISP_VERIFY_SSL"), True),
        # Slack
        slack_enabled=_parse_bool(os.getenv("SLACK_ENABLED"), False),
        slack_channel=os.getenv("SLACK_CHANNEL"),
        slack_notify_on_escalation=_parse_bool(os.getenv("SLACK_NOTIFY_ON_ESCALATION"), True),
        slack_notify_on_verdict=_parse_bool(os.getenv("SLACK_NOTIFY_ON_VERDICT"), True),
    )


def create_wazuh_mcp_config(settings: IntegrationSettings) -> Optional[MCPServerConfig]:
    """Create Wazuh MCP server config from integration settings.

    Args:
        settings: Integration settings from database.

    Returns:
        MCPServerConfig if Wazuh is enabled and configured, None otherwise.
    """
    if not settings.wazuh_enabled:
        return None

    if not settings.wazuh_url:
        logger.warning("wazuh_enabled_but_url_missing")
        return None

    secrets = load_integration_secrets_from_env()
    if not secrets.wazuh_username or not secrets.wazuh_password:
        logger.warning(
            "wazuh_enabled_but_missing_credentials",
            username=bool(secrets.wazuh_username),
            password=bool(secrets.wazuh_password),
        )
        return None

    url = settings.wazuh_url
    if "://" not in url:
        url = f"https://{url}"

    parsed = urlsplit(url)
    host = parsed.hostname or "localhost"
    port = str(parsed.port or 55000)

    base_path = Path(os.getenv("MCP_SERVERS_BASE_PATH", ".."))

    return MCPServerConfig(
        name="wazuh",
        path=Path(
            os.getenv(
                "WAZUH_MCP_SERVER_PATH",
                str(base_path / "mcp-server-wazuh" / "target" / "release" / "mcp-server-wazuh"),
            )
        ),
        env_vars={
            "WAZUH_API_HOST": host,
            "WAZUH_API_PORT": port,
            "WAZUH_API_USERNAME": secrets.wazuh_username,
            "WAZUH_API_PASSWORD": secrets.wazuh_password,
            "WAZUH_INDEXER_HOST": os.getenv("WAZUH_INDEXER_HOST", host),
            "WAZUH_INDEXER_PORT": os.getenv("WAZUH_INDEXER_PORT", "9200"),
            "WAZUH_INDEXER_USERNAME": os.getenv("WAZUH_INDEXER_USERNAME", "admin"),
            "WAZUH_INDEXER_PASSWORD": os.getenv("WAZUH_INDEXER_PASSWORD", "admin"),
            "WAZUH_VERIFY_SSL": "true" if settings.wazuh_verify_ssl else "false",
        },
    )


def create_cortex_mcp_config(settings: IntegrationSettings) -> Optional[MCPServerConfig]:
    """Create Cortex MCP server config from integration settings.

    Args:
        settings: Integration settings from database.

    Returns:
        MCPServerConfig if Cortex is enabled and configured, None otherwise.
    """
    if not settings.cortex_enabled:
        return None

    secrets = load_integration_secrets_from_env()

    if not settings.cortex_url or not secrets.cortex_api_key:
        logger.warning(
            "cortex_enabled_but_missing_config",
            url=bool(settings.cortex_url),
            api_key=bool(secrets.cortex_api_key),
        )
        return None

    base_path = Path(os.getenv("MCP_SERVERS_BASE_PATH", ".."))

    return MCPServerConfig(
        name="cortex",
        path=Path(
            os.getenv(
                "CORTEX_MCP_SERVER_PATH",
                str(base_path / "mcp-server-cortex" / "target" / "release" / "mcp-server-cortex"),
            )
        ),
        env_vars={
            "CORTEX_ENDPOINT": settings.cortex_url,
            "CORTEX_API_KEY": secrets.cortex_api_key,
            "CORTEX_VERIFY_SSL": "true" if settings.cortex_verify_ssl else "false",
        },
    )


def create_thehive_mcp_config(settings: IntegrationSettings) -> Optional[MCPServerConfig]:
    """Create TheHive MCP server config from integration settings.

    Args:
        settings: Integration settings from database.

    Returns:
        MCPServerConfig if TheHive is enabled and configured, None otherwise.
    """
    if not settings.thehive_enabled:
        return None

    secrets = load_integration_secrets_from_env()

    if not settings.thehive_url or not secrets.thehive_api_key:
        logger.warning(
            "thehive_enabled_but_missing_config",
            url=bool(settings.thehive_url),
            api_key=bool(secrets.thehive_api_key),
        )
        return None

    base_path = Path(os.getenv("MCP_SERVERS_BASE_PATH", ".."))

    env_vars = {
        "THEHIVE_URL": settings.thehive_url,
        "THEHIVE_API_TOKEN": secrets.thehive_api_key,
        "VERIFY_SSL": "true" if settings.thehive_verify_ssl else "false",
    }

    if settings.thehive_organisation:
        env_vars["THEHIVE_ORGANISATION"] = settings.thehive_organisation

    return MCPServerConfig(
        name="thehive",
        path=Path(
            os.getenv(
                "THEHIVE_MCP_SERVER_PATH",
                str(base_path / "mcp-server-thehive" / "target" / "release" / "mcp-server-thehive"),
            )
        ),
        env_vars=env_vars,
    )


def create_misp_mcp_config(settings: IntegrationSettings) -> Optional[MCPServerConfig]:
    """Create MISP MCP server config from integration settings.

    Args:
        settings: Integration settings from database.

    Returns:
        MCPServerConfig if MISP is enabled and configured, None otherwise.
    """
    if not settings.misp_enabled:
        return None

    secrets = load_integration_secrets_from_env()

    if not settings.misp_url or not secrets.misp_api_key:
        logger.warning(
            "misp_enabled_but_missing_config",
            url=bool(settings.misp_url),
            api_key=bool(secrets.misp_api_key),
        )
        return None

    base_path = Path(os.getenv("MCP_SERVERS_BASE_PATH", ".."))

    return MCPServerConfig(
        name="misp",
        path=Path(
            os.getenv(
                "MISP_MCP_SERVER_PATH",
                str(base_path / "mcp-server-misp" / "target" / "release" / "mcp-server-misp"),
            )
        ),
        env_vars={
            "MISP_URL": settings.misp_url,
            "MISP_API_KEY": secrets.misp_api_key,
            "MISP_VERIFY_SSL": "true" if settings.misp_verify_ssl else "false",
        },
    )


@dataclass
class EnabledMCPServers:
    """Container for enabled MCP server configurations."""

    wazuh: Optional[MCPServerConfig] = None
    cortex: Optional[MCPServerConfig] = None
    thehive: Optional[MCPServerConfig] = None
    misp: Optional[MCPServerConfig] = None

    @property
    def has_any_enabled(self) -> bool:
        """Check if any MCP server is enabled."""
        return any([self.wazuh, self.cortex, self.thehive, self.misp])

    @property
    def enabled_count(self) -> int:
        """Count of enabled MCP servers."""
        return sum(1 for s in [self.wazuh, self.cortex, self.thehive, self.misp] if s is not None)


def create_mcp_configs(settings: IntegrationSettings) -> EnabledMCPServers:
    """Create MCP server configurations based on integration settings.

    Args:
        settings: Integration settings from database.

    Returns:
        EnabledMCPServers with configs for enabled integrations.
    """
    return EnabledMCPServers(
        wazuh=create_wazuh_mcp_config(settings),
        cortex=create_cortex_mcp_config(settings),
        thehive=create_thehive_mcp_config(settings),
        misp=create_misp_mcp_config(settings),
    )
