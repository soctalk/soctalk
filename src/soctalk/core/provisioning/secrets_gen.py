"""Generation of per-tenant secrets at provisioning time.

See docs/multi-tenant/secret-placement.md. §5.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass


@dataclass(frozen=True)
class TenantBootstrapSecrets:
    """Random credentials minted when a tenant is first provisioned.

    Stored in the tenant's namespace as K8s Secrets; references in
    ``TenantSecret`` DB table (never the raw material).
    """

    wazuh_admin_pw: str
    wazuh_authd_secret: str
    thehive_admin_pw: str
    thehive_api_token: str
    cortex_admin_pw: str
    cortex_api_key: str
    cassandra_pw: str


def _wazuh_admin_pw() -> str:
    # Wazuh's API user update rejects passwords without a special
    # character (Error 5007). ``token_urlsafe`` emits ``[A-Za-z0-9_-]``,
    # so ~25% of 32-byte outputs are alphanumeric only. Regenerate
    # until at least one ``_`` or ``-`` is present.
    while True:
        pw = secrets.token_urlsafe(32)
        if "_" in pw or "-" in pw:
            return pw


def generate_bootstrap_secrets() -> TenantBootstrapSecrets:
    return TenantBootstrapSecrets(
        wazuh_admin_pw=_wazuh_admin_pw(),
        wazuh_authd_secret=secrets.token_urlsafe(48),
        thehive_admin_pw=secrets.token_urlsafe(32),
        thehive_api_token=secrets.token_urlsafe(48),
        cortex_admin_pw=secrets.token_urlsafe(32),
        cortex_api_key=secrets.token_urlsafe(48),
        cassandra_pw=secrets.token_urlsafe(32),
    )


def bootstrap_as_k8s_secret_data(s: TenantBootstrapSecrets) -> dict[str, str]:
    """Shape the bootstrap secrets as a single K8s Secret's string data block."""
    return {
        "wazuh_admin_pw": s.wazuh_admin_pw,
        "wazuh_authd_secret": s.wazuh_authd_secret,
        "thehive_admin_pw": s.thehive_admin_pw,
        "thehive_api_token": s.thehive_api_token,
        "cortex_admin_pw": s.cortex_admin_pw,
        "cortex_api_key": s.cortex_api_key,
        "cassandra_pw": s.cassandra_pw,
    }
