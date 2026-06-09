"""IntegrationConfig: separate Wazuh Indexer credentials for 'provided' profile.

Revision ID: v1_0015_wazuh_indexer_credentials
Revises: v1_0012_integration_external_wazuh
Create Date: 2026-06-02

Context
-------
The ``provided`` deployment profile (tenant brings their own external
Wazuh) needs TWO distinct credential pairs, because the Wazuh **API**
(manager, :55000) and the Wazuh **Indexer** (OpenSearch, :9200)
authenticate independently. This mirrors:

  * the in-cluster ``charts/wazuh`` ``credentials`` block, which has
    separate ``apiUsername``/``apiPassword`` and
    ``indexerUsername``/``indexerPassword`` keys; and
  * the per-tenant ``*-wazuh-creds`` Secret consumed by the adapter and
    the chat agent's Wazuh resolver, which carries four keys:
    ``WAZUH_API_USERNAME``, ``WAZUH_API_PASSWORD``,
    ``INDEXER_USERNAME``, ``INDEXER_PASSWORD``.

v1_0012 added a single credential pair (``wazuh_username`` /
``wazuh_password_plain``) plus the API token and both URLs. Those columns
now carry the **API** credentials. This revision adds the two missing
**Indexer** credential columns:

  * wazuh_indexer_username        VARCHAR(255)
  * wazuh_indexer_password_plain  VARCHAR(4096)

Plaintext storage mirrors the existing ``llm_api_key_plain`` /
``wazuh_password_plain`` compromise; KMS/Fernet hardening is tracked as a
cross-column follow-up.

Reversible.
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision: str = "v1_0015_wazuh_indexer_credentials"
down_revision: str | None = "v1_0012_integration_external_wazuh"
branch_labels: str | None = None
depends_on: str | None = None


_COLUMNS: list[tuple[str, int]] = [
    ("wazuh_indexer_username", 255),
    ("wazuh_indexer_password_plain", 4096),
]


def upgrade() -> None:
    for name, length in _COLUMNS:
        op.add_column(
            "integration_configs",
            sa.Column(name, sa.String(length=length), nullable=True),
        )


def downgrade() -> None:
    for name, _length in reversed(_COLUMNS):
        op.drop_column("integration_configs", name)
