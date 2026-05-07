"""IntegrationConfig.llm_api_key_plain — per-tenant LLM key in Postgres.

Revision ID: v1_0007_integration_llm_api_key
Revises: v1_0006_agent_dispatch
Create Date: 2026-04-23

Context
-------
The soctalk-tenant chart now templates an LLM API key Secret from
``values.llm.apiKey`` when the cross-cluster path is in use. For that
to work, L1's install-spec builder must be able to read the key at
spec build time — which in turn requires the key to live somewhere L1
can reach. In the legacy collapsed-tier path the key lives in the
in-cluster Secret ``soctalk-system/tenant-<id>-llm``; L1 reaches it
via its own K8s client. In the cross-cluster path that Secret lives
in a cluster L1 can't reach, so the only practical source is the L1
Postgres itself.

MVP tradeoff
------------
This column stores plaintext key material. The trust boundary is the
same one the adapter token and install_helm_release spec already
cross (Postgres + AgentJob spec). Production hardening is to layer
Fernet-at-rest or a KMS-backed column; tracked as follow-up.

Forward-only.
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision: str = "v1_0007_integration_llm_api_key"
down_revision: str | None = "v1_0006_agent_dispatch"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.add_column(
        "integration_configs",
        sa.Column("llm_api_key_plain", sa.Text(), nullable=True),
    )


def downgrade() -> None:
    # Forward-only.
    pass
