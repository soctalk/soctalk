"""Per-tenant adapter ingest settings for external Wazuh tenants.

The adapter already understands four ingest knobs through its environment
(``SOCTALK_ADAPTER_EXCLUDE_MANAGER_AGENT``, ``SOCTALK_INGEST_INITIAL_TS``,
``SOCTALK_ADAPTER_AGENT_PREFIX``, ``SOCTALK_ADAPTER_MIN_SEVERITY``), but
nothing persisted them per tenant: the chart rendered only an install-wide
severity floor, and the manager-agent exclusion was hard-wired on. That
default exists for the managed profiles, where agent 000 is the in-cluster
manager pod's own FIM/monitord noise. On a ``provided`` tenant agent 000 is
the external manager itself, which is where the Office 365 / cloud wodles
and remote syslog land, so the exclusion silently dropped every one of those
alerts while the tenant reported healthy.

All four columns are nullable and NULL means "default", so existing rows
keep today's behaviour until an operator sets a value.

Revision ID: v1_0048_tenant_ingest_settings
Revises: v1_0047_tenant_llm_engine
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "v1_0048_tenant_ingest_settings"
down_revision = "v1_0047_tenant_llm_engine"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "integration_configs",
        sa.Column("wazuh_ingest_exclude_manager_agent", sa.Boolean(), nullable=True),
    )
    op.add_column(
        "integration_configs",
        sa.Column("wazuh_ingest_initial_ts", sa.String(length=64), nullable=True),
    )
    op.add_column(
        "integration_configs",
        sa.Column("wazuh_ingest_agent_prefix", sa.String(length=255), nullable=True),
    )
    op.add_column(
        "integration_configs",
        sa.Column("wazuh_ingest_min_severity", sa.Integer(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("integration_configs", "wazuh_ingest_min_severity")
    op.drop_column("integration_configs", "wazuh_ingest_agent_prefix")
    op.drop_column("integration_configs", "wazuh_ingest_initial_ts")
    op.drop_column("integration_configs", "wazuh_ingest_exclude_manager_agent")
