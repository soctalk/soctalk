"""Entity correlation index + rarity stats (issue #27).

``alert_entity_keys`` is a projected, rebuildable index over the typed
entities/IOCs an alert carries — one row per (key_type, key_value) an
alert contributes, linked to its investigation. Entity-overlap attach
queries THIS, never a JSONB scan of alert_source_events.entities.

``entity_key_stats`` holds per-tenant, per-key frequency for hub-key
demotion (a corporate-proxy IP seen thousands of times must not correlate
unrelated activity). Maintained incrementally on ingest.

Both tenant-scoped, same RLS/grant shape as the other IR tables.

Revision ID: v1_0020_entity_keys
Revises: v1_0019_run_not_before
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "v1_0020_entity_keys"
down_revision: str | None = "v1_0019_run_not_before"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "alert_entity_keys",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "tenant_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("tenants.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "alert_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("alerts.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "investigation_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("investigations.id", ondelete="CASCADE"),
            nullable=True,
        ),
        # 'host' | 'ip' | 'hash' | 'domain' | 'user' | 'process' | 'port' | 'rule'
        sa.Column("key_type", sa.Text(), nullable=False),
        sa.Column("key_value", sa.Text(), nullable=False),
        # 'strong' (host/hash) | 'conditional' (ip/domain) | 'weak' (rule/user/port)
        sa.Column("strength", sa.Text(), nullable=False, server_default=sa.text("'conditional'")),
        sa.Column(
            "occurred_at",
            sa.TIMESTAMP(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column("expires_at", sa.TIMESTAMP(timezone=True), nullable=True),
    )
    # The lookup: active investigations sharing a key within a window.
    op.create_index(
        "ix_entity_keys_lookup",
        "alert_entity_keys",
        ["tenant_id", "key_type", "key_value", "expires_at"],
    )
    op.create_index(
        "ix_entity_keys_alert",
        "alert_entity_keys",
        ["tenant_id", "alert_id"],
    )

    op.create_table(
        "entity_key_stats",
        sa.Column(
            "tenant_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("tenants.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column("key_type", sa.Text(), primary_key=True),
        sa.Column("key_value", sa.Text(), primary_key=True),
        sa.Column("seen_count", sa.BigInteger(), nullable=False, server_default=sa.text("0")),
        sa.Column(
            "last_seen",
            sa.TIMESTAMP(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
    )

    for table in ("alert_entity_keys", "entity_key_stats"):
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY;")
        op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY;")
        op.execute(
            f"""
            CREATE POLICY {table}_tenant_isolation ON {table}
                FOR ALL TO soctalk_app
                USING (
                    NOT (tenant_id IS DISTINCT FROM
                         NULLIF(current_setting('app.current_tenant_id', true), '')::uuid)
                )
                WITH CHECK (
                    NOT (tenant_id IS DISTINCT FROM
                         NULLIF(current_setting('app.current_tenant_id', true), '')::uuid)
                )
            """
        )
        op.execute(f"GRANT SELECT, INSERT, UPDATE, DELETE ON {table} TO soctalk_app;")
        op.execute(f"GRANT SELECT, INSERT, UPDATE, DELETE ON {table} TO soctalk_mssp;")


def downgrade() -> None:
    for table in ("entity_key_stats", "alert_entity_keys"):
        op.execute(f'DROP POLICY IF EXISTS "{table}_tenant_isolation" ON "{table}"')
    op.drop_table("entity_key_stats")
    op.drop_index("ix_entity_keys_alert", table_name="alert_entity_keys")
    op.drop_index("ix_entity_keys_lookup", table_name="alert_entity_keys")
    op.drop_table("alert_entity_keys")
