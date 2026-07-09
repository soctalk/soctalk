"""alert_source_events (idempotency + evidence) and adapter_checkpoints.

Issue #17 tranches 2 (foundations), 3 (idempotency/evidence), 5 (checkpoint).

- ``alert_source_events``: one row per ingested source event. UNIQUE
  (tenant_id, source, source_event_id) is the DB-enforced idempotency
  guarantee (fix 7) — a replayed event conflicts and no-ops. Doubles as
  the evidence store (fix 3): redacted full_log, entities, mitre, rule
  metadata, template hash, three timestamps (fix 5), retention_until.
- ``adapter_checkpoints``: durable per-(tenant, source) ingest cursor so
  a pod restart resumes instead of resetting (fix 6), plus dropped_total
  for loss accounting.

Both tenant-scoped with the same RLS + grant shape as the chat/events
tables. Hand-written against migrated table names (core/ir/models.py is
stale vs the case->investigation rename — do not autogenerate).

Revision ID: v1_0018_source_events_and_checkpoints
Revises: v1_0017_drop_bootstrap_tenant
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "v1_0018_source_events_and_checkpoints"
down_revision: str | None = "v1_0017_drop_bootstrap_tenant"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Dedicated description column on alerts (issue #17 fix 3): triage used
    # to write the human-readable log line into ``ai_assessment``, clobbering
    # the rules-based assess() label the column is named for. Give the log
    # text its own home; the worker claim reads this with a COALESCE fallback
    # to ai_assessment for rows written before this migration.
    op.add_column("alerts", sa.Column("description", sa.Text(), nullable=True))

    op.create_table(
        "alert_source_events",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "tenant_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("tenants.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("source", sa.Text(), nullable=False),
        sa.Column("source_event_id", sa.Text(), nullable=False),
        sa.Column(
            "alert_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("alerts.id", ondelete="CASCADE"),
            nullable=True,
        ),
        # Three timestamps (fix 5): occurrence, adapter observation, server ingest.
        sa.Column("occurred_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("observed_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column(
            "ingested_at",
            sa.TIMESTAMP(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        # Evidence (fix 3) — redacted text + structured decoder output.
        sa.Column("description_redacted", sa.Text(), nullable=True),
        sa.Column("full_log_redacted", sa.Text(), nullable=True),
        sa.Column(
            "entities",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column(
            "mitre",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column(
            "rule_groups",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column("decoder", sa.Text(), nullable=True),
        sa.Column("template_hash", sa.Text(), nullable=True),
        sa.Column("template_version", sa.Text(), nullable=True),
        sa.Column("redaction_version", sa.Text(), nullable=True),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default=sa.text("1")),
        sa.Column("batch_seq", sa.BigInteger(), nullable=True),
        sa.Column("retention_until", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column(
            "visibility",
            sa.Text(),
            nullable=False,
            server_default=sa.text("'mssp_only'"),
        ),
        sa.UniqueConstraint(
            "tenant_id",
            "source",
            "source_event_id",
            name="uq_source_events_idempotency",
        ),
    )
    op.create_index(
        "ix_source_events_alert",
        "alert_source_events",
        ["tenant_id", "alert_id"],
    )
    op.create_index(
        "ix_source_events_template",
        "alert_source_events",
        ["tenant_id", "template_hash"],
    )

    op.create_table(
        "adapter_checkpoints",
        sa.Column(
            "tenant_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("tenants.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column("source", sa.Text(), primary_key=True),
        sa.Column("cursor_ts", sa.Text(), nullable=True),
        sa.Column("cursor_event_id", sa.Text(), nullable=True),
        sa.Column("batch_seq", sa.BigInteger(), nullable=False, server_default=sa.text("0")),
        sa.Column("dropped_total", sa.BigInteger(), nullable=False, server_default=sa.text("0")),
        sa.Column(
            "updated_at",
            sa.TIMESTAMP(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
    )

    for table in ("alert_source_events", "adapter_checkpoints"):
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY;")
        op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY;")
        op.execute(
            f"""
            CREATE POLICY {table}_tenant_isolation ON {table}
                FOR ALL
                TO soctalk_app
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
        # MSSP (BYPASSRLS) role also needs table grants to read evidence.
        op.execute(f"GRANT SELECT, INSERT, UPDATE, DELETE ON {table} TO soctalk_mssp;")


def downgrade() -> None:
    for table in ("adapter_checkpoints", "alert_source_events"):
        op.execute(f'DROP POLICY IF EXISTS "{table}_tenant_isolation" ON "{table}"')
    op.drop_table("adapter_checkpoints")
    op.drop_index("ix_source_events_template", table_name="alert_source_events")
    op.drop_index("ix_source_events_alert", table_name="alert_source_events")
    op.drop_table("alert_source_events")
    op.drop_column("alerts", "description")
