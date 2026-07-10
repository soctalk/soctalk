"""Canonical entity graph + MITRE reference (issue #24).

- ``entities``: typed nodes with a deterministic id (UUIDv5 over the
  canonical natural key), first/last seen, per-type retention + audience.
- ``entity_relationships``: bitemporal edges. Observations are
  instantaneous (occurred_at, immutable); state relationships carry world
  time (valid_from/valid_until) and record time (recorded_at/superseded_at)
  and are closed by supersession, never deleted. Every derived edge carries
  provenance (asserter + reliability) and an evidence ref to the #17 store.
- ``mitre_techniques`` / ``mitre_tactics``: ATT&CK reference keyed by
  ATT&CK id (never STIX UUIDs), pinned to a version, honoring deprecation.

Revision ID: v1_0023_entity_graph
Revises: v1_0022_correlation_labels
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "v1_0023_entity_graph"
down_revision: str | None = "v1_0022_correlation_labels"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "entities",
        # Deterministic UUIDv5 — the same natural key always yields this id.
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "tenant_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("tenants.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column("entity_type", sa.Text(), nullable=False),
        sa.Column("canonical_value", sa.Text(), nullable=False),
        sa.Column("attributes", postgresql.JSONB(), nullable=False,
                  server_default=sa.text("'{}'::jsonb")),
        sa.Column("retention_class", sa.Text(), nullable=False, server_default=sa.text("'entity'")),
        sa.Column("visibility", sa.Text(), nullable=False, server_default=sa.text("'mssp_only'")),
        sa.Column("first_seen", sa.TIMESTAMP(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("last_seen", sa.TIMESTAMP(timezone=True), nullable=False, server_default=sa.text("now()")),
    )
    op.create_index("ix_entities_type_value", "entities", ["tenant_id", "entity_type", "canonical_value"])

    op.create_table(
        "entity_relationships",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "tenant_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("tenants.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("src_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("dst_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("verb", sa.Text(), nullable=False),
        sa.Column("role", sa.Text(), nullable=True),          # for event participation
        sa.Column("relation_class", sa.Text(), nullable=False),  # observed | derived
        # Temporal: observation gets occurred_at; state gets valid_* + record time.
        sa.Column("occurred_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("valid_from", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("valid_until", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("recorded_at", sa.TIMESTAMP(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("superseded_at", sa.TIMESTAMP(timezone=True), nullable=True),
        # Provenance + confidence.
        sa.Column("asserter", sa.Text(), nullable=True),
        sa.Column("reliability", sa.Text(), nullable=False, server_default=sa.text("'telemetry'")),
        sa.Column("confidence_score", sa.Integer(), nullable=True),   # 0..100, NULL = not evaluated
        sa.Column("source_event_id", sa.Text(), nullable=True),        # -> #17 evidence store
        sa.Column("investigation_id", postgresql.UUID(as_uuid=True), nullable=True),
    )
    op.create_index("ix_rel_src", "entity_relationships", ["tenant_id", "src_id", "verb"])
    op.create_index("ix_rel_dst", "entity_relationships", ["tenant_id", "dst_id", "verb"])
    # Current-state lookups skip superseded edges.
    op.create_index(
        "ix_rel_live", "entity_relationships",
        ["tenant_id", "src_id"], postgresql_where=sa.text("superseded_at IS NULL"),
    )

    op.create_table(
        "mitre_tactics",
        sa.Column("attack_id", sa.Text(), primary_key=True),   # e.g. TA0006
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("attack_version", sa.Text(), nullable=False),
        sa.Column("deprecated", sa.Boolean(), nullable=False, server_default=sa.text("false")),
    )
    op.create_table(
        "mitre_techniques",
        sa.Column("attack_id", sa.Text(), primary_key=True),   # e.g. T1110 / T1110.001
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("tactic_ids", postgresql.JSONB(), nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("attack_version", sa.Text(), nullable=False),
        sa.Column("deprecated", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("revoked_by", sa.Text(), nullable=True),
    )

    # RLS on the tenant-scoped graph tables (reference tables are global).
    for table in ("entities", "entity_relationships"):
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY;")
        op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY;")
        op.execute(
            f"""
            CREATE POLICY {table}_tenant_isolation ON {table}
                FOR ALL TO soctalk_app
                USING (NOT (tenant_id IS DISTINCT FROM
                       NULLIF(current_setting('app.current_tenant_id', true), '')::uuid))
                WITH CHECK (NOT (tenant_id IS DISTINCT FROM
                       NULLIF(current_setting('app.current_tenant_id', true), '')::uuid))
            """
        )
        op.execute(f"GRANT SELECT, INSERT, UPDATE, DELETE ON {table} TO soctalk_app;")
        op.execute(f"GRANT SELECT, INSERT, UPDATE, DELETE ON {table} TO soctalk_mssp;")
    # Reference tables: readable by app + mssp, written by mssp/admin only.
    for table in ("mitre_tactics", "mitre_techniques"):
        op.execute(f"GRANT SELECT ON {table} TO soctalk_app;")
        op.execute(f"GRANT SELECT, INSERT, UPDATE, DELETE ON {table} TO soctalk_mssp;")


def downgrade() -> None:
    for table in ("entity_relationships", "entities"):
        op.execute(f'DROP POLICY IF EXISTS "{table}_tenant_isolation" ON "{table}"')
    op.drop_table("mitre_techniques")
    op.drop_table("mitre_tactics")
    op.drop_index("ix_rel_live", table_name="entity_relationships")
    op.drop_index("ix_rel_dst", table_name="entity_relationships")
    op.drop_index("ix_rel_src", table_name="entity_relationships")
    op.drop_table("entity_relationships")
    op.drop_index("ix_entities_type_value", table_name="entities")
    op.drop_table("entities")
