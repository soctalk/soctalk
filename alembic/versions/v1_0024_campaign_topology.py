"""Campaign discrimination + topology (issue #31).

Extends the #24 model with the layer above the foundation:

- ``engagements``: declared pentest/red-team windows (source of truth for
  deconfliction) with scope — a queryable set so out-of-scope tester
  activity becomes a set-difference (a contractual finding, not a false
  alarm).
- ``activity_clusters``: inferred campaigns — groups of alerts/investigations
  characterized as declared-test | benign-probe | inferred-test | campaign.
  An inferred-benign classification is a FLAG for confirmation, never a
  silent suppression (mimicry is the obvious adversarial move).
- ``topology_edges``: hosts/services/ports/adjacency. Encodes potential
  (routable-but-unseen) vs observed adjacency distinctly — paths over
  never-observed edges are the interesting ones. Bitemporal / supersede-on-
  absence, reusing #24 semantics.

Revision ID: v1_0024_campaign_topology
Revises: v1_0023_entity_graph
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "v1_0024_campaign_topology"
down_revision: str | None = "v1_0023_entity_graph"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "engagements",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "tenant_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("tenants.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("kind", sa.Text(), nullable=False, server_default=sa.text("'pentest'")),
        sa.Column("starts_at", sa.TIMESTAMP(timezone=True), nullable=False),
        sa.Column("ends_at", sa.TIMESTAMP(timezone=True), nullable=False),
        # Scope: tester source ips/cidrs, in-scope hosts, permitted techniques.
        sa.Column("scope_source_ips", postgresql.JSONB(), nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("scope_hosts", postgresql.JSONB(), nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("scope_techniques", postgresql.JSONB(), nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("created_at", sa.TIMESTAMP(timezone=True), nullable=False, server_default=sa.text("now()")),
    )
    op.create_index("ix_engagements_window", "engagements", ["tenant_id", "starts_at", "ends_at"])

    op.create_table(
        "activity_clusters",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "tenant_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("tenants.id", ondelete="CASCADE"),
            nullable=False,
        ),
        # 'declared_test' | 'benign_probe' | 'inferred_test' | 'campaign'
        sa.Column("classification", sa.Text(), nullable=False),
        sa.Column("confidence_score", sa.Integer(), nullable=True),
        sa.Column("engagement_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("features", postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("investigation_ids", postgresql.JSONB(), nullable=False, server_default=sa.text("'[]'::jsonb")),
        # Set true only for inferred-benign: needs analyst confirmation,
        # never silently suppresses.
        sa.Column("needs_confirmation", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("created_at", sa.TIMESTAMP(timezone=True), nullable=False, server_default=sa.text("now()")),
    )
    op.create_index("ix_clusters_tenant", "activity_clusters", ["tenant_id", "classification"])

    op.create_table(
        "topology_edges",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "tenant_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("tenants.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("src_host", sa.Text(), nullable=False),
        sa.Column("dst_host", sa.Text(), nullable=False),
        sa.Column("port", sa.Integer(), nullable=True),
        # 'observed' (traffic actually seen) | 'potential' (routable, unseen)
        sa.Column("adjacency", sa.Text(), nullable=False, server_default=sa.text("'potential'")),
        # Bitemporal / supersede-on-absence (reuse #24 semantics).
        sa.Column("first_seen", sa.TIMESTAMP(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("last_seen", sa.TIMESTAMP(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("superseded_at", sa.TIMESTAMP(timezone=True), nullable=True),
    )
    op.create_index(
        "ix_topology_live", "topology_edges",
        ["tenant_id", "src_host"], postgresql_where=sa.text("superseded_at IS NULL"),
    )

    for table in ("engagements", "activity_clusters", "topology_edges"):
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


def downgrade() -> None:
    for table in ("topology_edges", "activity_clusters", "engagements"):
        op.execute(f'DROP POLICY IF EXISTS "{table}_tenant_isolation" ON "{table}"')
    op.drop_index("ix_topology_live", table_name="topology_edges")
    op.drop_table("topology_edges")
    op.drop_index("ix_clusters_tenant", table_name="activity_clusters")
    op.drop_table("activity_clusters")
    op.drop_index("ix_engagements_window", table_name="engagements")
    op.drop_table("engagements")
