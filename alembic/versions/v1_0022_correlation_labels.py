"""Correlation label capture (issue #30, substrate).

``correlation_labels`` records analyst judgments on grouping —
merge (two investigations were the same incident: a false SPLIT),
detach (an alert didn't belong: a false ATTACH), confirm (grouping was
right) — the supervised signal the future learned scorer trains on.
Captured now so labels accumulate before the scorer exists.

Revision ID: v1_0022_correlation_labels
Revises: v1_0021_verdict_cache
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "v1_0022_correlation_labels"
down_revision: str | None = "v1_0021_verdict_cache"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "correlation_labels",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "tenant_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("tenants.id", ondelete="CASCADE"),
            nullable=False,
        ),
        # 'merge' (false split) | 'detach' (false attach) | 'confirm'
        sa.Column("label", sa.Text(), nullable=False),
        sa.Column("investigation_id", postgresql.UUID(as_uuid=True), nullable=True),
        # For merge: the other investigation. For detach: the alert removed.
        sa.Column("other_investigation_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("alert_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("reviewer", sa.Text(), nullable=True),
        sa.Column("note", sa.Text(), nullable=True),
        sa.Column(
            "created_at",
            sa.TIMESTAMP(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
    )
    op.create_index(
        "ix_correlation_labels_tenant",
        "correlation_labels",
        ["tenant_id", "created_at"],
    )

    op.execute("ALTER TABLE correlation_labels ENABLE ROW LEVEL SECURITY;")
    op.execute("ALTER TABLE correlation_labels FORCE ROW LEVEL SECURITY;")
    op.execute(
        """
        CREATE POLICY correlation_labels_tenant_isolation ON correlation_labels
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
    op.execute("GRANT SELECT, INSERT, UPDATE, DELETE ON correlation_labels TO soctalk_app;")
    op.execute("GRANT SELECT, INSERT, UPDATE, DELETE ON correlation_labels TO soctalk_mssp;")


def downgrade() -> None:
    op.execute('DROP POLICY IF EXISTS "correlation_labels_tenant_isolation" ON "correlation_labels"')
    op.drop_index("ix_correlation_labels_tenant", table_name="correlation_labels")
    op.drop_table("correlation_labels")
