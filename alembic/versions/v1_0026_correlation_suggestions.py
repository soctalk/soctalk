"""Learned-correlation suggestions (issue #30, review-only).

``correlation_suggestions`` records what the async scorer WOULD attach that
the deterministic predicate (#27) missed — for analyst review, never
auto-attaching. The deterministic entity match stays the only thing that
actually attaches until a labeled offline spike proves the scorer's
precision and an analyst promotes it to enforcement.

Revision ID: v1_0026_correlation_suggestions
Revises: v1_0025_correlation_hardening
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "v1_0026_correlation_suggestions"
down_revision: str | None = "v1_0025_correlation_hardening"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "correlation_suggestions",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "tenant_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("tenants.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("alert_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("suggested_investigation_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("score", sa.Float(), nullable=False),
        # 'suggest' (>= attach threshold) | 'review' (ambiguous band)
        sa.Column("band", sa.Text(), nullable=False),
        sa.Column("features", postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
        # 'pending' | 'accepted' | 'rejected' — analyst disposition (a label
        # source, but distinct from correlation_labels which are the ground
        # truth; the scorer never trains on its own accepted suggestions).
        sa.Column("status", sa.Text(), nullable=False, server_default=sa.text("'pending'")),
        sa.Column("created_at", sa.TIMESTAMP(timezone=True), nullable=False, server_default=sa.text("now()")),
    )
    op.create_index("ix_suggestions_pending", "correlation_suggestions",
                    ["tenant_id", "status", "created_at"])

    op.execute("ALTER TABLE correlation_suggestions ENABLE ROW LEVEL SECURITY;")
    op.execute("ALTER TABLE correlation_suggestions FORCE ROW LEVEL SECURITY;")
    op.execute(
        """
        CREATE POLICY correlation_suggestions_tenant_isolation ON correlation_suggestions
            FOR ALL TO soctalk_app
            USING (NOT (tenant_id IS DISTINCT FROM
                   NULLIF(current_setting('app.current_tenant_id', true), '')::uuid))
            WITH CHECK (NOT (tenant_id IS DISTINCT FROM
                   NULLIF(current_setting('app.current_tenant_id', true), '')::uuid))
        """
    )
    op.execute("GRANT SELECT, INSERT, UPDATE, DELETE ON correlation_suggestions TO soctalk_app;")
    op.execute("GRANT SELECT, INSERT, UPDATE, DELETE ON correlation_suggestions TO soctalk_mssp;")


def downgrade() -> None:
    op.execute('DROP POLICY IF EXISTS "correlation_suggestions_tenant_isolation" ON "correlation_suggestions"')
    op.drop_index("ix_suggestions_pending", table_name="correlation_suggestions")
    op.drop_table("correlation_suggestions")
