"""Verdict memoization cache (issue #29).

A tenant-scoped cache keyed on a STABLE alert shape — (source, decoder,
template_hash, template_version) — NOT alert_signature (which carries a
5-minute bucket and is useless for long-term recurrence). Maps a shape to
the last structured verdict so a recurring benign pattern can be closed by
reference instead of spinning an LLM run.

Revision ID: v1_0021_verdict_cache
Revises: v1_0020_entity_keys
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "v1_0021_verdict_cache"
down_revision: str | None = "v1_0020_entity_keys"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "verdict_cache",
        sa.Column(
            "tenant_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("tenants.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column("shape_key", sa.Text(), primary_key=True),
        sa.Column("decision", sa.Text(), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False, server_default=sa.text("0")),
        sa.Column("template_hash", sa.Text(), nullable=True),
        sa.Column("hit_count", sa.BigInteger(), nullable=False, server_default=sa.text("0")),
        sa.Column(
            "last_verdict_at",
            sa.TIMESTAMP(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
    )

    op.execute("ALTER TABLE verdict_cache ENABLE ROW LEVEL SECURITY;")
    op.execute("ALTER TABLE verdict_cache FORCE ROW LEVEL SECURITY;")
    op.execute(
        """
        CREATE POLICY verdict_cache_tenant_isolation ON verdict_cache
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
    op.execute("GRANT SELECT, INSERT, UPDATE, DELETE ON verdict_cache TO soctalk_app;")
    op.execute("GRANT SELECT, INSERT, UPDATE, DELETE ON verdict_cache TO soctalk_mssp;")


def downgrade() -> None:
    op.execute('DROP POLICY IF EXISTS "verdict_cache_tenant_isolation" ON "verdict_cache"')
    op.drop_table("verdict_cache")
