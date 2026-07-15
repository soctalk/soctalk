"""Authorization facts: durable, tenant-scoped store for typed AuthorizationFacts.

External parties (FIM/IAM connectors, scripts), analysts (HIL), and SIEM-derived routine
all write typed facts here; the reasoning engine consumes them store-primary. The full
validated fact rides in ``body`` (JSONB); envelope fields are columns for lookup. Revocation
is soft (``revoked_at``) so the audit trail survives. Tenant-scoped with RLS.

Revision ID: v1_0034_authorization_facts
Revises: v1_0033_authored_playbooks
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "v1_0034_authorization_facts"
down_revision: str | None = "v1_0033_authored_playbooks"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "authorization_facts",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "tenant_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("tenants.id", ondelete="CASCADE"),
            nullable=False,
        ),
        # The fact's own envelope id (models.authorization AuthorizationFactBase.id).
        sa.Column("fact_id", sa.Text(), nullable=False),
        sa.Column("kind", sa.Text(), nullable=False),
        sa.Column("track", sa.Text(), nullable=False),
        sa.Column("source_type", sa.Text(), nullable=False),
        sa.Column("trust", sa.Integer(), nullable=False),
        # Queryable scope, lifted from the envelope (kind-dependent).
        sa.Column("subject", sa.Text(), nullable=True),
        sa.Column("target", sa.Text(), nullable=True),
        sa.Column("action", sa.Text(), nullable=True),
        sa.Column("entity_name", sa.Text(), nullable=True),
        sa.Column("valid_from", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("valid_until", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("superseded_by", sa.Text(), nullable=True),
        # Soft-delete revocation (never a hard delete — audit survives).
        sa.Column("revoked_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("revoked_by", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("revoke_reason", sa.Text(), nullable=True),
        sa.Column("created_by", sa.Text(), nullable=False, server_default=sa.text("''")),
        sa.Column(
            "created_at",
            sa.TIMESTAMP(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        # The full validated fact.
        sa.Column("body", postgresql.JSONB(), nullable=False),
        sa.CheckConstraint(
            "kind IN ('grant', 'prohibition', 'change_freeze', 'entity_context')",
            name="ck_authz_fact_kind",
        ),
        sa.CheckConstraint("track IN ('account', 'fim')", name="ck_authz_fact_track"),
        sa.UniqueConstraint("tenant_id", "fact_id", name="uq_authz_facts_tenant_factid"),
    )
    # Current-fact lookups (tenant + not revoked) and scope lookups.
    op.create_index(
        "ix_authz_facts_tenant_current",
        "authorization_facts",
        ["tenant_id", "revoked_at"],
    )
    op.create_index(
        "ix_authz_facts_tenant_scope",
        "authorization_facts",
        ["tenant_id", "subject", "target", "action"],
    )

    op.execute("ALTER TABLE authorization_facts ENABLE ROW LEVEL SECURITY;")
    op.execute("ALTER TABLE authorization_facts FORCE ROW LEVEL SECURITY;")
    op.execute(
        """
        CREATE POLICY authorization_facts_tenant_isolation
            ON authorization_facts
            FOR ALL TO soctalk_app
            USING (NOT (tenant_id IS DISTINCT FROM
                   NULLIF(current_setting('app.current_tenant_id', true), '')::uuid))
            WITH CHECK (NOT (tenant_id IS DISTINCT FROM
                   NULLIF(current_setting('app.current_tenant_id', true), '')::uuid))
        """
    )
    op.execute("GRANT SELECT, INSERT, UPDATE, DELETE ON authorization_facts TO soctalk_app;")
    op.execute("GRANT SELECT, INSERT, UPDATE, DELETE ON authorization_facts TO soctalk_mssp;")


def downgrade() -> None:
    op.execute(
        'DROP POLICY IF EXISTS "authorization_facts_tenant_isolation" ON authorization_facts'
    )
    op.drop_index("ix_authz_facts_tenant_scope", table_name="authorization_facts")
    op.drop_index("ix_authz_facts_tenant_current", table_name="authorization_facts")
    op.drop_table("authorization_facts")
