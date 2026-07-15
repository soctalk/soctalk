"""Authored playbooks: DB-backed shadow/draft playbook revisions (#44 follow-on).

An append-only revision log for playbooks authored through the API. Authoring is
SHADOW/DRAFT + export-to-YAML only — authored rows NEVER govern the worker directly
(active enforcement stays on the vetted file -> git -> worker-rollout path). Append-only:
every create/edit/retire inserts a new revision; the current state of a playbook is its
highest revision per (tenant, playbook_id). Tenant-scoped with RLS.

Revision ID: v1_0033_authored_playbooks
Revises: v1_0032_engagement_deconfliction
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "v1_0033_authored_playbooks"
down_revision: str | None = "v1_0032_engagement_deconfliction"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "authored_playbook_revisions",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "tenant_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("tenants.id", ondelete="CASCADE"),
            nullable=False,
        ),
        # The logical playbook slug (Playbook.id). Revisions accumulate per (tenant, playbook_id).
        sa.Column("playbook_id", sa.Text(), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False),
        # 'draft' (saved WIP) | 'shadow' (published for shadow evaluation) | 'retired' (deleted).
        # Never 'active': authored playbooks do not govern — export-to-YAML activates them.
        sa.Column("status", sa.Text(), nullable=False, server_default=sa.text("'shadow'")),
        # The validated Playbook definition (status forced to 'shadow' inside).
        sa.Column("definition", postgresql.JSONB(), nullable=False),
        sa.Column("created_by", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("created_at", sa.TIMESTAMP(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.CheckConstraint(
            "status IN ('draft', 'shadow', 'retired')",
            name="ck_authored_playbook_status",
        ),
        sa.UniqueConstraint(
            "tenant_id", "playbook_id", "revision",
            name="uq_authored_playbook_revision",
        ),
    )
    # Latest-revision-per-playbook lookups.
    op.create_index(
        "ix_authored_playbooks_current",
        "authored_playbook_revisions",
        ["tenant_id", "playbook_id", "revision"],
    )

    op.execute("ALTER TABLE authored_playbook_revisions ENABLE ROW LEVEL SECURITY;")
    op.execute("ALTER TABLE authored_playbook_revisions FORCE ROW LEVEL SECURITY;")
    op.execute(
        """
        CREATE POLICY authored_playbook_revisions_tenant_isolation
            ON authored_playbook_revisions
            FOR ALL TO soctalk_app
            USING (NOT (tenant_id IS DISTINCT FROM
                   NULLIF(current_setting('app.current_tenant_id', true), '')::uuid))
            WITH CHECK (NOT (tenant_id IS DISTINCT FROM
                   NULLIF(current_setting('app.current_tenant_id', true), '')::uuid))
        """
    )
    # Grants match the sibling tables. Append-only is enforced in APPLICATION CODE
    # (authoring.py only ever INSERTs revisions) rather than by withholding UPDATE/DELETE:
    # the schema's default privileges re-grant them anyway, and revoking TRUNCATE/DELETE
    # would break the test harness's TRUNCATE ... CASCADE teardown. The UNIQUE
    # (tenant, playbook_id, revision) still prevents a revision from being overwritten.
    op.execute(
        "GRANT SELECT, INSERT, UPDATE, DELETE ON authored_playbook_revisions TO soctalk_app;"
    )
    op.execute(
        "GRANT SELECT, INSERT, UPDATE, DELETE ON authored_playbook_revisions TO soctalk_mssp;"
    )


def downgrade() -> None:
    op.execute(
        'DROP POLICY IF EXISTS "authored_playbook_revisions_tenant_isolation" '
        "ON authored_playbook_revisions"
    )
    op.drop_index(
        "ix_authored_playbooks_current", table_name="authored_playbook_revisions"
    )
    op.drop_table("authored_playbook_revisions")
