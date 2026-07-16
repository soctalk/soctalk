"""Authored response playbooks: DB-backed draft/shadow/active revisions (#49 phase 2).

An append-only revision log for response playbooks authored through the API. Unlike
authored TRIAGE policies (which never govern directly — they export to YAML for the
worker rollout), authored RESPONSE playbooks CAN be genuinely ``active``: the response
dispatcher runs on L1 with DB access, so it reads active/shadow authored rows live at
complete_run time. That makes per-tenant activation a runtime flip, no deploy. Append-only:
every create/edit/activate/deactivate/retire inserts a new revision; the current state of a
response playbook is its highest revision per (tenant, response_playbook_id). Tenant-scoped
with RLS.

Revision ID: v1_0037_authored_response_playbooks
Revises: v1_0036_authz_fact_review_status
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "v1_0037_authored_response_playbooks"
down_revision: str | None = "v1_0036_authz_fact_review_status"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "authored_response_playbook_revisions",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "tenant_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("tenants.id", ondelete="CASCADE"),
            nullable=False,
        ),
        # The logical response-playbook slug (ResponsePlaybook.id).
        sa.Column("response_playbook_id", sa.Text(), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False),
        # 'draft' (WIP) | 'shadow' (audited, not dispatched) | 'active' (dispatched) |
        # 'retired' (deleted). 'active' governs live because L1 reads it at dispatch.
        sa.Column("status", sa.Text(), nullable=False, server_default=sa.text("'shadow'")),
        # The validated ResponsePlaybook definition.
        sa.Column("definition", postgresql.JSONB(), nullable=False),
        sa.Column("created_by", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column(
            "created_at", sa.TIMESTAMP(timezone=True), nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.CheckConstraint(
            "status IN ('draft', 'shadow', 'active', 'retired')",
            name="ck_authored_response_playbook_status",
        ),
        sa.UniqueConstraint(
            "tenant_id", "response_playbook_id", "revision",
            name="uq_authored_response_playbook_revision",
        ),
    )
    op.create_index(
        "ix_authored_response_playbooks_current",
        "authored_response_playbook_revisions",
        ["tenant_id", "response_playbook_id", "revision"],
    )

    op.execute(
        "ALTER TABLE authored_response_playbook_revisions ENABLE ROW LEVEL SECURITY;"
    )
    op.execute(
        "ALTER TABLE authored_response_playbook_revisions FORCE ROW LEVEL SECURITY;"
    )
    op.execute(
        """
        CREATE POLICY authored_response_playbook_revisions_tenant_isolation
            ON authored_response_playbook_revisions
            FOR ALL TO soctalk_app
            USING (NOT (tenant_id IS DISTINCT FROM
                   NULLIF(current_setting('app.current_tenant_id', true), '')::uuid))
            WITH CHECK (NOT (tenant_id IS DISTINCT FROM
                   NULLIF(current_setting('app.current_tenant_id', true), '')::uuid))
        """
    )
    # Append-only is enforced in application code (authoring.py only INSERTs); grants
    # mirror the sibling authored tables so the test harness TRUNCATE ... CASCADE works.
    op.execute(
        "GRANT SELECT, INSERT, UPDATE, DELETE ON authored_response_playbook_revisions "
        "TO soctalk_app;"
    )
    op.execute(
        "GRANT SELECT, INSERT, UPDATE, DELETE ON authored_response_playbook_revisions "
        "TO soctalk_mssp;"
    )


def downgrade() -> None:
    op.execute(
        'DROP POLICY IF EXISTS "authored_response_playbook_revisions_tenant_isolation" '
        "ON authored_response_playbook_revisions"
    )
    op.drop_index(
        "ix_authored_response_playbooks_current",
        table_name="authored_response_playbook_revisions",
    )
    op.drop_table("authored_response_playbook_revisions")
