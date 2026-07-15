"""Rename the authored-playbook table to triage-policy semantics (#43/#44 rename).

Pure, data-preserving rename of the DB objects backing authored triage policies. No
column types, constraints, RLS logic, or grants change — only names:

  table       authored_playbook_revisions            -> authored_triage_policy_revisions
  column      playbook_id                            -> triage_policy_id
  unique      uq_authored_playbook_revision          -> uq_authored_triage_policy_revision
  check       ck_authored_playbook_status            -> ck_authored_triage_policy_status
  index       ix_authored_playbooks_current          -> ix_authored_triage_policies_current
  RLS policy  authored_playbook_revisions_tenant_isolation
                                                     -> authored_triage_policy_revisions_tenant_isolation

The RLS policy keys off tenant_id (not the renamed column), so the column rename does
not touch it. Fully reversible.

Revision ID: v1_0035_rename_playbook_to_triage_policy
Revises: a1a451de05a1
"""

from __future__ import annotations

from alembic import op

revision = "v1_0035_rename_playbook_to_triage_policy"
down_revision: str | None = "a1a451de05a1"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TABLE authored_playbook_revisions RENAME TO authored_triage_policy_revisions")
    op.execute(
        "ALTER TABLE authored_triage_policy_revisions RENAME COLUMN playbook_id TO triage_policy_id"
    )
    op.execute(
        "ALTER TABLE authored_triage_policy_revisions "
        "RENAME CONSTRAINT uq_authored_playbook_revision TO uq_authored_triage_policy_revision"
    )
    op.execute(
        "ALTER TABLE authored_triage_policy_revisions "
        "RENAME CONSTRAINT ck_authored_playbook_status TO ck_authored_triage_policy_status"
    )
    op.execute("ALTER INDEX ix_authored_playbooks_current RENAME TO ix_authored_triage_policies_current")
    op.execute(
        "ALTER POLICY authored_playbook_revisions_tenant_isolation "
        "ON authored_triage_policy_revisions "
        "RENAME TO authored_triage_policy_revisions_tenant_isolation"
    )


def downgrade() -> None:
    op.execute(
        "ALTER POLICY authored_triage_policy_revisions_tenant_isolation "
        "ON authored_triage_policy_revisions "
        "RENAME TO authored_playbook_revisions_tenant_isolation"
    )
    op.execute("ALTER INDEX ix_authored_triage_policies_current RENAME TO ix_authored_playbooks_current")
    op.execute(
        "ALTER TABLE authored_triage_policy_revisions "
        "RENAME CONSTRAINT ck_authored_triage_policy_status TO ck_authored_playbook_status"
    )
    op.execute(
        "ALTER TABLE authored_triage_policy_revisions "
        "RENAME CONSTRAINT uq_authored_triage_policy_revision TO uq_authored_playbook_revision"
    )
    op.execute(
        "ALTER TABLE authored_triage_policy_revisions RENAME COLUMN triage_policy_id TO playbook_id"
    )
    op.execute("ALTER TABLE authored_triage_policy_revisions RENAME TO authored_playbook_revisions")
