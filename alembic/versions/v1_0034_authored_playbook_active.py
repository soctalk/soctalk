"""Authored playbooks can be ACTIVATED to govern (#44 follow-on).

Add 'active' to the authoring lifecycle. An active authored playbook is materialized into
the tenant's chart values (ConfigMap -> SOCTALK_PLAYBOOK_DIR) on reconcile, loading through
the worker's own fail-closed parser exactly like a file playbook. Deactivation returns it to
'shadow'. The stored definition JSONB stays shadow; render overrides status to active.

Revision ID: v1_0034_authored_playbook_active
Revises: v1_0033_authored_playbooks
"""

from __future__ import annotations

from alembic import op

revision = "v1_0034_authored_playbook_active"
down_revision: str | None = "v1_0033_authored_playbooks"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        "ALTER TABLE authored_playbook_revisions "
        "DROP CONSTRAINT IF EXISTS ck_authored_playbook_status"
    )
    op.execute(
        "ALTER TABLE authored_playbook_revisions "
        "ADD CONSTRAINT ck_authored_playbook_status "
        "CHECK (status IN ('draft', 'shadow', 'active', 'retired'))"
    )


def downgrade() -> None:
    op.execute(
        "ALTER TABLE authored_playbook_revisions "
        "DROP CONSTRAINT IF EXISTS ck_authored_playbook_status"
    )
    op.execute(
        "ALTER TABLE authored_playbook_revisions "
        "ADD CONSTRAINT ck_authored_playbook_status "
        "CHECK (status IN ('draft', 'shadow', 'retired'))"
    )
