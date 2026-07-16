"""Add a review gate to authorization facts (tenant-asserted facts land 'pending').

A ``review_status`` lifecycle column (pending | approved | rejected) governs whether a fact is
visible to the reasoning engine. Every existing/connector/analyst/adapter fact is 'approved'
(unchanged behaviour); only tenant-asserted facts start 'pending' and stay invisible to triage
until an MSSP analyst approves them. The store's ``list_current_facts`` (the engine's
store-primary read) filters on ``review_status = 'approved'`` — the load-bearing safety gate.

Revision ID: v1_0036_authz_fact_review_status
Revises: v1_0035_rename_playbook_to_triage_policy
"""

from __future__ import annotations

from alembic import op

revision = "v1_0036_authz_fact_review_status"
down_revision: str | None = "v1_0035_rename_playbook_to_triage_policy"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Default 'approved' so every existing row and every non-tenant writer is unaffected.
    op.execute(
        "ALTER TABLE authorization_facts "
        "ADD COLUMN review_status TEXT NOT NULL DEFAULT 'approved'"
    )
    op.execute(
        "ALTER TABLE authorization_facts "
        "ADD CONSTRAINT ck_authz_fact_review_status "
        "CHECK (review_status IN ('pending', 'approved', 'rejected'))"
    )
    # Partial index for the analyst review queue (the pending rows).
    op.execute(
        "CREATE INDEX ix_authz_facts_pending_review ON authorization_facts (tenant_id) "
        "WHERE review_status = 'pending' AND revoked_at IS NULL"
    )


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS ix_authz_facts_pending_review")
    op.execute(
        "ALTER TABLE authorization_facts DROP CONSTRAINT IF EXISTS ck_authz_fact_review_status"
    )
    op.execute("ALTER TABLE authorization_facts DROP COLUMN IF EXISTS review_status")
