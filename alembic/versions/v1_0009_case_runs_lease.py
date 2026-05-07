"""case_runs: lease columns for the L2 runs-worker claim/complete protocol.

Revision ID: v1_0009_case_runs_lease
Revises: v1_0008_audit_log_mssp_scope
Create Date: 2026-04-29
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql


revision = "v1_0009_case_runs_lease"
down_revision = "v1_0008_audit_log_mssp_scope"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "case_runs",
        sa.Column("claimed_by", sa.Text(), nullable=True),
    )
    op.add_column(
        "case_runs",
        sa.Column("claimed_at", sa.TIMESTAMP(timezone=True), nullable=True),
    )
    op.add_column(
        "case_runs",
        sa.Column("lease_id", postgresql.UUID(as_uuid=True), nullable=True),
    )
    op.add_column(
        "case_runs",
        sa.Column(
            "lease_expires_at",
            sa.TIMESTAMP(timezone=True),
            nullable=True,
        ),
    )
    op.execute(
        """
        CREATE INDEX ix_case_runs_lease_expires_at
            ON case_runs (lease_expires_at)
            WHERE status = 'active' AND claimed_at IS NOT NULL
        """
    )


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS ix_case_runs_lease_expires_at")
    op.drop_column("case_runs", "lease_expires_at")
    op.drop_column("case_runs", "lease_id")
    op.drop_column("case_runs", "claimed_at")
    op.drop_column("case_runs", "claimed_by")
