"""Settle window: not_before on investigation_runs (issue #28).

A run is not claimable until now() >= not_before, so a burst of correlated
events accumulates onto one investigation before the first LLM look
(Alertmanager group_wait). Existing rows default to epoch (immediately
claimable — no behavior change for anything already queued).

Revision ID: v1_0019_run_not_before
Revises: v1_0018_source_events_and_checkpoints
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "v1_0019_run_not_before"
down_revision: str | None = "v1_0018_source_events_and_checkpoints"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "investigation_runs",
        sa.Column(
            "not_before",
            sa.TIMESTAMP(timezone=True),
            nullable=False,
            server_default=sa.text("'1970-01-01T00:00:00Z'"),
        ),
    )
    # Partial index to keep the claim's not_before predicate cheap.
    op.create_index(
        "ix_runs_claimable",
        "investigation_runs",
        ["tenant_id", "not_before"],
        postgresql_where=sa.text("status = 'active'"),
    )


def downgrade() -> None:
    op.drop_index("ix_runs_claimable", table_name="investigation_runs")
    op.drop_column("investigation_runs", "not_before")
