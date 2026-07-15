"""Engagement deconfliction: revoke fields + the declared-test observation lane.

Two changes wire the parked ``engagements`` primitive (#31) into ingest triage:

- ``engagements`` gains ``revoked_at`` / ``revoked_by`` / ``revoke_reason`` so an
  analyst can end a window early WITHOUT mutating ``ends_at`` (the declared window
  is audit-bearing and must survive). ``deconflict()`` filters ``revoked_at IS NULL``.
- ``engagement_observations``: one row per deconflicted alert — the durable,
  queryable "declared-test lane". A deconflicted alert is NEVER auto-closed/FP;
  it lands here so nothing is silently suppressed (counts, audit, expiry all
  visible). Keyed to the source-event row (unique-safe), not raw source_event_id
  (which is only unique with (tenant, source)).

Revision ID: v1_0031_engagement_deconfliction
Revises: v1_0031_auto_close_volume_index
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "v1_0032_engagement_deconfliction"
down_revision: str | None = "v1_0031_auto_close_volume_index"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # --- revoke fields on engagements (don't overload ends_at) ---
    op.add_column("engagements", sa.Column("revoked_at", sa.TIMESTAMP(timezone=True), nullable=True))
    op.add_column("engagements", sa.Column("revoked_by", postgresql.UUID(as_uuid=True), nullable=True))
    op.add_column("engagements", sa.Column("revoke_reason", sa.Text(), nullable=True))

    # --- the declared-test lane ---
    op.create_table(
        "engagement_observations",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "tenant_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("tenants.id", ondelete="CASCADE"),
            nullable=False,
        ),
        # The primary covering engagement; matched_* lists every in-window
        # engagement that covered the activity (windows can legitimately overlap).
        sa.Column("primary_engagement_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column(
            "matched_engagement_ids", postgresql.JSONB(), nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column(
            "alert_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("alerts.id", ondelete="CASCADE"),
            nullable=False,
        ),
        # The source-event row is the stable, globally-unique anchor.
        sa.Column(
            "source_event_row_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("alert_source_events.id", ondelete="CASCADE"),
            nullable=False,
        ),
        # 'declared_test' (in-scope, skipped the LLM) | 'out_of_scope' (strayed,
        # forced to a real look — a contractual finding, never suppressed).
        sa.Column("status", sa.Text(), nullable=False),
        sa.Column("out_of_scope", postgresql.JSONB(), nullable=True),
        sa.Column("occurred_at", sa.TIMESTAMP(timezone=True), nullable=False),
        sa.Column("created_at", sa.TIMESTAMP(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.CheckConstraint(
            "status IN ('declared_test', 'out_of_scope')",
            name="ck_engagement_observations_status",
        ),
    )
    # One observation per source-event row (idempotent under replay).
    op.create_index(
        "uq_engagement_observations_source_event",
        "engagement_observations",
        ["tenant_id", "source_event_row_id"],
        unique=True,
    )
    # Lane queries: recent declared-tests / out-of-scope findings.
    op.create_index(
        "ix_engagement_observations_lane",
        "engagement_observations",
        ["tenant_id", "status", "occurred_at"],
    )
    # Per-engagement counts.
    op.create_index(
        "ix_engagement_observations_engagement",
        "engagement_observations",
        ["tenant_id", "primary_engagement_id", "status"],
    )

    op.execute("ALTER TABLE engagement_observations ENABLE ROW LEVEL SECURITY;")
    op.execute("ALTER TABLE engagement_observations FORCE ROW LEVEL SECURITY;")
    op.execute(
        """
        CREATE POLICY engagement_observations_tenant_isolation ON engagement_observations
            FOR ALL TO soctalk_app
            USING (NOT (tenant_id IS DISTINCT FROM
                   NULLIF(current_setting('app.current_tenant_id', true), '')::uuid))
            WITH CHECK (NOT (tenant_id IS DISTINCT FROM
                   NULLIF(current_setting('app.current_tenant_id', true), '')::uuid))
        """
    )
    op.execute("GRANT SELECT, INSERT, UPDATE, DELETE ON engagement_observations TO soctalk_app;")
    op.execute("GRANT SELECT, INSERT, UPDATE, DELETE ON engagement_observations TO soctalk_mssp;")


def downgrade() -> None:
    op.execute(
        'DROP POLICY IF EXISTS "engagement_observations_tenant_isolation" '
        "ON engagement_observations"
    )
    op.drop_index("ix_engagement_observations_engagement", table_name="engagement_observations")
    op.drop_index("ix_engagement_observations_lane", table_name="engagement_observations")
    op.drop_index("uq_engagement_observations_source_event", table_name="engagement_observations")
    op.drop_table("engagement_observations")
    op.drop_column("engagements", "revoke_reason")
    op.drop_column("engagements", "revoked_by")
    op.drop_column("engagements", "revoked_at")
