"""Tenant deployment profile + async provisioning job queue.

Revision ID: v1_0005_tenant_profile_jobs
Revises: v1_0004_repair_ir_defaults
Create Date: 2026-04-21

Adds:

1. ``tenants.profile`` text column. New tenants default to ``poc``. Existing
   rows at migration time are backfilled to ``legacy`` — we refuse to assume
   any particular topology for tenants created before the profile concept
   existed; later automation must derive their shape from the live release
   instead of trusting a column.

2. ``provisioning_jobs`` table — the queue the async provisioning worker
   claims from. Deliberately not a reuse of ``case_outbox``: provisioning
   is not a case-domain concern, and retries / retention / status semantics
   should not be entangled with the IR outbox.

Forward-only.
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision: str = "v1_0005_tenant_profile_jobs"
down_revision: str | None = "v1_0004_repair_ir_defaults"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    # 1. tenants.profile ---------------------------------------------------

    op.execute(
        "ALTER TABLE tenants "
        "ADD COLUMN IF NOT EXISTS profile text"
    )
    # Backfill: existing rows → 'legacy' (NOT 'prod'; see migration docstring).
    op.execute("UPDATE tenants SET profile = 'legacy' WHERE profile IS NULL")
    # Now enforce NOT NULL + default for new rows.
    op.execute("ALTER TABLE tenants ALTER COLUMN profile SET NOT NULL")
    op.execute("ALTER TABLE tenants ALTER COLUMN profile SET DEFAULT 'poc'")
    op.execute(
        "ALTER TABLE tenants ADD CONSTRAINT ck_tenants_profile "
        "CHECK (profile IN ('poc', 'persistent', 'legacy'))"
    )

    # 2. provisioning_jobs -------------------------------------------------

    op.create_table(
        "provisioning_jobs",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text("gen_random_uuid()")),
        sa.Column(
            "tenant_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("tenants.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("kind", sa.Text(), nullable=False),
        sa.Column("status", sa.Text(), nullable=False,
                  server_default=sa.text("'pending'")),
        sa.Column("attempts", sa.Integer(), nullable=False,
                  server_default=sa.text("0")),
        sa.Column("max_attempts", sa.Integer(), nullable=False,
                  server_default=sa.text("5")),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column("claimed_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("claimed_by", sa.Text(), nullable=True),
        sa.Column(
            "next_attempt_at",
            sa.TIMESTAMP(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column(
            "created_at",
            sa.TIMESTAMP(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column(
            "updated_at",
            sa.TIMESTAMP(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.CheckConstraint(
            "kind IN ('tenant.provision', 'tenant.decommission')",
            name="ck_provisioning_jobs_kind",
        ),
        sa.CheckConstraint(
            "status IN ('pending', 'in_flight', 'succeeded', 'failed')",
            name="ck_provisioning_jobs_status",
        ),
    )
    # Pending jobs are the hot path; only one active (pending or in_flight)
    # job per (tenant, kind) is allowed so retry doesn't multi-enqueue.
    op.execute(
        "CREATE UNIQUE INDEX uq_provisioning_jobs_active "
        "ON provisioning_jobs (tenant_id, kind) "
        "WHERE status IN ('pending', 'in_flight')"
    )
    op.create_index(
        "ix_provisioning_jobs_claim",
        "provisioning_jobs",
        ["status", "next_attempt_at"],
    )

    # Grant access to the roles that matter. The worker runs under the
    # mssp role; the API handler under app.
    op.execute(
        "GRANT SELECT, INSERT, UPDATE ON provisioning_jobs "
        "TO soctalk_app, soctalk_mssp"
    )


def downgrade() -> None:
    # Forward-only.
    pass
