"""L1 agent dispatch surface: Installation + AgentJob + tokens.

Revision ID: v1_0006_agent_dispatch
Revises: ce989e482ad9
Create Date: 2026-04-23

Mirrors the control-plane shape soctalk-cloud uses for L0→L1, applied
one level down: L1 as the control plane for L2 agents running in
tenant clusters. The agent binary is unchanged; the peer URL + scope
differ.

Tables:
  - tenant_installations
  - tenant_installation_bootstrap_tokens
  - tenant_installation_runtime_tokens
  - tenant_installation_events        (lifecycle audit)
  - agent_jobs                        (wire commands)
  - agent_job_events                  (per-step progress)
  - tenant_installation_heartbeats

Forward-only.
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision: str = "v1_0006_agent_dispatch"
down_revision: str | None = "ce989e482ad9"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.create_table(
        "tenant_installations",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text("gen_random_uuid()")),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("tenants.id", ondelete="CASCADE"),
                  nullable=False),
        sa.Column("cluster_label", sa.Text(), nullable=True),
        sa.Column("desired_chart_ref", sa.Text(), nullable=False),
        sa.Column("desired_chart_version", sa.Text(), nullable=False),
        sa.Column("desired_action", sa.Text(), nullable=False,
                  server_default=sa.text("'none'")),
        sa.Column("agent_version", sa.Text(), nullable=True),
        sa.Column("agent_last_seen", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("reported_chart_version", sa.Text(), nullable=True),
        sa.Column("reported_state", sa.Text(), nullable=True),
        sa.Column("state", sa.Text(), nullable=False,
                  server_default=sa.text("'pending'")),
        sa.Column("state_changed_at", sa.TIMESTAMP(timezone=True),
                  nullable=False, server_default=sa.func.now()),
        sa.Column("created_at", sa.TIMESTAMP(timezone=True),
                  nullable=False, server_default=sa.func.now()),
        sa.Column("deleted_at", sa.TIMESTAMP(timezone=True), nullable=True),
    )
    # Exactly-one Installation per tenant (active or soft-deleted); the
    # controller reuses the existing row across upgrade/decommission cycles.
    op.create_index(
        "ix_tenant_installations_tenant", "tenant_installations",
        ["tenant_id"], unique=True,
    )
    op.create_index(
        "ix_tenant_installations_state", "tenant_installations", ["state"],
    )

    op.create_table(
        "tenant_installation_bootstrap_tokens",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text("gen_random_uuid()")),
        sa.Column("installation_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("tenant_installations.id", ondelete="CASCADE"),
                  nullable=False),
        sa.Column("token_hash", sa.Text(), nullable=False),
        sa.Column("created_at", sa.TIMESTAMP(timezone=True),
                  nullable=False, server_default=sa.func.now()),
        sa.Column("expires_at", sa.TIMESTAMP(timezone=True), nullable=False),
        sa.Column("consumed_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.TIMESTAMP(timezone=True), nullable=True),
    )

    op.create_table(
        "tenant_installation_runtime_tokens",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text("gen_random_uuid()")),
        sa.Column("installation_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("tenant_installations.id", ondelete="CASCADE"),
                  nullable=False),
        sa.Column("token_hash", sa.Text(), nullable=False),
        sa.Column("issued_at", sa.TIMESTAMP(timezone=True),
                  nullable=False, server_default=sa.func.now()),
        sa.Column("last_used_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.TIMESTAMP(timezone=True), nullable=True),
    )

    op.create_table(
        "tenant_installation_events",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text("gen_random_uuid()")),
        sa.Column("timestamp", sa.TIMESTAMP(timezone=True),
                  nullable=False, server_default=sa.func.now()),
        sa.Column("installation_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("tenant_installations.id", ondelete="CASCADE"),
                  nullable=False),
        sa.Column("event_type", sa.Text(), nullable=False),
        sa.Column("from_state", sa.Text(), nullable=True),
        sa.Column("to_state", sa.Text(), nullable=True),
        sa.Column("actor_id", sa.Text(), nullable=True),
        sa.Column("details", postgresql.JSONB(), nullable=False,
                  server_default=sa.text("'{}'::jsonb")),
    )
    op.create_index(
        "ix_tenant_installation_events_installation_ts",
        "tenant_installation_events",
        ["installation_id", "timestamp"],
    )

    op.create_table(
        "agent_jobs",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text("gen_random_uuid()")),
        sa.Column("installation_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("tenant_installations.id", ondelete="CASCADE"),
                  nullable=False),
        sa.Column("seq_in_parent", sa.Integer(), nullable=False,
                  server_default=sa.text("0")),
        sa.Column("kind", sa.Text(), nullable=False),
        sa.Column("idempotency_key", sa.Text(), nullable=False),
        sa.Column("spec", postgresql.JSONB(), nullable=False,
                  server_default=sa.text("'{}'::jsonb")),
        sa.Column("status", sa.Text(), nullable=False,
                  server_default=sa.text("'pending'")),
        sa.Column("claimed_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("completed_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("outcome", sa.Text(), nullable=True),
        sa.Column("error_code", sa.Text(), nullable=True),
        sa.Column("summary", sa.Text(), nullable=True),
        sa.Column("detail", postgresql.JSONB(), nullable=True),
        sa.Column("created_at", sa.TIMESTAMP(timezone=True),
                  nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.TIMESTAMP(timezone=True),
                  nullable=False, server_default=sa.func.now()),
    )
    op.create_index(
        "ix_agent_jobs_installation_status", "agent_jobs",
        ["installation_id", "status"],
    )
    # Idempotency: same (installation, key) must never double-enqueue.
    op.create_index(
        "ix_agent_jobs_idempotency", "agent_jobs",
        ["installation_id", "idempotency_key"], unique=True,
    )

    op.create_table(
        "agent_job_events",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text("gen_random_uuid()")),
        sa.Column("job_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("agent_jobs.id", ondelete="CASCADE"),
                  nullable=False),
        sa.Column("seq", sa.Integer(), nullable=False),
        sa.Column("event_type", sa.Text(), nullable=False),
        sa.Column("timestamp", sa.TIMESTAMP(timezone=True), nullable=False),
        sa.Column("step", sa.Text(), nullable=True),
        sa.Column("detail", postgresql.JSONB(), nullable=False,
                  server_default=sa.text("'{}'::jsonb")),
        sa.Column("inserted_at", sa.TIMESTAMP(timezone=True),
                  nullable=False, server_default=sa.func.now()),
    )
    op.create_index(
        "ix_agent_job_events_job_seq", "agent_job_events",
        ["job_id", "seq"], unique=True,
    )

    op.create_table(
        "tenant_installation_heartbeats",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text("gen_random_uuid()")),
        sa.Column("installation_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("tenant_installations.id", ondelete="CASCADE"),
                  nullable=False),
        sa.Column("timestamp", sa.TIMESTAMP(timezone=True), nullable=False),
        sa.Column("agent_version", sa.Text(), nullable=True),
        sa.Column("reported_chart_version", sa.Text(), nullable=True),
        sa.Column("reported_state", sa.Text(), nullable=True),
    )
    op.create_index(
        "ix_tenant_installation_heartbeats_installation_ts",
        "tenant_installation_heartbeats",
        ["installation_id", "timestamp"],
    )


def downgrade() -> None:
    # Forward-only.
    pass
