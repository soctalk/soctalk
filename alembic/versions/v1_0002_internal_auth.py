"""Internal authentication tables.

Revision ID: v1_0002_internal_auth
Revises: v1_0001_multi_tenancy
Create Date: 2026-04-20

Authoritative spec: ``docs/v1/P1-1-internal-auth.md``.

Adds ``password_credentials`` and ``sessions``. Everything else reuses
existing models (``users``, ``audit_log``).

Forward-only; rollback is via Postgres backup restore.
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision: str = "v1_0002_internal_auth"
down_revision: str | None = "v1_0001_multi_tenancy"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    # password_credentials: one row per user with a local password.
    op.create_table(
        "password_credentials",
        sa.Column(
            "user_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column("password_hash", sa.Text(), nullable=False),
        sa.Column(
            "must_change",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
        sa.Column(
            "updated_at",
            sa.TIMESTAMP(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column("last_used_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column(
            "consecutive_failures",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("0"),
        ),
        sa.Column("locked_until", sa.TIMESTAMP(timezone=True), nullable=True),
    )

    # sessions: DB-backed sessions. id is also the cookie value.
    op.create_table(
        "sessions",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
        ),
        sa.Column(
            "user_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "tenant_context",
            postgresql.UUID(as_uuid=True),
            nullable=True,
        ),
        sa.Column(
            "created_at",
            sa.TIMESTAMP(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column(
            "last_seen_at",
            sa.TIMESTAMP(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column("absolute_expiry", sa.TIMESTAMP(timezone=True), nullable=False),
        sa.Column("idle_expiry", sa.TIMESTAMP(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("ip_created", postgresql.INET(), nullable=True),
        sa.Column("user_agent", sa.Text(), nullable=True),
    )
    op.create_index(
        "ix_sessions_user_revoked",
        "sessions",
        ["user_id", "revoked_at"],
    )

    # Grants. soctalk_app reads/writes its own auth state. soctalk_mssp does
    # too, so the CLI (which runs under the admin/mssp role) can seed
    # password_credentials for initial operator onboarding.
    for tbl in ("password_credentials", "sessions"):
        op.execute(
            f"GRANT SELECT, INSERT, UPDATE, DELETE ON {tbl} "
            "TO soctalk_app, soctalk_mssp"
        )

    # These tables are not tenant-scoped (they key on user_id, which
    # already carries tenant_id), so no RLS policy is attached. Access is
    # gated by the application layer.
