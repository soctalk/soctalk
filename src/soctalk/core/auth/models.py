"""SQLModel definitions for the internal auth subsystem.

Paired with the Alembic migration ``v1_0002_internal_auth``. Both tables
key on ``users.id`` and inherit the tenant from the user row.
"""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID

from sqlalchemy import Column, DateTime, ForeignKey, Index
from sqlalchemy.dialects.postgresql import INET
from sqlmodel import Field, SQLModel, Text


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class PasswordCredential(SQLModel, table=True):
    """One row per user with a local password. MSSP staff and tenant users
    are both eligible.

    The hash string produced by ``argon2-cffi`` embeds all parameters and
    the salt, so future parameter tuning doesn't require a migration.
    """

    __tablename__ = "password_credentials"

    user_id: UUID = Field(
        sa_column=Column(
            ForeignKey("users.id", ondelete="CASCADE"),
            primary_key=True,
        )
    )
    password_hash: str = Field(sa_column=Column(Text, nullable=False))
    must_change: bool = Field(default=False)
    updated_at: datetime = Field(
        sa_column=Column(DateTime(timezone=True), nullable=False),
        default_factory=_utcnow,
    )
    last_used_at: datetime | None = Field(
        default=None,
        sa_column=Column(DateTime(timezone=True), nullable=True),
    )
    consecutive_failures: int = Field(default=0)
    locked_until: datetime | None = Field(
        default=None,
        sa_column=Column(DateTime(timezone=True), nullable=True),
    )


class Session(SQLModel, table=True):
    """DB-backed session. The cookie carries ``id`` as an opaque value; the
    row is the source of truth.

    See ``docs/multi-tenant/internal-auth.md`` §4.
    """

    __tablename__ = "sessions"
    __table_args__ = (
        Index("ix_sessions_user_revoked", "user_id", "revoked_at"),
    )

    id: UUID = Field(primary_key=True)
    user_id: UUID = Field(
        sa_column=Column(
            ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        )
    )
    tenant_context: UUID | None = Field(default=None)
    created_at: datetime = Field(
        sa_column=Column(DateTime(timezone=True), nullable=False),
        default_factory=_utcnow,
    )
    last_seen_at: datetime = Field(
        sa_column=Column(DateTime(timezone=True), nullable=False),
        default_factory=_utcnow,
    )
    absolute_expiry: datetime = Field(
        sa_column=Column(DateTime(timezone=True), nullable=False),
    )
    idle_expiry: datetime = Field(
        sa_column=Column(DateTime(timezone=True), nullable=False),
    )
    revoked_at: datetime | None = Field(
        default=None,
        sa_column=Column(DateTime(timezone=True), nullable=True),
    )
    ip_created: str | None = Field(
        default=None,
        sa_column=Column(INET, nullable=True),
    )
    user_agent: str | None = Field(default=None, sa_column=Column(Text))
