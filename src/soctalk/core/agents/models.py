"""L1→L2 dispatch models.

The MSSP's SocTalk (L1) dispatches declarative jobs to an agent running
in the tenant's cluster (L2). This module holds the persistent state
the L1 control plane needs to drive that relationship: one Installation
per tenant, bootstrap + runtime tokens, agent job queue, wire events,
heartbeats, lifecycle transitions.

This mirrors the shape soctalk-cloud uses for L0→L1, intentionally. The
agent binary is the same; only the peer URL + scope differ.

Naming convention: prefix everything with ``tenant_installation_`` or
``agent_`` so rows are unambiguous alongside the existing tenant- and
IR-scoped tables.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import Column, DateTime, ForeignKey, Index, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlmodel import Field, SQLModel


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# Installation — one per tenant. Desired + reported state.
# ---------------------------------------------------------------------------


class TenantInstallation(SQLModel, table=True):
    """L1's view of a tenant's deployed SOC stack in L2's cluster.

    One row per tenant. Drives the state machine (pending →
    agent_connected → provisioning → active/degraded) and carries the
    desired chart contract the L2 agent will apply.
    """

    __tablename__ = "tenant_installations"
    __table_args__ = (
        Index("ix_tenant_installations_tenant", "tenant_id", unique=True),
        Index("ix_tenant_installations_state", "state"),
    )

    id: UUID = Field(default_factory=uuid4, primary_key=True)
    tenant_id: UUID = Field(
        sa_column=Column(
            ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False
        )
    )
    cluster_label: str | None = Field(default=None, sa_column=Column(Text))

    # Desired: what the agent should reconcile toward.
    desired_chart_ref: str = Field(sa_column=Column(Text, nullable=False))
    desired_chart_version: str = Field(sa_column=Column(Text, nullable=False))
    # 'none' | 'install' | 'upgrade' | 'uninstall'
    desired_action: str = Field(default="none")

    # Reported: last signal received from the agent.
    agent_version: str | None = Field(default=None, sa_column=Column(Text))
    agent_last_seen: datetime | None = Field(
        default=None, sa_column=Column(DateTime(timezone=True))
    )
    reported_chart_version: str | None = Field(default=None, sa_column=Column(Text))
    reported_state: str | None = Field(default=None, sa_column=Column(Text))

    # State machine.
    state: str = Field(default="pending")
    state_changed_at: datetime = Field(
        default_factory=_utcnow,
        sa_column=Column(DateTime(timezone=True), nullable=False),
    )
    created_at: datetime = Field(
        default_factory=_utcnow,
        sa_column=Column(DateTime(timezone=True), nullable=False),
    )
    deleted_at: datetime | None = Field(
        default=None, sa_column=Column(DateTime(timezone=True))
    )


# ---------------------------------------------------------------------------
# Tokens — bootstrap (single-use, short TTL) and runtime (rotatable).
# ---------------------------------------------------------------------------


class TenantInstallationBootstrapToken(SQLModel, table=True):
    __tablename__ = "tenant_installation_bootstrap_tokens"

    id: UUID = Field(default_factory=uuid4, primary_key=True)
    installation_id: UUID = Field(
        sa_column=Column(
            ForeignKey("tenant_installations.id", ondelete="CASCADE"),
            nullable=False,
        )
    )
    token_hash: str = Field(sa_column=Column(Text, nullable=False))
    created_at: datetime = Field(
        default_factory=_utcnow,
        sa_column=Column(DateTime(timezone=True), nullable=False),
    )
    expires_at: datetime = Field(
        sa_column=Column(DateTime(timezone=True), nullable=False)
    )
    consumed_at: datetime | None = Field(
        default=None, sa_column=Column(DateTime(timezone=True))
    )
    revoked_at: datetime | None = Field(
        default=None, sa_column=Column(DateTime(timezone=True))
    )


class TenantInstallationRuntimeToken(SQLModel, table=True):
    __tablename__ = "tenant_installation_runtime_tokens"

    id: UUID = Field(default_factory=uuid4, primary_key=True)
    installation_id: UUID = Field(
        sa_column=Column(
            ForeignKey("tenant_installations.id", ondelete="CASCADE"),
            nullable=False,
        )
    )
    token_hash: str = Field(sa_column=Column(Text, nullable=False))
    issued_at: datetime = Field(
        default_factory=_utcnow,
        sa_column=Column(DateTime(timezone=True), nullable=False),
    )
    last_used_at: datetime | None = Field(
        default=None, sa_column=Column(DateTime(timezone=True))
    )
    revoked_at: datetime | None = Field(
        default=None, sa_column=Column(DateTime(timezone=True))
    )


# ---------------------------------------------------------------------------
# Lifecycle audit trail for the Installation state machine.
# ---------------------------------------------------------------------------


class TenantInstallationEvent(SQLModel, table=True):
    __tablename__ = "tenant_installation_events"
    __table_args__ = (
        Index(
            "ix_tenant_installation_events_installation_ts",
            "installation_id", "timestamp",
        ),
    )

    id: UUID = Field(default_factory=uuid4, primary_key=True)
    timestamp: datetime = Field(
        default_factory=_utcnow,
        sa_column=Column(DateTime(timezone=True), nullable=False),
    )
    installation_id: UUID = Field(
        sa_column=Column(
            ForeignKey("tenant_installations.id", ondelete="CASCADE"),
            nullable=False,
        )
    )
    event_type: str = Field(sa_column=Column(Text, nullable=False))
    from_state: str | None = Field(default=None, sa_column=Column(Text))
    to_state: str | None = Field(default=None, sa_column=Column(Text))
    actor_id: str | None = Field(default=None, sa_column=Column(Text))
    details: dict[str, Any] = Field(
        default_factory=dict,
        sa_column=Column(JSONB, nullable=False),
    )


# ---------------------------------------------------------------------------
# Wire-layer jobs the L2 agent claims and executes.
# ---------------------------------------------------------------------------


class AgentJob(SQLModel, table=True):
    """Declarative command the L2 agent pops off the queue.

    Kinds (MVP): preflight, install_helm_release, upgrade_helm_release,
    uninstall_helm_release, rotate_runtime_token. The agent never
    receives a shell; every kind is a closed verb with typed spec.
    """

    __tablename__ = "agent_jobs"
    __table_args__ = (
        Index("ix_agent_jobs_installation_status", "installation_id", "status"),
        Index("ix_agent_jobs_idempotency", "installation_id", "idempotency_key",
              unique=True),
    )

    id: UUID = Field(default_factory=uuid4, primary_key=True)
    installation_id: UUID = Field(
        sa_column=Column(
            ForeignKey("tenant_installations.id", ondelete="CASCADE"),
            nullable=False,
        )
    )
    seq_in_parent: int = Field(default=0)
    kind: str = Field(sa_column=Column(Text, nullable=False))
    idempotency_key: str = Field(sa_column=Column(Text, nullable=False))
    spec: dict[str, Any] = Field(
        default_factory=dict, sa_column=Column(JSONB, nullable=False)
    )
    # pending | in_flight | succeeded | failed
    status: str = Field(default="pending")
    claimed_at: datetime | None = Field(
        default=None, sa_column=Column(DateTime(timezone=True))
    )
    completed_at: datetime | None = Field(
        default=None, sa_column=Column(DateTime(timezone=True))
    )
    outcome: str | None = Field(default=None, sa_column=Column(Text))
    error_code: str | None = Field(default=None, sa_column=Column(Text))
    summary: str | None = Field(default=None, sa_column=Column(Text))
    detail: dict[str, Any] | None = Field(
        default=None, sa_column=Column(JSONB, nullable=True)
    )
    created_at: datetime = Field(
        default_factory=_utcnow,
        sa_column=Column(DateTime(timezone=True), nullable=False),
    )
    updated_at: datetime = Field(
        default_factory=_utcnow,
        sa_column=Column(DateTime(timezone=True), nullable=False),
    )


class AgentJobEvent(SQLModel, table=True):
    """Per-step progress event the agent streams during a job.

    Wire idempotency: ``UNIQUE (job_id, seq)`` so a duplicate retry
    doesn't create phantom rows.
    """

    __tablename__ = "agent_job_events"
    __table_args__ = (
        Index("ix_agent_job_events_job_seq", "job_id", "seq", unique=True),
    )

    id: UUID = Field(default_factory=uuid4, primary_key=True)
    job_id: UUID = Field(
        sa_column=Column(
            ForeignKey("agent_jobs.id", ondelete="CASCADE"), nullable=False
        )
    )
    seq: int = Field(sa_column=Column(nullable=False))
    event_type: str = Field(sa_column=Column(Text, nullable=False))
    timestamp: datetime = Field(
        sa_column=Column(DateTime(timezone=True), nullable=False)
    )
    step: str | None = Field(default=None, sa_column=Column(Text))
    detail: dict[str, Any] = Field(
        default_factory=dict,
        sa_column=Column(JSONB, nullable=False),
    )
    inserted_at: datetime = Field(
        default_factory=_utcnow,
        sa_column=Column(DateTime(timezone=True), nullable=False),
    )


class TenantInstallationHeartbeat(SQLModel, table=True):
    __tablename__ = "tenant_installation_heartbeats"
    __table_args__ = (
        Index(
            "ix_tenant_installation_heartbeats_installation_ts",
            "installation_id", "timestamp",
        ),
    )

    id: UUID = Field(default_factory=uuid4, primary_key=True)
    installation_id: UUID = Field(
        sa_column=Column(
            ForeignKey("tenant_installations.id", ondelete="CASCADE"),
            nullable=False,
        )
    )
    timestamp: datetime = Field(
        sa_column=Column(DateTime(timezone=True), nullable=False)
    )
    agent_version: str | None = Field(default=None, sa_column=Column(Text))
    reported_chart_version: str | None = Field(default=None, sa_column=Column(Text))
    reported_state: str | None = Field(default=None, sa_column=Column(Text))
