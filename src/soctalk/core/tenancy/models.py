"""V1 multi-tenancy SQLModel definitions.

``docs/v1/P0-1-security-model.md``.

Design notes
------------
- Shared-database tenancy with ``tenant_id`` on every tenant-scoped table.
- Row-Level Security enforced at Postgres layer (see ``docs/v1/P0-4-postgres-rls.md``);
  these Python models declare the schema but rely on the migration to attach
  ``ENABLE ROW LEVEL SECURITY`` and ``FORCE ROW LEVEL SECURITY``.
- ``TenantSecret`` stores *references only*. ``(namespace, secret_name, version_label)``.
  Raw secret material lives in Kubernetes Secrets (see P0-5).
- ``User`` carries both MSSP-side staff (``tenant_id`` NULL) and customer-side
  users (``tenant_id`` set, role = ``customer_viewer``). The RLS policy allows
  NULL-tenant rows to be visible across contexts for join-style access from
  MSSP endpoints (see P0-4 §5.2).

Roles follow the 4-role model locked in 00-decisions.md (D-08):
``platform_admin``, ``mssp_admin``, ``analyst``, ``customer_viewer``.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import Column, ForeignKey, Index
from sqlalchemy.dialects.postgresql import JSONB
from sqlmodel import Field, SQLModel, Text


class Role(str, Enum):
    """Roles. The original 4 in D-08 plus ``tenant_admin`` introduced for
    the per-tenant bootstrap user created at provisioning time
    (``_mint_tenant_admin_user``) — gives a tenant-scoped principal that
    can edit settings within their own tenant without holding any MSSP
    privilege. Frontend role gating treats the substring ``admin`` /
    ``analyst`` as review-capable so this name fits the existing matrix.
    """

    PLATFORM_ADMIN = "platform_admin"
    MSSP_ADMIN = "mssp_admin"
    ANALYST = "analyst"
    TENANT_ADMIN = "tenant_admin"
    CUSTOMER_VIEWER = "customer_viewer"


class UserType(str, Enum):
    """Broad user category.

    ``mssp`` covers platform_admin / mssp_admin / analyst (cross-tenant).
    ``tenant`` covers customer_viewer (tenant-scoped).
    Worker and adapter principals do not sit in the user table.
    """

    MSSP = "mssp"
    TENANT = "tenant"


class TenantState(str, Enum):
    """Tenant lifecycle states (see docs/v1/P0-8 §6)."""

    PENDING = "pending"
    PROVISIONING = "provisioning"
    ACTIVE = "active"
    SUSPENDED = "suspended"
    DEGRADED = "degraded"
    DECOMMISSIONING = "decommissioning"
    ARCHIVED = "archived"
    PURGED = "purged"


class AuditAction(str, Enum):
    """Canonical audit action identifiers (non-exhaustive; extend as needed)."""

    TENANT_CREATE = "tenant.create"
    TENANT_SUSPEND = "tenant.suspend"
    TENANT_RESUME = "tenant.resume"
    TENANT_DECOMMISSION = "tenant.decommission"
    TENANT_CONFIG_UPDATE = "tenant.config.update"
    TENANT_BRANDING_UPDATE = "tenant.branding.update"
    USER_CREATE = "user.create"
    USER_DELETE = "user.delete"
    USER_IMPERSONATE = "user.impersonate"
    SETTINGS_UPDATE = "settings.update"
    INVESTIGATION_APPROVE = "investigation.approve"
    INVESTIGATION_REJECT = "investigation.reject"
    SYSTEM_CONTEXT_ENTER = "system.context.enter"
    LICENSE_ROTATE = "license.rotate"


# ----------------------------------------------------------------------------
# Install-scoped tables (no RLS)
# ----------------------------------------------------------------------------


class Organization(SQLModel, table=True):
    """Install-level identity.

    One row per install. MSSP identity + install identity recorded here. Values
    come from the license JWT (V1.5) or from chart values at install time (V1).
    """

    __tablename__ = "organizations"

    id: UUID = Field(default_factory=uuid4, primary_key=True)
    mssp_id: UUID = Field(unique=True, index=True)
    mssp_name: str = Field(max_length=255)
    install_id: UUID = Field(unique=True, index=True)
    install_label: str | None = Field(default=None, max_length=255)
    slug: str = Field(max_length=63, unique=True, index=True)
    # MSSP-level branding for slug-driven landing.
    logo_url: str | None = Field(default=None, max_length=500)
    primary_color: str | None = Field(default=None, max_length=16)
    secondary_color: str | None = Field(default=None, max_length=16)
    favicon_url: str | None = Field(default=None, max_length=500)
    # Reserved for V1.5 license JWT storage; NULL in V1.
    license_jwt: str | None = Field(default=None, sa_column=Column(Text))
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)


# ----------------------------------------------------------------------------
# Tenant table (install-scoped by presence, but schema defines the primary
# scoping entity for the rest of the tenant-scoped tables)
# ----------------------------------------------------------------------------


class Tenant(SQLModel, table=True):
    """End-customer tenant. One per customer per install."""

    __tablename__ = "tenants"
    __table_args__ = (
        Index("ix_tenants_slug", "slug", unique=True),
        Index("ix_tenants_state", "state"),
    )

    id: UUID = Field(default_factory=uuid4, primary_key=True)
    slug: str = Field(max_length=63)
    display_name: str = Field(max_length=255)
    state: str = Field(default=TenantState.PENDING.value, max_length=32)
    # Deployment profile: 'poc' (ephemeral), 'persistent' (single-node
    # durable), or 'legacy' (pre-wizard tenants — don't re-derive).
    profile: str = Field(default="poc", max_length=16)
    # Association back to the install's Organization row.
    organization_id: UUID = Field(
        sa_column=Column(ForeignKey("organizations.id"), nullable=False, index=True)
    )
    # Tracking fields
    created_at: datetime = Field(default_factory=datetime.utcnow)
    state_changed_at: datetime = Field(default_factory=datetime.utcnow)
    deleted_at: datetime | None = Field(default=None)
    # Config snapshot (mirrors the tenant chart values schema; see P0-8 §3).
    # Stored as JSONB for schema flexibility during V1. Typed pydantic model
    # validates before writes in the application layer.
    config: dict[str, Any] = Field(
        default_factory=dict, sa_column=Column(JSONB, nullable=False)
    )
    # Runtime state reported by the adapter.
    runtime: dict[str, Any] = Field(
        default_factory=dict, sa_column=Column(JSONB, nullable=False)
    )


# ----------------------------------------------------------------------------
# Users (install-scoped presence with optional tenant binding)
# ----------------------------------------------------------------------------


class User(SQLModel, table=True):
    """Unified user table. MSSP-side: tenant_id NULL. Tenant-side: tenant_id set.

    Authentication happens at ingress (OIDC); this table holds the identity
    SocTalk trusts after the handoff. Role + tenant_id together determine scope.
    """

    __tablename__ = "users"
    __table_args__ = (
        Index("ix_users_email", "email", unique=True),
        Index("ix_users_tenant_id", "tenant_id"),
    )

    id: UUID = Field(default_factory=uuid4, primary_key=True)
    email: str = Field(max_length=320)  # RFC 5321 max length
    display_name: str | None = Field(default=None, max_length=255)
    user_type: str = Field(max_length=16)  # UserType enum value
    role: str = Field(max_length=32)  # Role enum value
    tenant_id: UUID | None = Field(
        default=None,
        sa_column=Column(ForeignKey("tenants.id"), nullable=True),
    )
    active: bool = Field(default=True)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    last_seen_at: datetime | None = Field(default=None)


# ----------------------------------------------------------------------------
# Per-tenant config tables
# ----------------------------------------------------------------------------


class IntegrationConfig(SQLModel, table=True):
    """Per-tenant integration endpoints (Wazuh URL, TheHive URL, etc.).

    Secret material (API keys, tokens) is *not* here: stored in K8s Secrets;
    references live in :class:`TenantSecret`.

    Replaces the single-row ``UserSettings('default')`` legacy table.
    """

    __tablename__ = "integration_configs"
    __table_args__ = (
        Index("ix_integration_configs_tenant", "tenant_id", unique=True),
    )

    id: UUID = Field(default_factory=uuid4, primary_key=True)
    tenant_id: UUID = Field(
        sa_column=Column(ForeignKey("tenants.id"), nullable=False, index=True)
    )
    # Wazuh
    wazuh_enabled: bool = Field(default=True)
    wazuh_url: str | None = Field(default=None, max_length=500)
    wazuh_verify_ssl: bool = Field(default=True)
    # TheHive
    thehive_enabled: bool = Field(default=True)
    thehive_url: str | None = Field(default=None, max_length=500)
    thehive_organisation: str | None = Field(default=None, max_length=255)
    thehive_verify_ssl: bool = Field(default=True)
    # Cortex
    cortex_enabled: bool = Field(default=True)
    cortex_url: str | None = Field(default=None, max_length=500)
    cortex_verify_ssl: bool = Field(default=True)
    # MISP (V1.5)
    misp_enabled: bool = Field(default=False)
    misp_url: str | None = Field(default=None, max_length=500)
    misp_verify_ssl: bool = Field(default=True)
    # Slack notifications
    slack_enabled: bool = Field(default=False)
    slack_channel: str | None = Field(default=None, max_length=100)
    slack_notify_on_escalation: bool = Field(default=True)
    slack_notify_on_verdict: bool = Field(default=True)
    # LLM config (per-tenant BYO)
    llm_provider: str = Field(default="openai-compatible", max_length=32)
    llm_base_url: str = Field(default="https://api.openai.com/v1", max_length=500)
    llm_model: str = Field(default="gpt-4o", max_length=255)
    llm_fast_model: str | None = Field(default=None, max_length=255)
    llm_reasoning_model: str | None = Field(default=None, max_length=255)
    llm_temperature: float = Field(default=0.0)
    llm_max_tokens: int = Field(default=4096)
    # Plaintext LLM API key material stored in Postgres.
    #
    # MVP path: needed for the cross-cluster L1→L2 deploy, where the
    # L1 Postgres is the only place L1 can read the key when building
    # the install_helm_release spec (the L2 chart then materializes a
    # K8s Secret from the plaintext Helm value). The legacy in-cluster
    # path also writes the value to the ``soctalk-system/tenant-<id>-llm``
    # K8s Secret for collapsed-tier deploys.
    #
    # Production hardening: layer Fernet-at-rest or a KMS-backed column
    # here before exposing to anything other than internal operators.
    # Tracked as a follow-up to the MVP slice.
    llm_api_key_plain: str | None = Field(default=None, max_length=4096)
    # Timestamps
    updated_at: datetime = Field(default_factory=datetime.utcnow)


class BrandingConfig(SQLModel, table=True):
    """Per-tenant branding (consumed by both UIs via config API)."""

    __tablename__ = "branding_configs"
    __table_args__ = (
        Index("ix_branding_configs_tenant", "tenant_id", unique=True),
    )

    id: UUID = Field(default_factory=uuid4, primary_key=True)
    tenant_id: UUID = Field(
        sa_column=Column(ForeignKey("tenants.id"), nullable=False, index=True)
    )
    app_name: str = Field(default="SocTalk", max_length=255)
    logo_url: str | None = Field(default=None, max_length=500)
    primary_color: str | None = Field(default=None, max_length=16)
    secondary_color: str | None = Field(default=None, max_length=16)
    favicon_url: str | None = Field(default=None, max_length=500)
    updated_at: datetime = Field(default_factory=datetime.utcnow)


class TenantSecret(SQLModel, table=True):
    """Reference (not material) to a Kubernetes Secret holding per-tenant credentials.

    Stored references only; actual secret material never lands in Postgres.
    See P0-5 §1.
    """

    __tablename__ = "tenant_secrets"
    __table_args__ = (
        Index("ix_tenant_secrets_tenant_purpose", "tenant_id", "purpose"),
    )

    id: UUID = Field(default_factory=uuid4, primary_key=True)
    tenant_id: UUID = Field(
        sa_column=Column(ForeignKey("tenants.id"), nullable=False)
    )
    # Purpose enum string, e.g. "llm", "wazuh", "thehive", "cortex", "adapter-jwt"
    purpose: str = Field(max_length=64)
    k8s_namespace: str = Field(max_length=253)
    k8s_secret_name: str = Field(max_length=253)
    k8s_secret_key: str = Field(max_length=253, default="api_key")
    version_label: str | None = Field(default=None, max_length=64)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    rotated_at: datetime | None = Field(default=None)


# ----------------------------------------------------------------------------
# Audit + lifecycle (tenant-scoped with nullable tenant for install-level events)
# ----------------------------------------------------------------------------


class AuditLog(SQLModel, table=True):
    """Append-only audit trail.

    ``tenant_id`` NULL means the event was install-scoped (e.g., platform_admin
    action, system context entry); set means tenant-specific. Customer users
    can read rows WHERE ``tenant_id = own_tenant``: including MSSP-impersonation
    entries where ``acting_as`` is populated.
    """

    __tablename__ = "audit_log"
    __table_args__ = (
        Index("ix_audit_log_tenant_ts", "tenant_id", "timestamp"),
        Index("ix_audit_log_actor", "actor_id"),
        Index("ix_audit_log_action", "action"),
    )

    id: UUID = Field(default_factory=uuid4, primary_key=True)
    timestamp: datetime = Field(default_factory=datetime.utcnow, index=True)
    tenant_id: UUID | None = Field(
        default=None, sa_column=Column(ForeignKey("tenants.id"), nullable=True)
    )
    actor_principal: str = Field(max_length=32)  # user | worker | system | adapter
    actor_id: str = Field(max_length=128)  # user_id | "worker:<job>" | "system:<reason>" | tenant_id
    # For impersonation: the MSSP user acting on behalf of a tenant.
    acting_as: UUID | None = Field(default=None)
    action: str = Field(max_length=64)
    resource_type: str | None = Field(default=None, max_length=64)
    resource_id: str | None = Field(default=None, max_length=128)
    before: dict[str, Any] | None = Field(default=None, sa_column=Column(JSONB))
    after: dict[str, Any] | None = Field(default=None, sa_column=Column(JSONB))
    request_id: str | None = Field(default=None, max_length=128)
    notes: str | None = Field(default=None, sa_column=Column(Text))


class TenantLifecycleEvent(SQLModel, table=True):
    """Append-only log of tenant state transitions and config revisions."""

    __tablename__ = "tenant_lifecycle_events"
    __table_args__ = (
        Index("ix_tle_tenant_ts", "tenant_id", "timestamp"),
    )

    id: UUID = Field(default_factory=uuid4, primary_key=True)
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    tenant_id: UUID = Field(
        sa_column=Column(ForeignKey("tenants.id"), nullable=False)
    )
    event_type: str = Field(max_length=64)
    # e.g., "provisioning_started", "active", "config_updated", "upgrade_requested",
    # "suspended", "resumed", "decommission_started", "archived", "purged"
    from_state: str | None = Field(default=None, max_length=32)
    to_state: str | None = Field(default=None, max_length=32)
    actor_id: str | None = Field(default=None, max_length=128)
    details: dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSONB))


class ProvisioningJob(SQLModel, table=True):
    """Async provisioning work queue.

    One row per pending/in-flight provision-or-decommission request. Worker
    claims with ``SELECT ... FOR UPDATE SKIP LOCKED``, runs the stepwise
    reconcile on ``TenantController``, updates status + attempts.

    The partial unique index ``uq_provisioning_jobs_active`` keeps at most
    one active (pending or in_flight) job per (tenant, kind).
    """

    __tablename__ = "provisioning_jobs"

    id: UUID = Field(default_factory=uuid4, primary_key=True)
    tenant_id: UUID = Field(
        sa_column=Column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    )
    kind: str = Field(max_length=32)  # 'tenant.provision' | 'tenant.decommission'
    status: str = Field(default="pending", max_length=16)
    attempts: int = Field(default=0)
    max_attempts: int = Field(default=5)
    last_error: str | None = Field(default=None, sa_column=Column(Text))
    claimed_at: datetime | None = Field(default=None)
    claimed_by: str | None = Field(default=None, max_length=128)
    next_attempt_at: datetime = Field(default_factory=datetime.utcnow)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)


__all__ = [
    "AuditAction",
    "AuditLog",
    "BrandingConfig",
    "IntegrationConfig",
    "Organization",
    "ProvisioningJob",
    "Role",
    "Tenant",
    "TenantLifecycleEvent",
    "TenantSecret",
    "TenantState",
    "User",
    "UserType",
]
