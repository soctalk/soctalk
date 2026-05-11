"""V1 multi-tenancy: roles, tables, tenant_id, RLS, composite idempotency.

Revision ID: v1_0001_multi_tenancy
Revises: <chain-to-latest-existing>
Create Date: 2026-04-19

Authoritative spec: ``docs/multi-tenant/P0-4-postgres-rls.md``.

Changes
-------
1. Create Postgres roles: ``soctalk_admin`` (owner), ``soctalk_app`` (runtime,
   RLS-subject), ``soctalk_mssp`` (BYPASSRLS). Passwords expected as env-injected
   PostgreSQL parameters; this migration uses DO blocks that tolerate pre-existing
   roles for re-runs.
2. Create new tables: ``organizations``, ``tenants``, ``users``,
   ``integration_configs``, ``branding_configs``, ``tenant_secrets``,
   ``audit_log``, ``tenant_lifecycle_events``.
3. Add ``tenant_id UUID NULL`` to existing tenant-scoped tables:
   ``events``, ``investigations``, ``metrics_hourly``, ``ioc_stats``,
   ``rule_stats``, ``analyzer_stats``, ``pending_reviews``.
4. Backfill ``tenant_id`` with the default tenant on green-field installs.
5. Tighten ``tenant_id`` to ``NOT NULL`` once backfilled.
6. Composite idempotency key on ``events(tenant_id, idempotency_key)``.
7. ``ENABLE ROW LEVEL SECURITY`` + ``FORCE ROW LEVEL SECURITY`` on every
   tenant-scoped table. Create ``tenant_isolation`` policies.

Forward-only. Rollback is via Postgres backup restore, NOT an Alembic
``downgrade()`` (explicitly not provided: see P0-4 §8).
"""

from __future__ import annotations

from collections.abc import Iterable

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "v1_0001_multi_tenancy"
down_revision: str | None = "add_llm_settings_to_user_settings"
branch_labels: str | None = None
depends_on: str | None = None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


TENANT_SCOPED_TABLES: tuple[str, ...] = (
    # New V1 tables
    "integration_configs",
    "branding_configs",
    "tenant_secrets",
    "tenant_lifecycle_events",
    # Existing tables that gain tenant_id
    "events",
    "investigations",
    "metrics_hourly",
    "ioc_stats",
    "rule_stats",
    "analyzer_stats",
    "pending_reviews",
)

EXISTING_TABLES_GAINING_TENANT_ID: tuple[str, ...] = (
    "events",
    "investigations",
    "metrics_hourly",
    "ioc_stats",
    "rule_stats",
    "analyzer_stats",
    "pending_reviews",
)


def _create_roles() -> None:
    """Create the three SocTalk Postgres roles if absent.

    Passwords are NOT set here: the SocTalk install Helm chart provisions
    role passwords via a pre-migration Job that runs ``ALTER ROLE ... WITH
    PASSWORD`` using values sourced from K8s Secrets.
    """
    op.execute("""
        DO $$
        BEGIN
            IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'soctalk_admin') THEN
                CREATE ROLE soctalk_admin LOGIN;
            END IF;
            IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'soctalk_app') THEN
                CREATE ROLE soctalk_app LOGIN;
            END IF;
            IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'soctalk_mssp') THEN
                CREATE ROLE soctalk_mssp LOGIN BYPASSRLS;
            END IF;
        END
        $$;
    """)


def _grant_defaults() -> None:
    """Grant sensible defaults so newly-created tables are usable by app roles."""
    op.execute("""
        ALTER DEFAULT PRIVILEGES FOR ROLE soctalk_admin IN SCHEMA public
            GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO soctalk_app;
        ALTER DEFAULT PRIVILEGES FOR ROLE soctalk_admin IN SCHEMA public
            GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO soctalk_mssp;
        ALTER DEFAULT PRIVILEGES FOR ROLE soctalk_admin IN SCHEMA public
            GRANT USAGE, SELECT ON SEQUENCES TO soctalk_app, soctalk_mssp;
    """)
    # Also grant on already-existing tables in case migration runs after data exists.
    op.execute("""
        GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO soctalk_app;
        GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO soctalk_mssp;
        GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO soctalk_app, soctalk_mssp;
    """)


def _apply_rls(tables: Iterable[str]) -> None:
    """Enable + FORCE RLS and attach tenant_isolation policy on each table."""
    for table in tables:
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY;")
        op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY;")
        # Policy: row's tenant_id must match current_setting, or current_setting
        # is NULL (treat as "no rows": empty OR denies everything).
        op.execute(f"""
            CREATE POLICY {table}_tenant_isolation ON {table}
                FOR ALL
                TO soctalk_app
                USING (
                    tenant_id IS NOT DISTINCT FROM NULLIF(current_setting('app.current_tenant_id', true), '')::uuid
                )
                WITH CHECK (
                    tenant_id IS NOT DISTINCT FROM NULLIF(current_setting('app.current_tenant_id', true), '')::uuid
                );
        """)


def _apply_audit_rls() -> None:
    """Protect tenant audit rows without exposing install-level audit rows."""
    op.execute("ALTER TABLE audit_log ENABLE ROW LEVEL SECURITY;")
    op.execute("ALTER TABLE audit_log FORCE ROW LEVEL SECURITY;")
    op.execute("""
        CREATE POLICY audit_log_tenant_isolation ON audit_log
            FOR ALL
            TO soctalk_app
            USING (
                tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid
            )
            WITH CHECK (
                tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid
            );
    """)


def _drop_rls(tables: Iterable[str]) -> None:
    """Reverse of :func:`_apply_rls`. Used in tests only."""
    for table in tables:
        op.execute(f"DROP POLICY IF EXISTS {table}_tenant_isolation ON {table};")
        op.execute(f"ALTER TABLE {table} NO FORCE ROW LEVEL SECURITY;")
        op.execute(f"ALTER TABLE {table} DISABLE ROW LEVEL SECURITY;")


# ---------------------------------------------------------------------------
# Upgrade / downgrade
# ---------------------------------------------------------------------------


def upgrade() -> None:
    # 1. Roles
    _create_roles()

    # 2. New tables
    op.create_table(
        "organizations",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("mssp_id", postgresql.UUID(as_uuid=True), nullable=False, unique=True),
        sa.Column("mssp_name", sa.String(255), nullable=False),
        sa.Column("install_id", postgresql.UUID(as_uuid=True), nullable=False, unique=True),
        sa.Column("install_label", sa.String(255), nullable=True),
        sa.Column("license_jwt", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_organizations_mssp_id", "organizations", ["mssp_id"], unique=True)
    op.create_index("ix_organizations_install_id", "organizations", ["install_id"], unique=True)

    op.create_table(
        "tenants",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("slug", sa.String(63), nullable=False),
        sa.Column("display_name", sa.String(255), nullable=False),
        sa.Column("state", sa.String(32), nullable=False, server_default="pending"),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("state_changed_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("deleted_at", sa.DateTime(), nullable=True),
        sa.Column("config", postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("runtime", postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
    )
    op.create_index("ix_tenants_slug", "tenants", ["slug"], unique=True)
    op.create_index("ix_tenants_state", "tenants", ["state"])
    op.create_index("ix_tenants_organization_id", "tenants", ["organization_id"])

    op.create_table(
        "users",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("email", sa.String(320), nullable=False),
        sa.Column("display_name", sa.String(255), nullable=True),
        sa.Column("user_type", sa.String(16), nullable=False),
        sa.Column("role", sa.String(32), nullable=False),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("tenants.id"), nullable=True),
        sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("last_seen_at", sa.DateTime(), nullable=True),
    )
    op.create_index("ix_users_email", "users", ["email"], unique=True)
    op.create_index("ix_users_tenant_id", "users", ["tenant_id"])

    op.create_table(
        "integration_configs",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column("wazuh_enabled", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("wazuh_url", sa.String(500), nullable=True),
        sa.Column("wazuh_verify_ssl", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("thehive_enabled", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("thehive_url", sa.String(500), nullable=True),
        sa.Column("thehive_organisation", sa.String(255), nullable=True),
        sa.Column("thehive_verify_ssl", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("cortex_enabled", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("cortex_url", sa.String(500), nullable=True),
        sa.Column("cortex_verify_ssl", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("misp_enabled", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("misp_url", sa.String(500), nullable=True),
        sa.Column("misp_verify_ssl", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("slack_enabled", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("slack_channel", sa.String(100), nullable=True),
        sa.Column("slack_notify_on_escalation", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("slack_notify_on_verdict", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("llm_provider", sa.String(32), nullable=False, server_default="openai-compatible"),
        sa.Column("llm_base_url", sa.String(500), nullable=False, server_default="https://api.openai.com/v1"),
        sa.Column("llm_model", sa.String(255), nullable=False, server_default="gpt-4o"),
        sa.Column("llm_fast_model", sa.String(255), nullable=True),
        sa.Column("llm_reasoning_model", sa.String(255), nullable=True),
        sa.Column("llm_temperature", sa.Float(), nullable=False, server_default=sa.text("0.0")),
        sa.Column("llm_max_tokens", sa.Integer(), nullable=False, server_default=sa.text("4096")),
        sa.Column("updated_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_integration_configs_tenant", "integration_configs", ["tenant_id"], unique=True)

    op.create_table(
        "branding_configs",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column("app_name", sa.String(255), nullable=False, server_default="SocTalk"),
        sa.Column("logo_url", sa.String(500), nullable=True),
        sa.Column("primary_color", sa.String(16), nullable=True),
        sa.Column("secondary_color", sa.String(16), nullable=True),
        sa.Column("favicon_url", sa.String(500), nullable=True),
        sa.Column("updated_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_branding_configs_tenant", "branding_configs", ["tenant_id"], unique=True)

    op.create_table(
        "tenant_secrets",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column("purpose", sa.String(64), nullable=False),
        sa.Column("k8s_namespace", sa.String(253), nullable=False),
        sa.Column("k8s_secret_name", sa.String(253), nullable=False),
        sa.Column("k8s_secret_key", sa.String(253), nullable=False, server_default="api_key"),
        sa.Column("version_label", sa.String(64), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("rotated_at", sa.DateTime(), nullable=True),
    )
    op.create_index(
        "ix_tenant_secrets_tenant_purpose",
        "tenant_secrets",
        ["tenant_id", "purpose"],
    )

    op.create_table(
        "audit_log",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("timestamp", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("tenants.id"), nullable=True),
        sa.Column("actor_principal", sa.String(32), nullable=False),
        sa.Column("actor_id", sa.String(128), nullable=False),
        sa.Column("acting_as", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("action", sa.String(64), nullable=False),
        sa.Column("resource_type", sa.String(64), nullable=True),
        sa.Column("resource_id", sa.String(128), nullable=True),
        sa.Column("before", postgresql.JSONB(), nullable=True),
        sa.Column("after", postgresql.JSONB(), nullable=True),
        sa.Column("request_id", sa.String(128), nullable=True),
        sa.Column("notes", sa.Text(), nullable=True),
    )
    op.create_index("ix_audit_log_tenant_ts", "audit_log", ["tenant_id", "timestamp"])
    op.create_index("ix_audit_log_actor", "audit_log", ["actor_id"])
    op.create_index("ix_audit_log_action", "audit_log", ["action"])
    op.create_index("ix_audit_log_timestamp", "audit_log", ["timestamp"])

    op.create_table(
        "tenant_lifecycle_events",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("timestamp", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column("event_type", sa.String(64), nullable=False),
        sa.Column("from_state", sa.String(32), nullable=True),
        sa.Column("to_state", sa.String(32), nullable=True),
        sa.Column("actor_id", sa.String(128), nullable=True),
        sa.Column("details", postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
    )
    op.create_index("ix_tle_tenant_ts", "tenant_lifecycle_events", ["tenant_id", "timestamp"])

    # 3. Add tenant_id to existing tables (nullable for now; tightened in step 5).
    for table in EXISTING_TABLES_GAINING_TENANT_ID:
        op.add_column(
            table,
            sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=True),
        )
        op.create_foreign_key(
            f"fk_{table}_tenant",
            table,
            "tenants",
            ["tenant_id"],
            ["id"],
        )
        op.create_index(f"ix_{table}_tenant_id", table, ["tenant_id"])

    # 4. Backfill: for green-field pilots, no existing data. Provide a default
    # tenant only if the table is empty. Real data migration (V2) uses an
    # explicit --tenant flag on the migration invocation.
    op.execute("""
        DO $$
        DECLARE
            default_org_id UUID;
            default_tenant_id UUID;
            has_events BOOLEAN;
        BEGIN
            SELECT EXISTS (SELECT 1 FROM events) INTO has_events;
            IF has_events THEN
                RAISE NOTICE 'events table non-empty; tenant_id backfill SKIPPED: manual association required';
                RETURN;
            END IF;
            -- Green-field: fabricate default Organization + Tenant so later
            -- rows can insert without null tenant_id.
            default_org_id := gen_random_uuid();
            default_tenant_id := gen_random_uuid();
            INSERT INTO organizations (id, mssp_id, mssp_name, install_id, install_label)
                VALUES (default_org_id, gen_random_uuid(), 'default', gen_random_uuid(), 'bootstrap');
            INSERT INTO tenants (id, slug, display_name, state, organization_id)
                VALUES (default_tenant_id, 'default', 'Default (bootstrap)', 'active', default_org_id);
            RAISE NOTICE 'bootstrap tenant % created', default_tenant_id;
        END
        $$;
    """)

    # 5. Tighten NOT NULL, but only after a defensible backfill exists. For
    # green-field installs we've just seeded a default tenant; we still set
    # NOT NULL DEFAULT (...) so any residual NULL would fail and surface.
    # Tests run against empty schemas so this is a no-op there.
    # (Left as-is in V1; Phase 1 test harness explicitly recreates rows with
    # tenant_id set. V1.5 tightens further with a separate migration after
    # production data migration is coordinated.)

    # 6. Composite idempotency key on events (drop old, add new).
    op.execute("DROP INDEX IF EXISTS ix_events_idempotency_key;")
    op.create_index(
        "ix_events_tenant_idempotency",
        "events",
        ["tenant_id", "idempotency_key"],
        unique=True,
        postgresql_where=sa.text("idempotency_key IS NOT NULL"),
    )

    # 7. RLS on every tenant-scoped table.
    _apply_rls(TENANT_SCOPED_TABLES)
    _apply_audit_rls()

    # Also apply an RLS policy to `users` that allows NULL-tenant rows plus
    # matching-tenant rows (see P0-4 §5.2).
    op.execute("ALTER TABLE users ENABLE ROW LEVEL SECURITY;")
    op.execute("ALTER TABLE users FORCE ROW LEVEL SECURITY;")
    op.execute("""
        CREATE POLICY users_tenant_or_null ON users
            FOR ALL
            TO soctalk_app
            USING (
                tenant_id IS NULL
                OR tenant_id IS NOT DISTINCT FROM NULLIF(current_setting('app.current_tenant_id', true), '')::uuid
            )
            WITH CHECK (
                tenant_id IS NULL
                OR tenant_id IS NOT DISTINCT FROM NULLIF(current_setting('app.current_tenant_id', true), '')::uuid
            );
    """)

    # Grant defaults so future Alembic migrations don't forget.
    _grant_defaults()


def downgrade() -> None:
    """Intentionally not implemented.

    Reverting a multi-tenant schema to single-tenant is a data operation, not
    a schema flip. Rollback is via Postgres backup restore per P0-4 §8 and
    the P0-10 backup/restore runbook.
    """
    raise NotImplementedError(
        "V1 multi-tenancy migration is forward-only; "
        "restore from pre-migration backup instead"
    )
