"""AI-led IR core: cases, events, proposals, execution log, outbox.

Revision ID: v1_0003_ir_core
Revises: v1_0002_internal_auth
Create Date: 2026-04-21

Authoritative spec: ``docs/v1/P2-0-core-invariants.md``.

Adds the data foundation for native AI-led incident response.
Integration-toggle columns for TheHive/MISP are added to
integration_configs; MISP carries the column only (no runtime in MVP).

Forward-only. Rollback via backup restore.
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision: str = "v1_0003_ir_core"
down_revision: str | None = "v1_0002_internal_auth"
branch_labels: str | None = None
depends_on: str | None = None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _visibility_check() -> str:
    """Reusable CHECK for the visibility enum."""
    return "visibility IN ('mssp_only', 'customer_safe', 'system', 'tool_output')"


def _attach_rls_audience(table: str, tenant_col: str = "tenant_id") -> None:
    """Enable + force RLS, attach tenant+audience policy.

    Customer audience sees only non-mssp_only rows. MSSP audience sees
    everything within the tenant. Tenant scoping matches V1 pattern.
    """

    op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
    op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
    op.execute(
        f"""
        CREATE POLICY {table}_tenant_audience ON {table}
          USING (
            -- MSSP cross-tenant read: no tenant filter set, audience='mssp'
            (
              COALESCE(NULLIF(current_setting('app.current_tenant_id', true), ''), '') = ''
              AND current_setting('app.current_audience', true) = 'mssp'
            )
            OR
            -- Normal tenant-scoped read with audience gating
            (
              {tenant_col} IS NOT DISTINCT FROM
                NULLIF(current_setting('app.current_tenant_id', true), '')::uuid
              AND (
                visibility IN ('customer_safe', 'system')
                OR current_setting('app.current_audience', true) = 'mssp'
              )
            )
          )
          WITH CHECK (
            {tenant_col} IS NOT DISTINCT FROM
              NULLIF(current_setting('app.current_tenant_id', true), '')::uuid
          )
        """
    )


def _attach_rls_tenant_only(table: str, tenant_col: str = "tenant_id") -> None:
    """Tenant scoping only (no visibility column on this table)."""

    op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
    op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
    op.execute(
        f"""
        CREATE POLICY {table}_tenant_isolation ON {table}
          USING (
            (
              COALESCE(NULLIF(current_setting('app.current_tenant_id', true), ''), '') = ''
              AND current_setting('app.current_audience', true) = 'mssp'
            )
            OR
            {tenant_col} IS NOT DISTINCT FROM
              NULLIF(current_setting('app.current_tenant_id', true), '')::uuid
          )
          WITH CHECK (
            {tenant_col} IS NOT DISTINCT FROM
              NULLIF(current_setting('app.current_tenant_id', true), '')::uuid
          )
        """
    )


# ---------------------------------------------------------------------------
# Migration
# ---------------------------------------------------------------------------


def upgrade() -> None:
    # ------------------------------------------------------------------
    # Integration-toggle columns on existing integration_configs.
    # Pre-V1 deployments already carried ``thehive_url`` / ``misp_url``
    # (plus a handful of other knobs) via SQLModel auto-create, so use
    # ``ADD COLUMN IF NOT EXISTS`` to stay idempotent on those installs.
    # ------------------------------------------------------------------
    op.execute(
        """
        ALTER TABLE integration_configs
          ADD COLUMN IF NOT EXISTS thehive_export_enabled BOOLEAN NOT NULL DEFAULT false,
          ADD COLUMN IF NOT EXISTS thehive_url TEXT,
          ADD COLUMN IF NOT EXISTS thehive_api_key_secret_ref TEXT,
          ADD COLUMN IF NOT EXISTS misp_ingest_enabled BOOLEAN NOT NULL DEFAULT false,
          ADD COLUMN IF NOT EXISTS misp_url TEXT,
          ADD COLUMN IF NOT EXISTS misp_api_key_secret_ref TEXT,
          ADD COLUMN IF NOT EXISTS auto_close_enabled BOOLEAN NOT NULL DEFAULT true
        """
    )

    # ------------------------------------------------------------------
    # alerts (the case_id FK → cases is added after cases is created,
    # via ALTER TABLE, to avoid forward-reference ordering issues).
    # ------------------------------------------------------------------
    op.create_table(
        "alerts",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "tenant_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("tenants.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("source", sa.Text(), nullable=False),  # 'wazuh', etc.
        sa.Column("rule_id", sa.Text(), nullable=True),
        sa.Column("severity", sa.SmallInteger(), nullable=False),
        sa.Column("signature", sa.Text(), nullable=False),  # coalescing key
        sa.Column("first_event_at", sa.TIMESTAMP(timezone=True), nullable=False),
        sa.Column("last_event_at", sa.TIMESTAMP(timezone=True), nullable=False),
        sa.Column("event_count", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("source_event_ids", postgresql.JSONB(), nullable=False,
                  server_default=sa.text("'[]'::jsonb")),
        sa.Column("asset_ids", postgresql.JSONB(), nullable=False,
                  server_default=sa.text("'[]'::jsonb")),
        sa.Column("initial_iocs", postgresql.JSONB(), nullable=False,
                  server_default=sa.text("'[]'::jsonb")),
        sa.Column(
            "ai_assessment",
            sa.Text(),
            nullable=True,
        ),  # 'real' | 'unclear' | 'likely_fp' | 'high_conf_fp'
        sa.Column("ai_confidence", sa.Float(), nullable=True),
        sa.Column(
            "status",
            sa.Text(),
            nullable=False,
            server_default=sa.text("'new'"),
        ),  # 'new' | 'acked' | 'promoted' | 'ignored' | 'auto_closed'
        sa.Column(
            "case_id",
            postgresql.UUID(as_uuid=True),
            nullable=True,
        ),
        sa.Column("visibility", sa.Text(), nullable=False, server_default=sa.text("'mssp_only'")),
        sa.Column("created_at", sa.TIMESTAMP(timezone=True), nullable=False,
                  server_default=sa.func.now()),
        sa.CheckConstraint(_visibility_check(), name="ck_alerts_visibility"),
    )
    op.create_index("ix_alerts_tenant_status", "alerts", ["tenant_id", "status"])
    op.create_index("ix_alerts_signature", "alerts", ["tenant_id", "signature"])

    # ------------------------------------------------------------------
    # cases
    # ------------------------------------------------------------------
    op.create_table(
        "cases",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "tenant_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("tenants.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("short_id", sa.Text(), nullable=False),
        sa.Column("title", sa.Text(), nullable=False),
        sa.Column(
            "status",
            sa.Text(),
            nullable=False,
            server_default=sa.text("'active'"),
        ),  # 'active' | 'paused' | 'closed' | 'auto_closed_fp'
        sa.Column("severity", sa.SmallInteger(), nullable=False),
        sa.Column("assignee_user_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("summary", sa.Text(), nullable=True),
        sa.Column("opened_at", sa.TIMESTAMP(timezone=True), nullable=False,
                  server_default=sa.func.now()),
        sa.Column("closed_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("close_reason", sa.Text(), nullable=True),
        # Auto-close reopen semantics
        sa.Column("reopen_window_until", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("reopen_signature", postgresql.JSONB(), nullable=True),
        sa.Column("reopen_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("visibility", sa.Text(), nullable=False, server_default=sa.text("'mssp_only'")),
        sa.Column("created_at", sa.TIMESTAMP(timezone=True), nullable=False,
                  server_default=sa.func.now()),
        sa.Column("updated_at", sa.TIMESTAMP(timezone=True), nullable=False,
                  server_default=sa.func.now()),
        sa.CheckConstraint(_visibility_check(), name="ck_cases_visibility"),
        sa.UniqueConstraint("tenant_id", "short_id", name="uq_cases_tenant_short_id"),
    )
    op.create_index("ix_cases_tenant_status", "cases", ["tenant_id", "status"])

    # Back-reference from alerts → cases, added now that cases exists.
    op.execute(
        "ALTER TABLE alerts ADD CONSTRAINT fk_alerts_case "
        "FOREIGN KEY (case_id) REFERENCES cases(id) ON DELETE SET NULL"
    )

    # Sequence for case short_ids (install-scoped counter)
    op.execute("CREATE SEQUENCE IF NOT EXISTS cases_short_id_seq")

    # ------------------------------------------------------------------
    # case_runs
    # ------------------------------------------------------------------
    op.create_table(
        "case_runs",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "tenant_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("tenants.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "case_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("cases.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "status",
            sa.Text(),
            nullable=False,
            server_default=sa.text("'active'"),
        ),  # active | paused | waiting_on_gate | halted_budget | completed | failed
        sa.Column("tokens_used", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("tokens_budget", sa.Integer(), nullable=False, server_default="200000"),
        sa.Column("dollars_used", sa.Float(), nullable=False, server_default="0"),
        sa.Column("dollars_budget", sa.Float(), nullable=False, server_default="5.0"),
        sa.Column("tool_calls_used", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("tool_calls_budget", sa.Integer(), nullable=False, server_default="200"),
        sa.Column("started_at", sa.TIMESTAMP(timezone=True), nullable=False,
                  server_default=sa.func.now()),
        sa.Column("ended_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("last_error", sa.Text(), nullable=True),
    )
    # At most one active run per case.
    op.execute(
        """
        CREATE UNIQUE INDEX uq_case_runs_single_active ON case_runs (case_id)
          WHERE status IN ('active', 'paused', 'waiting_on_gate', 'halted_budget')
        """
    )

    # ------------------------------------------------------------------
    # case_events (inbox, immutable)
    # ------------------------------------------------------------------
    op.execute("CREATE SEQUENCE IF NOT EXISTS case_events_seq")
    op.create_table(
        "case_events",
        sa.Column("event_id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "tenant_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("tenants.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "case_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("cases.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "run_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("case_runs.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "seq",
            sa.BigInteger(),
            nullable=False,
            server_default=sa.text("nextval('case_events_seq')"),
        ),
        sa.Column("kind", sa.Text(), nullable=False),
        sa.Column("payload", postgresql.JSONB(), nullable=False,
                  server_default=sa.text("'{}'::jsonb")),
        sa.Column("causation_event_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("correlation_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("idempotency_key", sa.Text(), nullable=False),
        sa.Column(
            "visibility",
            sa.Text(),
            nullable=False,
            server_default=sa.text("'mssp_only'"),
        ),
        sa.Column("created_at", sa.TIMESTAMP(timezone=True), nullable=False,
                  server_default=sa.func.now()),
        sa.CheckConstraint(_visibility_check(), name="ck_case_events_visibility"),
        sa.UniqueConstraint("case_id", "idempotency_key",
                            name="uq_case_events_idempotency"),
    )
    op.create_index("ix_case_events_case_seq", "case_events", ["case_id", "seq"])

    # ------------------------------------------------------------------
    # case_facts (reducer-owned projection)
    # ------------------------------------------------------------------
    op.create_table(
        "case_facts",
        sa.Column(
            "case_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("cases.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column(
            "tenant_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("tenants.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("hypotheses", postgresql.JSONB(), nullable=False,
                  server_default=sa.text("'[]'::jsonb")),
        sa.Column("active_directives", postgresql.JSONB(), nullable=False,
                  server_default=sa.text("'[]'::jsonb")),
        sa.Column("active_policies", postgresql.JSONB(), nullable=False,
                  server_default=sa.text("'[]'::jsonb")),
        sa.Column("timeline_summary", postgresql.JSONB(), nullable=False,
                  server_default=sa.text("'[]'::jsonb")),
        sa.Column("applied_seq", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("updated_at", sa.TIMESTAMP(timezone=True), nullable=False,
                  server_default=sa.func.now()),
    )

    # ------------------------------------------------------------------
    # iocs (global within tenant; attaches to cases via bridge)
    # ------------------------------------------------------------------
    op.create_table(
        "iocs",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "tenant_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("tenants.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("type", sa.Text(), nullable=False),  # closed enum in app
        sa.Column("value", sa.Text(), nullable=False),
        sa.Column("fingerprint", sa.Text(), nullable=False),
        sa.Column("tlp", sa.Text(), nullable=False, server_default=sa.text("'amber'")),
        sa.Column("pap", sa.Text(), nullable=False, server_default=sa.text("'amber'")),
        sa.Column("first_seen", sa.TIMESTAMP(timezone=True), nullable=False,
                  server_default=sa.func.now()),
        sa.Column("last_seen", sa.TIMESTAMP(timezone=True), nullable=False,
                  server_default=sa.func.now()),
        sa.Column("external_context", postgresql.JSONB(), nullable=False,
                  server_default=sa.text("'{}'::jsonb")),
        sa.Column("visibility", sa.Text(), nullable=False,
                  server_default=sa.text("'mssp_only'")),
        sa.CheckConstraint(_visibility_check(), name="ck_iocs_visibility"),
        sa.UniqueConstraint("tenant_id", "fingerprint", name="uq_iocs_fingerprint"),
    )
    op.create_index("ix_iocs_tenant_type", "iocs", ["tenant_id", "type"])

    op.create_table(
        "case_iocs",
        sa.Column(
            "tenant_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("tenants.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "case_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("cases.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column(
            "ioc_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("iocs.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column("added_at", sa.TIMESTAMP(timezone=True), nullable=False,
                  server_default=sa.func.now()),
        sa.Column("added_by", sa.Text(), nullable=False),  # 'ai' | user_id
    )

    # ------------------------------------------------------------------
    # case_assets (minimal; assets are free-form in MVP)
    # ------------------------------------------------------------------
    op.create_table(
        "case_assets",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "tenant_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("tenants.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "case_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("cases.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("kind", sa.Text(), nullable=False),  # 'host' | 'user' | 'service'
        sa.Column("identifier", sa.Text(), nullable=False),
        sa.Column("details", postgresql.JSONB(), nullable=False,
                  server_default=sa.text("'{}'::jsonb")),
        sa.Column("added_at", sa.TIMESTAMP(timezone=True), nullable=False,
                  server_default=sa.func.now()),
    )
    op.create_index("ix_case_assets_case", "case_assets", ["case_id"])

    # ------------------------------------------------------------------
    # case_links (related-case hints; substrate for campaigns in v1.x)
    # ------------------------------------------------------------------
    op.create_table(
        "case_links",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "tenant_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("tenants.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "from_case_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("cases.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "to_case_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("cases.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("link_kind", sa.Text(), nullable=False),
        # 'shared_ioc' | 'shared_asset' | 'shared_rule' | 'analyst_marked'
        sa.Column("signature", postgresql.JSONB(), nullable=False,
                  server_default=sa.text("'{}'::jsonb")),
        sa.Column("confidence", sa.Float(), nullable=False, server_default="0.5"),
        sa.Column("created_by", sa.Text(), nullable=False),  # 'ai' | user_id
        sa.Column("created_at", sa.TIMESTAMP(timezone=True), nullable=False,
                  server_default=sa.func.now()),
        sa.Column("visibility", sa.Text(), nullable=False,
                  server_default=sa.text("'mssp_only'")),
        sa.CheckConstraint(_visibility_check(), name="ck_case_links_visibility"),
        sa.UniqueConstraint("from_case_id", "to_case_id", "link_kind",
                            name="uq_case_links_pair_kind"),
        sa.CheckConstraint(
            "from_case_id <> to_case_id",
            name="ck_case_links_distinct",
        ),
    )
    op.create_index("ix_case_links_from", "case_links", ["from_case_id"])
    op.create_index("ix_case_links_to", "case_links", ["to_case_id"])

    # ------------------------------------------------------------------
    # notes
    # ------------------------------------------------------------------
    op.create_table(
        "notes",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "tenant_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("tenants.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "case_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("cases.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("author_kind", sa.Text(), nullable=False),  # 'ai' | 'human' | 'system'
        sa.Column("author_id", sa.Text(), nullable=True),
        sa.Column("body", sa.Text(), nullable=False),
        sa.Column("visibility", sa.Text(), nullable=False,
                  server_default=sa.text("'mssp_only'")),
        sa.Column("created_at", sa.TIMESTAMP(timezone=True), nullable=False,
                  server_default=sa.func.now()),
        sa.CheckConstraint(_visibility_check(), name="ck_notes_visibility"),
    )
    op.create_index("ix_notes_case", "notes", ["case_id", "created_at"])

    # ------------------------------------------------------------------
    # proposals
    # ------------------------------------------------------------------
    op.create_table(
        "proposals",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "tenant_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("tenants.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "case_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("cases.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "run_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("case_runs.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("action_type", sa.Text(), nullable=False),
        sa.Column("params", postgresql.JSONB(), nullable=False,
                  server_default=sa.text("'{}'::jsonb")),
        sa.Column("rationale", sa.Text(), nullable=False, server_default=sa.text("''")),
        sa.Column("blast_radius", sa.Text(), nullable=True),
        sa.Column("capability_class", sa.Text(), nullable=False),
        sa.Column(
            "status",
            sa.Text(),
            nullable=False,
            server_default=sa.text("'draft'"),
        ),  # draft | proposed | approved | rejected | executing | executed | rolled_back | failed
        sa.Column("idempotency_key", sa.Text(), nullable=False),
        sa.Column("approver_user_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("approval_reason", sa.Text(), nullable=True),
        sa.Column("rejected_reason", sa.Text(), nullable=True),
        sa.Column("visibility", sa.Text(), nullable=False,
                  server_default=sa.text("'mssp_only'")),
        sa.Column("created_at", sa.TIMESTAMP(timezone=True), nullable=False,
                  server_default=sa.func.now()),
        sa.Column("updated_at", sa.TIMESTAMP(timezone=True), nullable=False,
                  server_default=sa.func.now()),
        sa.CheckConstraint(_visibility_check(), name="ck_proposals_visibility"),
    )
    # Idempotency unique within case.
    op.create_index(
        "uq_proposals_idempotency",
        "proposals",
        ["case_id", "idempotency_key"],
        unique=True,
    )
    op.create_index("ix_proposals_case_status", "proposals", ["case_id", "status"])

    # ------------------------------------------------------------------
    # case_outbox (executor + export queue)
    # ------------------------------------------------------------------
    op.create_table(
        "case_outbox",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "tenant_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("tenants.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "case_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("cases.id", ondelete="CASCADE"),
            nullable=True,
        ),
        sa.Column("kind", sa.Text(), nullable=False),
        # 'execute_proposal' | 'export.thehive.case' | ...
        sa.Column("idempotency_key", sa.Text(), nullable=False, unique=True),
        sa.Column("payload", postgresql.JSONB(), nullable=False,
                  server_default=sa.text("'{}'::jsonb")),
        sa.Column("external_system", sa.Text(), nullable=True),
        sa.Column("external_ref", sa.Text(), nullable=True),
        sa.Column(
            "status",
            sa.Text(),
            nullable=False,
            server_default=sa.text("'pending'"),
        ),  # pending | in_flight | succeeded | failed
        sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("max_attempts", sa.Integer(), nullable=False, server_default="5"),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column("claimed_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("claimed_by", sa.Text(), nullable=True),
        sa.Column("next_attempt_at", sa.TIMESTAMP(timezone=True), nullable=False,
                  server_default=sa.func.now()),
        sa.Column("succeeded_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("created_at", sa.TIMESTAMP(timezone=True), nullable=False,
                  server_default=sa.func.now()),
        sa.Column("updated_at", sa.TIMESTAMP(timezone=True), nullable=False,
                  server_default=sa.func.now()),
    )
    op.create_index(
        "ix_case_outbox_claim",
        "case_outbox",
        ["status", "next_attempt_at"],
    )

    # ------------------------------------------------------------------
    # execution_log (append-only audit, separate from conversation)
    # ------------------------------------------------------------------
    op.create_table(
        "execution_log",
        sa.Column("log_id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "tenant_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("tenants.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "case_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("cases.id", ondelete="CASCADE"),
            nullable=True,
        ),
        sa.Column(
            "run_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("case_runs.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("actor_kind", sa.Text(), nullable=False),
        # ai | human | system | executor
        sa.Column("actor_id", sa.Text(), nullable=False),
        sa.Column("kind", sa.Text(), nullable=False),
        sa.Column("subject_type", sa.Text(), nullable=True),
        sa.Column("subject_id", sa.Text(), nullable=True),
        sa.Column("before", postgresql.JSONB(), nullable=True),
        sa.Column("after", postgresql.JSONB(), nullable=True),
        sa.Column("versions", postgresql.JSONB(), nullable=False,
                  server_default=sa.text("'{}'::jsonb")),
        sa.Column("ts", sa.TIMESTAMP(timezone=True), nullable=False,
                  server_default=sa.func.now()),
    )
    op.create_index("ix_execution_log_case_ts", "execution_log", ["case_id", "ts"])

    # ------------------------------------------------------------------
    # tenant_policies (per-tenant policy overrides; install defaults in YAML)
    # ------------------------------------------------------------------
    op.create_table(
        "tenant_policies",
        sa.Column(
            "tenant_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("tenants.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column(
            "key",
            sa.Text(),
            primary_key=True,
        ),
        sa.Column("value", postgresql.JSONB(), nullable=False,
                  server_default=sa.text("'null'::jsonb")),
        sa.Column("updated_at", sa.TIMESTAMP(timezone=True), nullable=False,
                  server_default=sa.func.now()),
    )

    # ------------------------------------------------------------------
    # Attach RLS
    # ------------------------------------------------------------------
    for tbl in (
        "alerts",
        "cases",
        "case_events",
        "iocs",
        "notes",
        "proposals",
        "case_links",
    ):
        _attach_rls_audience(tbl)

    for tbl in (
        "case_runs",
        "case_facts",
        "case_iocs",
        "case_assets",
        "case_outbox",
        "execution_log",
        "tenant_policies",
    ):
        _attach_rls_tenant_only(tbl)

    # ------------------------------------------------------------------
    # Grants — role-specific
    # ------------------------------------------------------------------
    app_tables = (
        "alerts", "cases", "case_events", "case_runs", "case_facts",
        "iocs", "case_iocs", "case_assets", "case_links", "notes",
        "proposals", "case_outbox", "tenant_policies",
    )
    for tbl in app_tables:
        op.execute(
            f"GRANT SELECT, INSERT, UPDATE, DELETE ON {tbl} "
            "TO soctalk_app, soctalk_mssp"
        )

    # execution_log is INSERT + SELECT only for app + mssp roles.
    op.execute(
        "GRANT SELECT, INSERT ON execution_log TO soctalk_app, soctalk_mssp"
    )
    # Sequences
    op.execute("GRANT USAGE, SELECT ON SEQUENCE case_events_seq TO soctalk_app, soctalk_mssp")
    op.execute("GRANT USAGE, SELECT ON SEQUENCE cases_short_id_seq TO soctalk_app, soctalk_mssp")
