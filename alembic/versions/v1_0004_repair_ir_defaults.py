"""Repair v1_0003 drift: audit_log RLS, execution_log grants, over-quoted
string defaults.

Revision ID: v1_0004_repair_ir_defaults
Revises: v1_0003_ir_core
Create Date: 2026-04-21

Three problems surfaced on installs that applied v1_0003 before these
fixes landed:

1. ``audit_log`` lost ``ENABLE ROW LEVEL SECURITY`` / its tenant-isolation
   policy somewhere between v1_0001 and v1_0003. Re-apply idempotently so
   installs that are already missing them self-heal.

2. ``execution_log`` ended up with UPDATE/DELETE grants for
   ``soctalk_app`` and ``soctalk_mssp`` (stale from an earlier draft where
   it was bundled with the general tenant-scoped tables). The migration
   source has always wanted append-only; REVOKE idempotently.

3. Every ``server_default="'literal'"`` in v1_0003 rendered as
   ``'''literal'''`` in Postgres, so the stored default was the 8-char
   string ``'literal'`` (quotes included) — which breaks every CHECK
   constraint on the affected columns. The v1_0003 source has been
   rewritten to use ``sa.text("'literal'")``; this migration patches the
   already-materialised columns with ``ALTER COLUMN SET DEFAULT``.

Forward-only. Safe to re-run (all statements are idempotent or
already-correct-value no-ops).
"""

from __future__ import annotations

from alembic import op


revision: str = "v1_0004_repair_ir_defaults"
down_revision: str | None = "v1_0003_ir_core"
branch_labels: str | None = None
depends_on: str | None = None


# (table, column, default-literal) triples. The literal is passed through
# to SQL verbatim so it carries its own quoting.
_DEFAULT_REPAIRS: tuple[tuple[str, str, str], ...] = (
    ("alerts", "status", "'new'"),
    ("alerts", "visibility", "'mssp_only'"),
    ("cases", "status", "'active'"),
    ("cases", "visibility", "'mssp_only'"),
    ("case_runs", "status", "'active'"),
    ("case_events", "visibility", "'mssp_only'"),
    ("iocs", "tlp", "'amber'"),
    ("iocs", "pap", "'amber'"),
    ("iocs", "visibility", "'mssp_only'"),
    ("case_links", "visibility", "'mssp_only'"),
    ("notes", "visibility", "'mssp_only'"),
    ("proposals", "rationale", "''"),
    ("proposals", "status", "'draft'"),
    ("proposals", "visibility", "'mssp_only'"),
    ("case_outbox", "status", "'pending'"),
)


def upgrade() -> None:
    # 1. audit_log RLS (idempotent).
    op.execute("ALTER TABLE audit_log ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE audit_log FORCE ROW LEVEL SECURITY")
    op.execute("DROP POLICY IF EXISTS audit_log_tenant_isolation ON audit_log")
    op.execute(
        """
        CREATE POLICY audit_log_tenant_isolation ON audit_log
            FOR ALL
            TO soctalk_app
            USING (
                tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid
            )
            WITH CHECK (
                tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid
            )
        """
    )

    # 2. execution_log is append-only for the app + mssp roles.
    op.execute(
        "REVOKE UPDATE, DELETE ON execution_log FROM soctalk_app, soctalk_mssp"
    )

    # 3. Un-double-quote string defaults on IR tables.
    for table, column, literal in _DEFAULT_REPAIRS:
        op.execute(
            f"ALTER TABLE {table} ALTER COLUMN {column} SET DEFAULT {literal}"
        )


def downgrade() -> None:
    # Forward-only. Reverting would reintroduce the bugs.
    pass
