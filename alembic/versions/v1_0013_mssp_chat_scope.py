"""mssp chat: scope column, nullable tenant_id, fleet RLS branch, indexer URL.

Revision ID: v1_0013_mssp_chat_scope
Revises: v1_0012_chat_tables
Create Date: 2026-05-28

Backs Phase 1 of the MSSP chat plan (``docs/mssp-chat-plan.md``):

* ``conversations.scope`` discriminates tenant-bound from fleet-scope chats.
* ``conversations.tenant_id`` and ``chat_messages.tenant_id`` become nullable
  to hold fleet rows (``scope='mssp_fleet'`` → ``tenant_id IS NULL``).
* RLS policies on both tables grow a second permitted branch: NULL-tenant
  rows are visible/writable only by MSSP-audience sessions with a blank
  ``app.current_tenant_id``. The tenant branch stays exactly as it was.
* ``integration_configs.wazuh_indexer_url`` gets added (nullable) so the
  per-tenant Wazuh resolver can target the Indexer Service explicitly
  (the Manager Service does not expose 9200).

Ordering matters: the cross-column CHECK on conversations is added LAST,
after both ``scope`` and the relaxed ``tenant_id`` exist, so the predicate
can reference both without a "column does not exist" failure.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op


revision = "v1_0013_mssp_chat_scope"
down_revision = "v1_0012_chat_tables"
branch_labels = None
depends_on = None


# ---------------------------------------------------------------------------
# RLS policy bodies. Two-branch USING/WITH CHECK:
#   1. Tenant row, GUC matches caller's pin.
#   2. Fleet row (tenant_id IS NULL), GUC blank, audience='mssp'.
# ---------------------------------------------------------------------------
_RLS_PREDICATE = """\
    (
        tenant_id IS NOT NULL
        AND tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid
    )
    OR
    (
        tenant_id IS NULL
        AND COALESCE(NULLIF(current_setting('app.current_tenant_id', true), ''), '') = ''
        AND current_setting('app.current_audience', true) = 'mssp'
    )
"""


def upgrade() -> None:
    # 1. conversations.scope — self-contained CHECK so the column is usable
    #    before the cross-column constraint lands.
    op.add_column(
        "conversations",
        sa.Column(
            "scope",
            sa.Text(),
            nullable=False,
            server_default=sa.text("'tenant'"),
        ),
    )
    op.create_check_constraint(
        "ck_conversations_scope_value",
        "conversations",
        "scope IN ('tenant','mssp_fleet')",
    )

    # 2. Relax tenant_id on both tables.
    op.alter_column("conversations", "tenant_id", nullable=True)
    op.alter_column("chat_messages", "tenant_id", nullable=True)

    # 3. Cross-column CHECK: tenant scope ⇒ tenant_id set; fleet scope ⇒
    #    tenant_id NULL AND investigation_id NULL.
    op.create_check_constraint(
        "ck_conversations_scope",
        "conversations",
        "(scope = 'tenant' AND tenant_id IS NOT NULL) "
        "OR (scope = 'mssp_fleet' AND tenant_id IS NULL "
        "    AND investigation_id IS NULL)",
    )

    # 4. Replace the existing RLS policies with the two-branch versions.
    #    The existing policies were strict-equality with IS DISTINCT FROM;
    #    they need explicit audience-gating on the NULL branch so a
    #    tenant-audience session with a (theoretically) blank GUC cannot
    #    peek at fleet rows.
    for table in ("conversations", "chat_messages"):
        op.execute(f'DROP POLICY IF EXISTS "{table}_tenant_isolation" ON "{table}"')
        op.execute(
            f"""
            CREATE POLICY {table}_tenant_isolation ON {table}
                FOR ALL
                TO soctalk_app
                USING (
                    {_RLS_PREDICATE}
                )
                WITH CHECK (
                    {_RLS_PREDICATE}
                )
            """
        )

    # 5. integration_configs.wazuh_indexer_url — separate Service from
    #    the Manager URL, populated by the provisioning controller and
    #    the Phase 5 backfill script. NULL → resolver falls back to
    #    service-name substitution on the manager URL.
    op.add_column(
        "integration_configs",
        sa.Column("wazuh_indexer_url", sa.String(length=500), nullable=True),
    )


def downgrade() -> None:
    # Reverse order.
    op.drop_column("integration_configs", "wazuh_indexer_url")

    # Restore the original single-branch RLS policy on both tables.
    for table in ("conversations", "chat_messages"):
        op.execute(f'DROP POLICY IF EXISTS "{table}_tenant_isolation" ON "{table}"')
        op.execute(
            f"""
            CREATE POLICY {table}_tenant_isolation ON {table}
                FOR ALL
                TO soctalk_app
                USING (
                    NOT (tenant_id IS DISTINCT FROM
                         NULLIF(current_setting('app.current_tenant_id', true), '')::uuid)
                )
                WITH CHECK (
                    NOT (tenant_id IS DISTINCT FROM
                         NULLIF(current_setting('app.current_tenant_id', true), '')::uuid)
                )
            """
        )

    # Drop the cross-column CHECK, then the scope CHECK, then the column.
    op.drop_constraint("ck_conversations_scope", "conversations", type_="check")

    # Before restoring NOT NULL, any fleet rows in flight must be
    # removed; we leave that to the operator (downgrade is best-effort).
    op.alter_column("chat_messages", "tenant_id", nullable=False)
    op.alter_column("conversations", "tenant_id", nullable=False)

    op.drop_constraint(
        "ck_conversations_scope_value", "conversations", type_="check"
    )
    op.drop_column("conversations", "scope")
