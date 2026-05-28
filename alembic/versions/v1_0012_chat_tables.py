"""chat: conversations + chat_messages with tenant RLS.

Revision ID: v1_0012_chat_tables
Revises: v1_0011_rename_case_to_investigation
Create Date: 2026-05-28

Adds the persistence backing the AI SOC analyst chat (see
``docs/chat-interface-plan.md``). Two tables:

* ``conversations`` — one row per chat thread. Holds the tenant binding,
  the optional investigation scope, the model the agent loop is pinned
  to, and the rolling cost totals enforced as the per-conversation cap.
* ``chat_messages`` — append-only message log. Role discriminates
  user / assistant / tool / system / action. The action role is the
  ``proposed_action`` shape — NOT a URL; the confirm endpoint derives
  the call from ``content.action`` + ``content.target`` server-side.

Both tables get the same ``tenant_isolation`` RLS policy shape as
``events`` — fail-closed when ``app.current_tenant_id`` is unset.
MSSP cross-tenant reads use the BYPASSRLS ``soctalk_mssp`` role; chat
writes follow the explicit MSSP-write tenant-id rule in the plan
(investigation_id present → inherit its tenant; absent → caller's
current_tenant pin).
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql


revision = "v1_0012_chat_tables"
down_revision = "v1_0011_rename_case_to_investigation"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "conversations",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column(
            "tenant_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("tenants.id"),
            nullable=False,
        ),
        sa.Column(
            "created_by_user_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id"),
            nullable=False,
        ),
        # ON DELETE SET NULL so closing an investigation doesn't
        # cascade-delete its chat history; the conversation becomes
        # global and the agent loses the case context on next turn.
        sa.Column(
            "investigation_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("investigations.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("title", sa.Text(), nullable=True),
        sa.Column("model_name", sa.Text(), nullable=False),
        sa.Column(
            "status",
            sa.Text(),
            nullable=False,
            server_default=sa.text("'active'"),
        ),
        # BIGINT, not INT — long ops conversations can plausibly
        # accumulate hundreds of millions of tokens (tool results
        # compound) and INT overflows at 2.1B.
        sa.Column(
            "total_tokens",
            sa.BigInteger(),
            nullable=False,
            server_default=sa.text("0"),
        ),
        sa.Column(
            "total_dollars",
            sa.Float(),
            nullable=False,
            server_default=sa.text("0.0"),
        ),
        sa.Column(
            "budget_dollars",
            sa.Float(),
            nullable=False,
            server_default=sa.text("1.0"),
        ),
        sa.Column(
            "created_at",
            sa.TIMESTAMP(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column(
            "last_message_at",
            sa.TIMESTAMP(timezone=True),
            nullable=True,
        ),
        sa.CheckConstraint(
            "status IN ('active','closed','budget_exhausted')",
            name="ck_conversations_status",
        ),
    )

    op.create_index(
        "ix_conversations_tenant_created",
        "conversations",
        ["tenant_id", sa.text("created_at DESC")],
    )
    op.create_index(
        "ix_conversations_investigation",
        "conversations",
        ["investigation_id"],
        postgresql_where=sa.text("investigation_id IS NOT NULL"),
    )

    op.create_table(
        "chat_messages",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column(
            "conversation_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("conversations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "tenant_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("tenants.id"),
            nullable=False,
        ),
        sa.Column("role", sa.Text(), nullable=False),
        sa.Column(
            "content",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
        ),
        sa.Column(
            "tokens_in",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("0"),
        ),
        sa.Column(
            "tokens_out",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("0"),
        ),
        sa.Column(
            "dollars",
            sa.Float(),
            nullable=False,
            server_default=sa.text("0.0"),
        ),
        sa.Column("model_name", sa.Text(), nullable=True),
        sa.Column(
            "created_at",
            sa.TIMESTAMP(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.CheckConstraint(
            "role IN ('user','assistant','tool','system','action')",
            name="ck_chat_messages_role",
        ),
        # Enforce required JSON shape per role so we don't end up with
        # a free-for-all union the agent loop or projector can't trust.
        sa.CheckConstraint(
            "(role = 'user'      AND content ? 'text') OR "
            "(role = 'assistant' AND content ? 'text') OR "
            "(role = 'system'    AND content ? 'text') OR "
            "(role = 'tool'      AND content ? 'name' AND content ? 'args' "
            "                                            AND content ? 'result') OR "
            "(role = 'action'    AND content ? 'action' AND content ? 'target')",
            name="ck_chat_messages_content_shape",
        ),
    )

    op.create_index(
        "ix_chat_messages_conv_created",
        "chat_messages",
        ["conversation_id", "created_at"],
    )
    op.create_index(
        "ix_chat_messages_tenant_created",
        "chat_messages",
        ["tenant_id", "created_at"],
    )

    # RLS — same shape as the events table policy.
    for table in ("conversations", "chat_messages"):
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY;")
        op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY;")
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
        # Read/insert/update/delete grants for the runtime role.
        op.execute(f"GRANT SELECT, INSERT, UPDATE, DELETE ON {table} TO soctalk_app;")


def downgrade() -> None:
    for table in ("chat_messages", "conversations"):
        op.execute(f'DROP POLICY IF EXISTS "{table}_tenant_isolation" ON "{table}"')
    op.drop_index("ix_chat_messages_tenant_created", table_name="chat_messages")
    op.drop_index("ix_chat_messages_conv_created", table_name="chat_messages")
    op.drop_table("chat_messages")
    op.drop_index("ix_conversations_investigation", table_name="conversations")
    op.drop_index("ix_conversations_tenant_created", table_name="conversations")
    op.drop_table("conversations")
