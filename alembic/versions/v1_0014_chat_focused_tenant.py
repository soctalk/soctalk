"""chat: per-conversation focused tenant (fleet-scope soft binding).

Revision ID: v1_0014_chat_focused_tenant
Revises: v1_0013_mssp_chat_scope
Create Date: 2026-05-29

Adds ``conversations.focused_tenant_id`` — a per-conversation soft pin
for fleet-scope chats. Distinct from ``tenant_id`` (which is the hard
data binding for tenant-scope rows): focus is a *preference* the agent
latches onto so the user can say "let's work on lab tenant" mid-chat
without re-specifying the slug on every tool call.

* NULL when no focus set (the original fleet behaviour: model must pass
  ``tenant_slug`` explicitly on each tenant-targeted tool).
* References ``tenants(id)`` with ``ON DELETE SET NULL`` so dropping a
  tenant doesn't orphan or block fleet conversations.
* The dispatcher (``soctalk.chat.agent._resolve_tool_target_tenant``)
  reads this when a fleet-scope tool call omits ``tenant_slug`` and
  defaults to it; explicit ``tenant_slug`` still overrides.

The agent tool ``set_fleet_focus(slug_or_name)`` writes this column.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql


revision = "v1_0014_chat_focused_tenant"
down_revision = "v1_0013_mssp_chat_scope"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "conversations",
        sa.Column(
            "focused_tenant_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("tenants.id", ondelete="SET NULL"),
            nullable=True,
        ),
    )
    op.create_index(
        "ix_conversations_focused_tenant",
        "conversations",
        ["focused_tenant_id"],
        postgresql_where=sa.text("focused_tenant_id IS NOT NULL"),
    )


def downgrade() -> None:
    op.drop_index(
        "ix_conversations_focused_tenant", table_name="conversations"
    )
    op.drop_column("conversations", "focused_tenant_id")
