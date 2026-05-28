"""SQLModel tables for the AI SOC analyst chat.

Backs the schema laid down by ``v1_0012_chat_tables`` migration. Two
tables: ``conversations`` (thread metadata + rolling cost) and
``chat_messages`` (append-only log). See ``docs/chat-interface-plan.md``
for the design rationale, RLS rules, and content-shape contract per
role.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import BigInteger, Column, Index
from sqlalchemy.dialects.postgresql import JSONB, UUID as PGUUID
from sqlmodel import Field, SQLModel


class Conversation(SQLModel, table=True):
    """Chat thread between an analyst and the SocTalk AI agent.

    ``tenant_id`` is the data binding (used by RLS to gate reads and
    by audit trails to know which tenant owns the conversation).
    ``investigation_id`` is optional — when set, the agent loads case
    context into its system prompt at turn time and the dock UI mounts
    on the investigation detail page.
    """

    __tablename__ = "conversations"
    __table_args__ = (
        Index(
            "ix_conversations_tenant_created",
            "tenant_id",
            "created_at",
        ),
        Index(
            "ix_conversations_investigation",
            "investigation_id",
        ),
    )

    id: UUID = Field(default_factory=uuid4, primary_key=True)
    tenant_id: UUID = Field(sa_column=Column(PGUUID(as_uuid=True), nullable=False))
    created_by_user_id: UUID = Field(
        sa_column=Column(PGUUID(as_uuid=True), nullable=False)
    )
    investigation_id: UUID | None = Field(
        default=None,
        sa_column=Column(PGUUID(as_uuid=True), nullable=True),
    )
    title: str | None = Field(default=None)
    model_name: str = Field()
    # active | closed | budget_exhausted
    status: str = Field(default="active", max_length=32)
    # BIGINT (see migration comment).
    total_tokens: int = Field(default=0, sa_column=Column(BigInteger(), nullable=False))
    total_dollars: float = Field(default=0.0)
    budget_dollars: float = Field(default=1.0)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    last_message_at: datetime | None = Field(default=None)


class ChatMessage(SQLModel, table=True):
    """Append-only message log for a conversation.

    Role discriminates the ``content`` JSON shape — enforced by a DB
    CHECK constraint defined in the migration. Roles:

    * ``user`` / ``assistant`` / ``system`` — ``{"text": "..."}``
    * ``tool`` — ``{"name": "...", "args": {...}, "result": {...},
      "truncated": bool}``
    * ``action`` — the proposed-action shape; carries ``action`` verb
      + ``target.kind`` + ``target.id`` (NEVER a URL). After analyst
      confirmation the content is updated with
      ``confirmed_at`` + ``confirmed_by_user_id``.
    """

    __tablename__ = "chat_messages"
    __table_args__ = (
        Index(
            "ix_chat_messages_conv_created",
            "conversation_id",
            "created_at",
        ),
        Index(
            "ix_chat_messages_tenant_created",
            "tenant_id",
            "created_at",
        ),
    )

    id: UUID = Field(default_factory=uuid4, primary_key=True)
    conversation_id: UUID = Field(
        sa_column=Column(PGUUID(as_uuid=True), nullable=False)
    )
    tenant_id: UUID = Field(sa_column=Column(PGUUID(as_uuid=True), nullable=False))
    role: str = Field(max_length=16)
    content: dict[str, Any] = Field(
        default_factory=dict,
        sa_column=Column(JSONB, nullable=False),
    )
    tokens_in: int = Field(default=0)
    tokens_out: int = Field(default=0)
    dollars: float = Field(default=0.0)
    model_name: str | None = Field(default=None)
    created_at: datetime = Field(default_factory=datetime.utcnow)
