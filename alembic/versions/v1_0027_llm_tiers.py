"""Per-tier LLM backends for hybrid tenants (issue #12).

Adds ``integration_configs.llm_tiers`` — an optional JSONB map of per-tier
LLM backends (``{"fast": {...}, "reasoning": {...}}``) so a provisioned tenant
can run a self-hosted fast/router tier alongside a frontier reasoning tier
(the deployment half of #4). NULL = single-provider (existing behaviour),
so this is a no-op for every existing tenant and fully reversible.

Revision ID: v1_0027_llm_tiers
Revises: v1_0026_correlation_suggestions
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "v1_0027_llm_tiers"
down_revision: str | None = "v1_0026_correlation_suggestions"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "integration_configs",
        sa.Column("llm_tiers", postgresql.JSONB(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("integration_configs", "llm_tiers")
