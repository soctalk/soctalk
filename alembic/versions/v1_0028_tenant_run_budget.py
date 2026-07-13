"""Per-tenant run budget caps (issue #5 follow-up).

Adds ``integration_configs.llm_dollar_budget_per_run`` and
``llm_token_budget_per_run`` — optional per-tenant overrides for the case-run
LLM spend caps enforced in ``graph/budget.py`` (``over_budget`` → supervisor
CLOSE). NULL = use the worker default (``SOCTALK_CASE_RUN_*_BUDGET`` env or the
built-in $5 / 15k). Rendered into the runs-worker env only when set, so this is
a no-op for every existing tenant and fully reversible.

Revision ID: v1_0028_tenant_run_budget
Revises: v1_0027_llm_tiers
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "v1_0028_tenant_run_budget"
down_revision: str | None = "v1_0027_llm_tiers"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "integration_configs",
        sa.Column("llm_dollar_budget_per_run", sa.Float(), nullable=True),
    )
    op.add_column(
        "integration_configs",
        sa.Column("llm_token_budget_per_run", sa.Integer(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("integration_configs", "llm_token_budget_per_run")
    op.drop_column("integration_configs", "llm_dollar_budget_per_run")
