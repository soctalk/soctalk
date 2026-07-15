"""Partial index for the close-volume cap's rolling count (issue #46).

``count_recent_auto_closes`` runs on every would-be automatic close (ingest
memoized/rules paths and the worker close_fp completion):

    SELECT count(*) FROM investigations
    WHERE tenant_id = ? AND status = 'auto_closed_fp' AND closed_at > now() - window

No existing index covers (tenant_id, closed_at) for closed rows, so the count
would widen into a per-tenant scan exactly on the high-volume path the cap is
meant to protect.
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "v1_0031_auto_close_volume_index"
down_revision: str | None = "v1_0030_entity_keys_case_index"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_index(
        "ix_investigations_auto_closed_at",
        "investigations",
        ["tenant_id", "closed_at"],
        postgresql_where=sa.text("status = 'auto_closed_fp'"),
    )


def downgrade() -> None:
    op.drop_index(
        "ix_investigations_auto_closed_at", table_name="investigations"
    )
