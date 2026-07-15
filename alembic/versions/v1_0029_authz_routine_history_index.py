"""Indexes for the SIEM-routine authorization history query (epic M2 shadow mode).

The shadow scorer (`core/ir/authz_shadow.score_alert_shadow`) runs one COUNT per candidate
alert on the ingest path:

    ... FROM alert_source_events
    WHERE tenant_id=? AND source=? AND decoder=? AND template_hash=?
      AND template_version IS NOT DISTINCT FROM ?
      AND occurred_at >= ? AND occurred_at < ?
      AND entities @> ?::jsonb  (one per discriminating entity on the alert)

The existing `(tenant_id, template_hash)` btree doesn't cover the source/decoder/time
predicate, and there was no GIN index on `entities` for the containment match. This adds:

- a composite btree over the scalar predicate columns (+ occurred_at for the range/DISTINCT
  date scan), so the candidate rows are found without a wide scan;
- a GIN index on `entities` so the `@>` containment filter is index-assisted.
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "v1_0029_authz_routine_history_index"
down_revision: str | None = "v1_0028_tenant_run_budget"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_index(
        "ix_source_events_routine_history",
        "alert_source_events",
        ["tenant_id", "source", "decoder", "template_hash", "occurred_at"],
    )
    op.create_index(
        "ix_source_events_entities_gin",
        "alert_source_events",
        ["entities"],
        postgresql_using="gin",
    )


def downgrade() -> None:
    op.drop_index("ix_source_events_entities_gin", table_name="alert_source_events")
    op.drop_index("ix_source_events_routine_history", table_name="alert_source_events")


# keep sa import referenced for autogenerate parity with sibling migrations
_ = sa
