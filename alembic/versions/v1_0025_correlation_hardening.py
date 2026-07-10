"""Correlation hardening from adversarial review (#25/#24/#31 follow-up).

- investigations.has_new_evidence: the follow-up-run flag (review #2). Set
  when an alert attaches to an investigation with a live run; consumed by
  complete_run to start a fresh run so mid-run recurrence isn't lost.
- topology_edges: unique edge identity + index so upsert can upgrade
  potential->observed instead of appending (review #5).
- Missing indexes for entity_history / mitre_coverage (review #7).

FKs on the graph/label tables (review #6) are intentionally NOT added:
entity_relationships references the composite-PK ``entities`` and is
append-only observation data; a periodic reaper (retention) handles
orphans. Documented rather than silently skipped.

Revision ID: v1_0025_correlation_hardening
Revises: v1_0024_campaign_topology
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "v1_0025_correlation_hardening"
down_revision: str | None = "v1_0024_campaign_topology"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "investigations",
        sa.Column("has_new_evidence", sa.Boolean(), nullable=False,
                  server_default=sa.text("false")),
    )

    # Topology: one live edge per (tenant, src, dst, port). Enables the
    # ON CONFLICT upsert that upgrades potential -> observed.
    op.execute(
        """
        UPDATE topology_edges t SET superseded_at = now()
        WHERE superseded_at IS NULL AND EXISTS (
            SELECT 1 FROM topology_edges o
            WHERE o.tenant_id = t.tenant_id AND o.src_host = t.src_host
              AND o.dst_host = t.dst_host
              AND COALESCE(o.port, -1) = COALESCE(t.port, -1)
              AND o.superseded_at IS NULL AND o.id <> t.id AND o.last_seen > t.last_seen
        )
        """
    )
    op.create_index(
        "uq_topology_live_edge", "topology_edges",
        ["tenant_id", "src_host", "dst_host", sa.text("COALESCE(port, -1)")],
        unique=True, postgresql_where=sa.text("superseded_at IS NULL"),
    )

    # entity_history: dst + occurred_at ordering.
    op.create_index(
        "ix_rel_dst_time", "entity_relationships",
        ["tenant_id", "dst_id", "verb", sa.text("occurred_at DESC")],
    )
    # mitre_coverage grouping.
    op.create_index(
        "ix_rel_verb_dst", "entity_relationships",
        ["tenant_id", "verb", "dst_id"],
    )


def downgrade() -> None:
    op.drop_index("ix_rel_verb_dst", table_name="entity_relationships")
    op.drop_index("ix_rel_dst_time", table_name="entity_relationships")
    op.drop_index("uq_topology_live_edge", table_name="topology_edges")
    op.drop_column("investigations", "has_new_evidence")
