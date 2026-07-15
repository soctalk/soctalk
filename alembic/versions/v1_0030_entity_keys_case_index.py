"""Index for the close-floor sibling lookup (issue #43).

``find_other_active_investigation_sharing_keys`` (the server-side active-incident
veto in ``complete_run``) starts its self-join from the closing investigation's own
keys:

    ... FROM alert_entity_keys mine ... WHERE mine.tenant_id=? AND mine.investigation_id=?

The existing indexes cover ``(tenant_id, key_type, key_value, expires_at)`` (the
"other" side) and ``(tenant_id, alert_id)``, but nothing serves the
investigation-scoped entry point, so the veto would widen into a per-tenant scan on
every ``close_fp`` completion.
"""

from __future__ import annotations

from alembic import op

revision = "v1_0030_entity_keys_case_index"
down_revision: str | None = "v1_0029_authz_routine_history_index"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_index(
        "ix_entity_keys_investigation",
        "alert_entity_keys",
        ["tenant_id", "investigation_id"],
    )


def downgrade() -> None:
    op.drop_index("ix_entity_keys_investigation", table_name="alert_entity_keys")
