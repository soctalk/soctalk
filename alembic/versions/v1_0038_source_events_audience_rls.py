"""alert_source_events: MSSP-audience reads + investigation index (issue #71).

``alert_source_events`` (v1_0018) shipped with the pre-v1_0011 strict
tenant-isolation policy: rows visible only when ``app.current_tenant_id``
matches. Every sibling table has carried the v1_0011 convention since —
an UNPINNED session with ``app.current_audience = 'mssp'`` reads
fleet-wide. Surfaced by the MITRE contextualization endpoints: an
unpinned MSSP session listing an investigation's alerts got the alert
rows (audience-aware ``alerts`` policy) but silently empty ``mitre``
unions, because the source-event join was RLS-filtered to nothing.

Deliberately NARROWER than v1_0011's template on the write side: the
audience clause is granted for SELECT only. Source events are the
evidence/idempotency record — writes stay pinned-tenant-only (the
adapter ingest path always runs under ``tenant_context``), so an
unpinned MSSP app-role session cannot insert/update/delete evidence
across tenants (codex review finding).

Also adds the ``alerts(investigation_id, first_event_at)`` index the
per-investigation alert listing walks.

Revision ID: v1_0038_source_events_audience_rls
Revises: v1_0037_authored_response_playbooks
"""

from __future__ import annotations

from alembic import op

revision = "v1_0038_source_events_audience_rls"
down_revision: str | None = "v1_0037_authored_response_playbooks"
branch_labels = None
depends_on = None

_TABLE = "alert_source_events"

_STRICT_MATCH = """
            NOT (tenant_id IS DISTINCT FROM
                 NULLIF(current_setting('app.current_tenant_id', true), '')::uuid)
"""

_AUDIENCE_OR_MATCH = f"""
            (
                COALESCE(NULLIF(current_setting('app.current_tenant_id', true), ''), '') = ''
                AND current_setting('app.current_audience', true) = 'mssp'
            )
            OR {_STRICT_MATCH}
"""

_POLICIES = [
    f"""
    CREATE POLICY {_TABLE}_read ON {_TABLE}
        FOR SELECT TO soctalk_app
        USING ({_AUDIENCE_OR_MATCH})
    """,
    f"""
    CREATE POLICY {_TABLE}_insert ON {_TABLE}
        FOR INSERT TO soctalk_app
        WITH CHECK ({_STRICT_MATCH})
    """,
    f"""
    CREATE POLICY {_TABLE}_update ON {_TABLE}
        FOR UPDATE TO soctalk_app
        USING ({_STRICT_MATCH})
        WITH CHECK ({_STRICT_MATCH})
    """,
    f"""
    CREATE POLICY {_TABLE}_delete ON {_TABLE}
        FOR DELETE TO soctalk_app
        USING ({_STRICT_MATCH})
    """,
]

# v1_0018's original single policy, for downgrade.
_ORIGINAL = f"""
    CREATE POLICY {_TABLE}_tenant_isolation ON {_TABLE}
        FOR ALL TO soctalk_app
        USING ({_STRICT_MATCH})
        WITH CHECK ({_STRICT_MATCH})
"""

_NEW_POLICY_NAMES = [f"{_TABLE}_{kind}" for kind in ("read", "insert", "update", "delete")]


def upgrade() -> None:
    op.execute(f'DROP POLICY IF EXISTS "{_TABLE}_tenant_isolation" ON "{_TABLE}"')
    for sql in _POLICIES:
        op.execute(sql)
    op.create_index(
        "ix_alerts_investigation",
        "alerts",
        ["investigation_id", "first_event_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_alerts_investigation", table_name="alerts")
    for name in _NEW_POLICY_NAMES:
        op.execute(f'DROP POLICY IF EXISTS "{name}" ON "{_TABLE}"')
    op.execute(_ORIGINAL)
