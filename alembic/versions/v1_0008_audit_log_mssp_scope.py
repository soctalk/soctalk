"""audit_log RLS policy: permit MSSP-scope writes (tenant_id IS NULL).

Revision ID: v1_0008_audit_log_mssp_scope
Revises: v1_0007_integration_llm_api_key
Create Date: 2026-04-29

Context
-------
v1_0004 restored the ``audit_log_tenant_isolation`` policy with
``USING/WITH CHECK (tenant_id = current_setting('app.current_tenant_id'))``.
That works for tenant-scoped writes, but breaks MSSP-side actions whose
audit rows legitimately carry ``tenant_id IS NULL`` — e.g.
``auth.login.success`` for an MSSP admin, tenant-onboard events, install
upgrades. Under the strict policy ``NULL = NULL`` evaluates to NULL,
fails the WITH CHECK, and the soctalk_app role can never persist those
rows.

Fix: widen the predicate so MSSP-scope rows (``tenant_id IS NULL``) are
allowed *only when* the current session has no tenant context set —
preserving tenant isolation for tenant-scoped sessions while letting
MSSP-side handlers write null-tenant audit lines.
"""

from __future__ import annotations

from alembic import op


revision = "v1_0008_audit_log_mssp_scope"
down_revision = "v1_0007_integration_llm_api_key"
branch_labels = None
depends_on = None


_NEW_PREDICATE = """
(
    tenant_id IS NULL
    AND NULLIF(current_setting('app.current_tenant_id', true), '') IS NULL
) OR (
    tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid
)
"""


def upgrade() -> None:
    op.execute("DROP POLICY IF EXISTS audit_log_tenant_isolation ON audit_log")
    op.execute(
        f"""
        CREATE POLICY audit_log_tenant_isolation ON audit_log
            FOR ALL
            TO soctalk_app
            USING ({_NEW_PREDICATE})
            WITH CHECK ({_NEW_PREDICATE})
        """
    )


def downgrade() -> None:
    op.execute("DROP POLICY IF EXISTS audit_log_tenant_isolation ON audit_log")
    op.execute(
        """
        CREATE POLICY audit_log_tenant_isolation ON audit_log
            FOR ALL
            TO soctalk_app
            USING (
                tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid
            )
            WITH CHECK (
                tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid
            )
        """
    )
