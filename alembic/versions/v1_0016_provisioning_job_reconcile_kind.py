"""Admit 'tenant.reconcile' into provisioning_jobs.kind.

Revision ID: v1_0016_provisioning_job_reconcile_kind
Revises: v1_0015_wazuh_indexer_credentials
Create Date: 2026-06-20

Context
-------
``tenant.reconcile`` is a new provisioning-job kind: re-render +
helm-upgrade an ACTIVE tenant's release without lifecycle transitions, so
chart-affecting LLM edits (provider/base_url/model) actually propagate.
``PATCH /api/mssp/tenants/{id}/llm`` enqueues it for active tenants —
``TenantController.provision`` early-returns on ``active`` and the
active→provisioning transition is illegal, so the old ``tenant.provision``
enqueue silently never re-rendered the release.

What changes at the DB level
----------------------------
Only the ``ck_provisioning_jobs_kind`` CHECK constraint (from v1_0005),
which enumerates the allowed kind values and would reject INSERTs of the
new kind. The partial unique index ``uq_provisioning_jobs_active`` is keyed
generically on ``(tenant_id, kind) WHERE status IN ('pending','in_flight')``
— it covers the new kind automatically and needs no change, preserving the
"at most one active job per (tenant, kind)" invariant for reconcile jobs.

Forward-only (same policy as v1_0005).
"""

from __future__ import annotations

from alembic import op

revision: str = "v1_0016_provisioning_job_reconcile_kind"
down_revision: str | None = "v1_0015_wazuh_indexer_credentials"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.execute(
        "ALTER TABLE provisioning_jobs "
        "DROP CONSTRAINT ck_provisioning_jobs_kind"
    )
    op.execute(
        "ALTER TABLE provisioning_jobs ADD CONSTRAINT ck_provisioning_jobs_kind "
        "CHECK (kind IN ('tenant.provision', 'tenant.decommission', "
        "'tenant.reconcile'))"
    )


def downgrade() -> None:
    # Forward-only.
    pass
