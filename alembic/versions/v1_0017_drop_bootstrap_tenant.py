"""Drop the internal 'Default (bootstrap)' tenant row.

Revision ID: v1_0017_drop_bootstrap_tenant
Revises: v1_0016_provisioning_job_reconcile_kind
Create Date: 2026-07-07

Context
-------
The MSSP control plane is an Organization, not a tenant. Early installs seeded
a 'Default (bootstrap)' Tenant row (v1_0001), later tagged ``profile='legacy'``
(v1_0005). It has no operational role: nothing branches on the 'default' slug,
provisioning/agent-jobs are tenant-FK driven, and the bootstrap admin user
carries no ``tenant_id``. It only clutters the MSSP Tenants list as a
permanently-degraded pseudo-customer.

This removes that internal tenant so the list shows only real customers.

Guarded: it deletes the row only when it has NO dependent rows across every FK
that references ``tenants(id)`` — so an install that (unusually) attached data
to the default tenant is left untouched rather than cascade-deleted. The
Organization row is unaffected; db-init only ever creates the Organization,
never this tenant, so it is not recreated.

Forward-only (same policy as v1_0005): downgrade does not recreate it.
"""

from __future__ import annotations

from alembic import op

revision: str = "v1_0017_drop_bootstrap_tenant"
down_revision: str | None = "v1_0016_provisioning_job_reconcile_kind"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.execute(
        """
        DO $$
        DECLARE
            t uuid;
            r record;
            n bigint;
            deps bigint := 0;
        BEGIN
            SELECT id INTO t FROM tenants
             WHERE slug = 'default'
               AND display_name = 'Default (bootstrap)'
               AND profile = 'legacy'
               AND deleted_at IS NULL;
            IF t IS NULL THEN
                RETURN;  -- already removed, or never seeded
            END IF;

            -- Count dependents across every FK referencing tenants(id).
            FOR r IN
                SELECT conrelid::regclass::text AS tbl, a.attname AS col
                FROM pg_constraint c
                JOIN pg_attribute a
                     ON a.attrelid = c.conrelid AND a.attnum = ANY(c.conkey)
                WHERE c.confrelid = 'tenants'::regclass AND c.contype = 'f'
            LOOP
                EXECUTE format('SELECT count(*) FROM %I WHERE %I = $1', r.tbl, r.col)
                    INTO n USING t;
                deps := deps + n;
                IF n > 0 THEN
                    RAISE NOTICE
                      'bootstrap tenant % has % row(s) in %.%; leaving it in place',
                      t, n, r.tbl, r.col;
                END IF;
            END LOOP;

            IF deps = 0 THEN
                DELETE FROM tenants WHERE id = t;
                RAISE NOTICE 'removed empty internal bootstrap tenant %', t;
            ELSE
                RAISE NOTICE
                  'bootstrap tenant % has dependents; not removing (Organization unaffected)', t;
            END IF;
        END $$;
        """
    )


def downgrade() -> None:
    # Forward-only: the internal bootstrap tenant is not recreated.
    pass
