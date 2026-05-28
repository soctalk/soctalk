-- Idempotent bootstrap of the three SocTalk Postgres roles for V1 RLS tests.
--
-- Mirrors the CI bootstrap in .github/workflows/v1-ci.yml so local
-- ``just integration-up`` and the GitHub Action share role attributes.
--
-- soctalk_admin   DDL owner; runs migrations. NOSUPERUSER NOBYPASSRLS so
--                 the role is RLS-subject under FORCE ROW LEVEL SECURITY
--                 (postgres-rls.md §3). CREATEROLE lets the v1_0001
--                 migration's ``CREATE ROLE IF NOT EXISTS`` blocks no-op
--                 cleanly when called as soctalk_admin.
-- soctalk_app     Runtime app role. RLS-subject; never used for DDL.
-- soctalk_mssp    Cross-tenant elevated role. BYPASSRLS, used only via
--                 ``system_context()`` from designated code paths.
--
-- Re-runnable: each role is created only if missing. Attributes on a
-- pre-existing role are NOT re-applied; rotate manually if needed.

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'soctalk_admin') THEN
        CREATE ROLE soctalk_admin LOGIN CREATEROLE PASSWORD 'soctalk_admin';
    END IF;
END
$$;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'soctalk_app') THEN
        CREATE ROLE soctalk_app LOGIN PASSWORD 'soctalk_app';
    END IF;
END
$$;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'soctalk_mssp') THEN
        CREATE ROLE soctalk_mssp LOGIN BYPASSRLS PASSWORD 'soctalk_mssp';
    END IF;
END
$$;

GRANT ALL ON DATABASE soctalk TO soctalk_admin;
GRANT ALL ON SCHEMA public TO soctalk_admin;
