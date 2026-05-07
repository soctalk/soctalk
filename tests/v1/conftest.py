"""Pytest fixtures for V1 multi-tenancy tests.

Provides:
- Two seeded tenants (A, B) with separate integration_configs, branding,
  and sample events / investigations scoped per tenant.
- A Postgres session per role (soctalk_app, soctalk_mssp) so tests can assert
  role-specific behavior.

these fixtures assume a Postgres instance reachable via the
``DATABASE_URL_ADMIN`` / ``DATABASE_URL_APP`` / ``DATABASE_URL_MSSP`` env
vars, with the V1 migration applied. Phase 0 dev harness (``scripts/dev-up.sh``)
brings up the required dependencies; tests using these fixtures are marked
``@pytest.mark.integration`` and skipped when ``SKIP_INTEGRATION=1``.
"""

from __future__ import annotations

import os
from collections.abc import AsyncIterator
from dataclasses import dataclass
from uuid import UUID, uuid4

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from soctalk.core.tenancy.models import (
    BrandingConfig,
    IntegrationConfig,
    Organization,
    Role,
    Tenant,
    TenantState,
    User,
    UserType,
)


SKIP_INTEGRATION = os.getenv("SKIP_INTEGRATION", "0") == "1"


# ---------------------------------------------------------------------------
# Engine / session factories per Postgres role
# ---------------------------------------------------------------------------


def _admin_url() -> str:
    return os.getenv(
        "DATABASE_URL_ADMIN",
        "postgresql+asyncpg://soctalk_admin:soctalk_admin@localhost:5432/soctalk",
    )


def _app_url() -> str:
    return os.getenv(
        "DATABASE_URL_APP",
        "postgresql+asyncpg://soctalk_app:soctalk_app@localhost:5432/soctalk",
    )


def _mssp_url() -> str:
    return os.getenv(
        "DATABASE_URL_MSSP",
        "postgresql+asyncpg://soctalk_mssp:soctalk_mssp@localhost:5432/soctalk",
    )


@pytest_asyncio.fixture
async def admin_engine():
    engine = create_async_engine(_admin_url(), echo=False, pool_pre_ping=True)
    yield engine
    await engine.dispose()


@pytest_asyncio.fixture
async def app_engine():
    engine = create_async_engine(_app_url(), echo=False, pool_pre_ping=True)
    yield engine
    await engine.dispose()


@pytest_asyncio.fixture
async def mssp_engine():
    engine = create_async_engine(_mssp_url(), echo=False, pool_pre_ping=True)
    yield engine
    await engine.dispose()


@pytest_asyncio.fixture
async def admin_session(admin_engine) -> AsyncIterator[AsyncSession]:
    factory = async_sessionmaker(admin_engine, expire_on_commit=False)
    async with factory() as session:
        yield session


@pytest_asyncio.fixture
async def app_session(app_engine) -> AsyncIterator[AsyncSession]:
    factory = async_sessionmaker(app_engine, expire_on_commit=False)
    async with factory() as session:
        yield session


@pytest_asyncio.fixture
async def mssp_session(mssp_engine) -> AsyncIterator[AsyncSession]:
    factory = async_sessionmaker(mssp_engine, expire_on_commit=False)
    async with factory() as session:
        yield session


# ---------------------------------------------------------------------------
# Seed data
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SeededTenant:
    org_id: UUID
    tenant_id: UUID
    slug: str
    display_name: str
    admin_user_id: UUID
    viewer_user_id: UUID


@pytest_asyncio.fixture
async def seed_two_tenants(
    admin_session: AsyncSession, mssp_session: AsyncSession
) -> tuple[SeededTenant, SeededTenant]:
    """Seed two fresh tenants and one user in each for isolation tests.

    The seed INSERTs use the ``mssp_session`` (``soctalk_mssp`` BYPASSRLS role)
    to sidestep FORCE ROW LEVEL SECURITY on tenant-scoped tables; a FORCE-RLS
    admin path would require setting ``app.current_tenant_id`` for every
    inserted tenant's rows, which is impractical for a cross-tenant fixture.
    ``admin_session`` is still used for the ``TRUNCATE CASCADE`` reset and is
    available to tests that need to verify admin RLS behaviour.
    """
    org_a_id, org_b_id = uuid4(), uuid4()
    tenant_a_id, tenant_b_id = uuid4(), uuid4()
    admin_a_id, viewer_a_id = uuid4(), uuid4()
    admin_b_id, viewer_b_id = uuid4(), uuid4()

    await _truncate_test_tables(admin_session)

    # Explicit flushes between groups. SQLAlchemy's dependency sorter orders
    # INSERTs by FK dependency WITHIN a single flush, but when multiple
    # tables are flushed together it can batch inserts via ``executemany``
    # that PG evaluates in the SQL order we hand in, which is model-add
    # order — not FK order. Flush each dependent layer before moving on.
    mssp_session.add_all([
        Organization(id=org_a_id, mssp_id=uuid4(), mssp_name="MSSP-A",
                     install_id=uuid4(), install_label="test"),
        Organization(id=org_b_id, mssp_id=uuid4(), mssp_name="MSSP-B",
                     install_id=uuid4(), install_label="test"),
    ])
    await mssp_session.flush()

    mssp_session.add_all([
        Tenant(id=tenant_a_id, slug="acme", display_name="Acme Corp",
               state=TenantState.ACTIVE.value, organization_id=org_a_id, config={}),
        Tenant(id=tenant_b_id, slug="beta", display_name="Beta Inc",
               state=TenantState.ACTIVE.value, organization_id=org_b_id, config={}),
    ])
    await mssp_session.flush()

    mssp_session.add_all([
        User(id=admin_a_id, email="admin-a@mssp-a.example",
             user_type=UserType.MSSP.value, role=Role.MSSP_ADMIN.value),
        User(id=viewer_a_id, email="viewer-a@acme.example",
             user_type=UserType.TENANT.value, role=Role.CUSTOMER_VIEWER.value,
             tenant_id=tenant_a_id),
        User(id=admin_b_id, email="admin-b@mssp-b.example",
             user_type=UserType.MSSP.value, role=Role.MSSP_ADMIN.value),
        User(id=viewer_b_id, email="viewer-b@beta.example",
             user_type=UserType.TENANT.value, role=Role.CUSTOMER_VIEWER.value,
             tenant_id=tenant_b_id),
    ])
    await mssp_session.flush()

    mssp_session.add_all([
        IntegrationConfig(tenant_id=tenant_a_id, wazuh_url="https://wazuh-a.acme"),
        IntegrationConfig(tenant_id=tenant_b_id, wazuh_url="https://wazuh-b.beta"),
        BrandingConfig(tenant_id=tenant_a_id, app_name="Acme SOC"),
        BrandingConfig(tenant_id=tenant_b_id, app_name="Beta SOC"),
    ])
    await mssp_session.commit()

    return (
        SeededTenant(org_a_id, tenant_a_id, "acme", "Acme Corp", admin_a_id, viewer_a_id),
        SeededTenant(org_b_id, tenant_b_id, "beta", "Beta Inc", admin_b_id, viewer_b_id),
    )


async def _truncate_test_tables(session: AsyncSession) -> None:
    """TRUNCATE all V1 tenant-scoped tables. Owner/admin role only."""
    from sqlalchemy import text

    tables = [
        # IR (v1_0003) — must TRUNCATE first because they reference
        # tenants / cases; CASCADE will pull bridge tables along.
        "execution_log",
        "case_outbox",
        "proposals",
        "case_links",
        "case_iocs",
        "case_assets",
        "case_events",
        "case_facts",
        "case_runs",
        "cases",
        "alerts",
        "iocs",
        "notes",
        "tenant_policies",
        # P1-1 internal auth
        "sessions",
        "password_credentials",
        # V1 multi-tenancy
        "tenant_lifecycle_events",
        "audit_log",
        "tenant_secrets",
        "branding_configs",
        "integration_configs",
        "users",
        "tenants",
        "organizations",
    ]
    await session.execute(text(f"TRUNCATE {', '.join(tables)} RESTART IDENTITY CASCADE;"))
    await session.commit()
