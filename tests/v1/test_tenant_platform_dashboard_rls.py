"""The dashboard's ``platform_outdated`` flag under the real request role.

Every HTTP request gets an **app-role** session (``DBSessionMiddleware``),
and ``tenant_lifecycle_events`` is FORCE-RLS with per-tenant isolation: with
no ``app.current_tenant_id`` (an MSSP-scope request) the app role sees none
of its rows. The first cut of the flag read the latest ``helm_applied``
render on that session, saw nothing, and reported every tenant as outdated
forever, including one rolled seconds earlier. Unit tests had mocked the
query, so only a real Postgres with the real roles shows it.
"""

from __future__ import annotations

import os
from collections.abc import AsyncIterator
from datetime import datetime
from uuid import uuid4

import pytest
import pytest_asyncio
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from soctalk.core.tenancy.models import (
    Organization,
    Tenant,
    TenantLifecycleEvent,
    TenantState,
)

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        os.getenv("SKIP_INTEGRATION", "0") == "1",
        reason="SKIP_INTEGRATION set; needs Postgres with the V1 roles",
    ),
]


def _url(var: str, user: str) -> str:
    return os.getenv(var, f"postgresql+asyncpg://{user}:{user}@localhost:5444/soctalk")


@pytest_asyncio.fixture
async def sessionmakers() -> AsyncIterator[dict[str, async_sessionmaker[AsyncSession]]]:
    engines = {
        "admin": create_async_engine(_url("DATABASE_URL_ADMIN", "soctalk_admin")),
        "mssp": create_async_engine(_url("DATABASE_URL_MSSP", "soctalk_mssp")),
        "app": create_async_engine(_url("DATABASE_URL_APP", "soctalk_app")),
    }
    yield {k: async_sessionmaker(e, expire_on_commit=False) for k, e in engines.items()}
    for e in engines.values():
        await e.dispose()


@pytest_asyncio.fixture
async def rendered_tenant(sessionmakers) -> Tenant:
    async with sessionmakers["admin"]() as s:
        await s.execute(text(
            "TRUNCATE tenant_lifecycle_events, integration_configs, branding_configs, "
            "tenant_secrets, provisioning_jobs, tenants, organizations CASCADE"
        ))
        await s.commit()
    async with sessionmakers["mssp"]() as s:
        org = Organization(
            mssp_id=uuid4(), mssp_name="Dash RLS", slug="dash-rls",
            install_id=uuid4(), install_label="test",
        )
        s.add(org)
        await s.flush()
        tenant = Tenant(
            slug=f"dr{uuid4().hex[:6]}", display_name="Dash RLS",
            state=TenantState.ACTIVE.value, profile="provided", organization_id=org.id,
        )
        s.add(tenant)
        await s.flush()
        s.add(TenantLifecycleEvent(
            tenant_id=tenant.id, event_type="helm_applied",
            from_state="active", to_state="active", actor_id="test",
            details={"chart": "soctalk-tenant", "platform_fingerprint": "CURRENT",
                     "platform_started_at": "2026-01-01T00:00:00+00:00"},
            timestamp=datetime.utcnow(),
        ))
        await s.commit()
        return tenant


class _MsspRequest:
    """What the request stack hands an MSSP-scope dashboard call: an app-role
    session with audience=mssp and no tenant pinned."""

    def __init__(self, db: AsyncSession):
        class State:
            pass

        self.state = State()
        self.state.db = db
        self.state.user_identity = {
            "user_id": str(uuid4()), "email": "ops@example.test", "user_type": "mssp",
            "role": "mssp_admin", "tenant_id": None, "current_tenant": None,
        }


async def test_app_role_cannot_see_lifecycle_events_without_tenant_context(
    sessionmakers, rendered_tenant
):
    """The cause, pinned: the request role's view of the table is empty."""
    from soctalk.core.provisioning.platform import latest_tenant_renders

    async with sessionmakers["app"]() as s:
        await s.execute(text("SELECT set_config('app.current_audience', 'mssp', true)"))
        renders = await latest_tenant_renders(s, [rendered_tenant.id])
    assert renders == {rendered_tenant.id: None}


async def test_dashboard_reports_a_freshly_rendered_tenant_as_current(
    sessionmakers, rendered_tenant, monkeypatch
):
    from soctalk.core.api import mssp_dashboard as dash
    from soctalk.core.provisioning import platform as pf
    from soctalk.core.tenancy import db as tenancy_db

    monkeypatch.setattr(pf, "current_fingerprint", lambda: "CURRENT")
    # The module-global MSSP engine would bind to another test's event loop;
    # hand the code under test this test's MSSP sessionmaker instead.
    monkeypatch.setattr(tenancy_db, "get_mssp_sessionmaker", lambda: sessionmakers["mssp"])

    async with sessionmakers["app"]() as s:
        await s.execute(text("SELECT set_config('app.current_audience', 'mssp', true)"))
        resp = await dash.tenant_health(_MsspRequest(s))

    row = next(r for r in resp.items if r.slug == rendered_tenant.slug)
    assert row.platform_outdated is False


async def test_dashboard_still_flags_a_tenant_on_another_platform(
    sessionmakers, rendered_tenant, monkeypatch
):
    from soctalk.core.api import mssp_dashboard as dash
    from soctalk.core.provisioning import platform as pf
    from soctalk.core.tenancy import db as tenancy_db

    monkeypatch.setattr(pf, "current_fingerprint", lambda: "UPGRADED")
    monkeypatch.setattr(tenancy_db, "get_mssp_sessionmaker", lambda: sessionmakers["mssp"])

    async with sessionmakers["app"]() as s:
        await s.execute(text("SELECT set_config('app.current_audience', 'mssp', true)"))
        resp = await dash.tenant_health(_MsspRequest(s))

    row = next(r for r in resp.items if r.slug == rendered_tenant.slug)
    assert row.platform_outdated is True


async def test_dashboard_does_not_flag_an_agent_managed_tenant(
    sessionmakers, rendered_tenant, monkeypatch
):
    """An L2 tenant is rendered on its own cluster by the agent; the MSSP has
    no local render to compare, so the flag is unknown (None), not outdated."""
    from soctalk.core.agents.models import TenantInstallation
    from soctalk.core.api import mssp_dashboard as dash
    from soctalk.core.provisioning import platform as pf
    from soctalk.core.tenancy import db as tenancy_db

    async with sessionmakers["mssp"]() as s:
        s.add(TenantInstallation(
            tenant_id=rendered_tenant.id, desired_chart_ref="oci://x/soctalk-tenant",
            desired_chart_version="0.2.1", state="active",
        ))
        await s.commit()
    monkeypatch.setattr(pf, "current_fingerprint", lambda: "UPGRADED")
    monkeypatch.setattr(tenancy_db, "get_mssp_sessionmaker", lambda: sessionmakers["mssp"])

    async with sessionmakers["app"]() as s:
        await s.execute(text("SELECT set_config('app.current_audience', 'mssp', true)"))
        resp = await dash.tenant_health(_MsspRequest(s))
    row = next(r for r in resp.items if r.slug == rendered_tenant.slug)
    assert row.platform_outdated is None
