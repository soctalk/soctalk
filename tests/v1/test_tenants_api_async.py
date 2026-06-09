"""Assertions that the legacy POST /api/mssp/tenants no longer
provisions inline, and that ``:decommission`` is async.

Both contracts are the review-closing invariants: a caller that hits
either endpoint must not trigger helm from inside the request handler.
The worker owns every data-plane mutation now.
"""

from __future__ import annotations

import os
from collections.abc import AsyncIterator
from uuid import uuid4

import pytest
import pytest_asyncio
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from soctalk.core.tenancy.models import (
    IntegrationConfig,
    Organization,
    ProvisioningJob,
    Tenant,
    TenantState,
)

SKIP_INTEGRATION = os.getenv("SKIP_INTEGRATION", "0") == "1"

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        SKIP_INTEGRATION,
        reason="SKIP_INTEGRATION set; tenants-API async tests need Postgres",
    ),
]


def _mssp_url() -> str:
    return os.getenv(
        "DATABASE_URL_MSSP",
        "postgresql+asyncpg://soctalk_mssp:soctalk_mssp@localhost:5444/soctalk",
    )


def _admin_url() -> str:
    return os.getenv(
        "DATABASE_URL_ADMIN",
        "postgresql+asyncpg://soctalk_admin:soctalk_admin@localhost:5444/soctalk",
    )


@pytest_asyncio.fixture
async def admin_session() -> AsyncIterator[AsyncSession]:
    engine = create_async_engine(_admin_url(), echo=False, pool_pre_ping=True)
    sm = async_sessionmaker(engine, expire_on_commit=False)
    async with sm() as s:
        yield s
    await engine.dispose()


@pytest_asyncio.fixture
async def mssp_session() -> AsyncIterator[AsyncSession]:
    engine = create_async_engine(_mssp_url(), echo=False, pool_pre_ping=True)
    sm = async_sessionmaker(engine, expire_on_commit=False)
    async with sm() as s:
        yield s
    await engine.dispose()


@pytest_asyncio.fixture
async def seeded_org(
    mssp_session: AsyncSession, admin_session: AsyncSession
) -> Organization:
    await admin_session.execute(
        text(
            "TRUNCATE tenant_lifecycle_events, integration_configs, "
            "branding_configs, tenant_secrets, provisioning_jobs, "
            "tenants, organizations CASCADE"
        )
    )
    await admin_session.commit()
    org = Organization(
        mssp_id=uuid4(), mssp_name="Legacy-API Test", slug="legacy-api-test",
        install_id=uuid4(), install_label="test",
    )
    mssp_session.add(org)
    await mssp_session.commit()
    return org


# ---------------------------------------------------------------------------
# Call the handler function directly so we don't need the full FastAPI
# app stack (auth middleware, DB middleware, etc.). The guarantees we
# want to prove are about what the handler writes to the DB and what it
# does NOT call — not HTTP plumbing.
# ---------------------------------------------------------------------------


async def test_legacy_create_is_identity_only_no_provisioning(
    mssp_session: AsyncSession, seeded_org: Organization, monkeypatch
):
    """Review gap #4: POST /api/mssp/tenants must not provision inline."""

    from soctalk.core.api.tenants import TenantCreate, create_tenant
    from soctalk.core.provisioning import controller as ctrl_mod

    # Poison the controller so any inline provisioning attempt is obvious.
    sentinel = {"called": False}

    async def forbidden(*_a, **_kw):
        sentinel["called"] = True
        raise AssertionError(
            "create_tenant must not call TenantController.provision"
        )

    monkeypatch.setattr(ctrl_mod.TenantController, "provision", forbidden)

    class FakeRequest:
        class State:
            user_identity = {"user_id": "test-user"}
            db = mssp_session
        state = State()

    payload = TenantCreate(
        slug=f"id{uuid4().hex[:8]}",
        display_name="Identity Only",
    )

    result = await create_tenant(payload, FakeRequest())
    assert sentinel["called"] is False
    assert result.state == TenantState.PENDING.value
    assert result.profile in (None, "legacy", "poc")

    # No provisioning job should have been enqueued on this path.
    jobs = (
        await mssp_session.execute(
            select(ProvisioningJob).where(ProvisioningJob.tenant_id == result.id)
        )
    ).scalars().all()
    assert jobs == []


async def test_decommission_enqueues_job_and_returns_immediately(
    mssp_session: AsyncSession, seeded_org: Organization, monkeypatch
):
    """Review gap #4: :decommission must not call helm from the handler."""

    from soctalk.core.api.tenants import decommission_tenant
    from soctalk.core.provisioning import controller as ctrl_mod

    sentinel = {"called": False}

    async def forbidden(*_a, **_kw):
        sentinel["called"] = True
        raise AssertionError(
            "decommission_tenant must not call TenantController.decommission"
        )

    monkeypatch.setattr(ctrl_mod.TenantController, "decommission", forbidden)

    tenant = Tenant(
        slug=f"dc{uuid4().hex[:8]}",
        display_name="Decomm target",
        state=TenantState.ACTIVE.value,
        profile="poc",
        organization_id=seeded_org.id,
    )
    mssp_session.add(tenant)
    await mssp_session.commit()
    await mssp_session.refresh(tenant)

    class FakeRequest:
        class State:
            user_identity = {"user_id": "test-user"}
            db = mssp_session
        state = State()

    result = await decommission_tenant(tenant.id, FakeRequest(), force=False)
    assert sentinel["called"] is False
    assert result.state == TenantState.DECOMMISSIONING.value

    jobs = (
        await mssp_session.execute(
            select(ProvisioningJob)
            .where(ProvisioningJob.tenant_id == tenant.id)
            .where(ProvisioningJob.kind == "tenant.decommission")
        )
    ).scalars().all()
    assert len(jobs) == 1
    assert jobs[0].status == "pending"


async def test_decommission_is_idempotent_under_double_call(
    mssp_session: AsyncSession, seeded_org: Organization, monkeypatch
):
    """Two :decommission calls on the same tenant enqueue at most one
    active job (partial unique index would otherwise throw)."""

    from soctalk.core.api.tenants import decommission_tenant
    from soctalk.core.provisioning import controller as ctrl_mod

    async def noop(*_a, **_kw):  # let the call through, but do nothing
        raise AssertionError("unreachable")

    monkeypatch.setattr(ctrl_mod.TenantController, "decommission", noop)

    tenant = Tenant(
        slug=f"dd{uuid4().hex[:8]}",
        display_name="Double Decomm",
        state=TenantState.ACTIVE.value,
        profile="poc",
        organization_id=seeded_org.id,
    )
    mssp_session.add(tenant)
    await mssp_session.commit()
    await mssp_session.refresh(tenant)

    class FakeRequest:
        class State:
            user_identity = {"user_id": "test-user"}
            db = mssp_session
        state = State()

    await decommission_tenant(tenant.id, FakeRequest(), force=False)
    await decommission_tenant(tenant.id, FakeRequest(), force=False)

    jobs = (
        await mssp_session.execute(
            select(ProvisioningJob)
            .where(ProvisioningJob.tenant_id == tenant.id)
            .where(ProvisioningJob.kind == "tenant.decommission")
        )
    ).scalars().all()
    assert len(jobs) == 1


async def test_provided_profile_persists_external_wazuh_fields(
    mssp_session: AsyncSession, seeded_org: Organization
):
    """The 'provided' deployment profile lets a tenant point at an
    external Wazuh deployment. The five new IntegrationConfig.wazuh_*
    credential / endpoint columns must round-trip via Postgres so the
    renderer (next feature) can read them back when building the
    adapter values.
    """
    tenant = Tenant(
        slug=f"pv{uuid4().hex[:8]}",
        display_name="Provided-SIEM Tenant",
        state=TenantState.PENDING.value,
        profile="provided",
        organization_id=seeded_org.id,
    )
    mssp_session.add(tenant)
    await mssp_session.flush()

    integration = IntegrationConfig(
        tenant_id=tenant.id,
        wazuh_enabled=True,
        wazuh_username="soctalk-adapter",
        wazuh_password_plain="s3cret-pw-" + uuid4().hex,
        wazuh_api_token_plain="tok-" + uuid4().hex,
        wazuh_indexer_url="https://indexer.example.com:9200",
        wazuh_api_url="https://wazuh.example.com:55000",
        wazuh_indexer_username="indexer-ro",
        wazuh_indexer_password_plain="idx-pw-" + uuid4().hex,
    )
    mssp_session.add(integration)
    await mssp_session.commit()

    # Drop ORM cache so we hit the DB on the next read.
    mssp_session.expunge_all()

    read_back = (
        await mssp_session.execute(
            select(IntegrationConfig).where(
                IntegrationConfig.tenant_id == tenant.id
            )
        )
    ).scalar_one()

    assert read_back.wazuh_username == integration.wazuh_username
    assert read_back.wazuh_password_plain == integration.wazuh_password_plain
    assert read_back.wazuh_api_token_plain == integration.wazuh_api_token_plain
    assert read_back.wazuh_indexer_url == integration.wazuh_indexer_url
    assert read_back.wazuh_api_url == integration.wazuh_api_url
    assert read_back.wazuh_indexer_username == integration.wazuh_indexer_username
    assert (
        read_back.wazuh_indexer_password_plain
        == integration.wazuh_indexer_password_plain
    )

    # Tenant.profile also round-trips with the new enum value.
    tenant_read = (
        await mssp_session.execute(select(Tenant).where(Tenant.id == tenant.id))
    ).scalar_one()
    assert tenant_read.profile == "provided"


async def test_onboard_provided_persists_external_wazuh_fields(
    mssp_session: AsyncSession, seeded_org: Organization
):
    """The onboarding wizard payload carries external Wazuh connection
    material for the 'provided' profile inside a nested ``external_siem``
    block. ``onboard_tenant`` must write the *full* credential set onto the
    tenant's IntegrationConfig (passwords/token → *_plain columns) so the
    adapter and chat resolver can later reach the tenant-supplied SIEM.

    Exercises the complete payload → column mapping, including api_token and
    verify_ssl.
    """
    from soctalk.core.api.tenants import (
        ExternalSiemOnboard,
        TenantOnboard,
        onboard_tenant,
    )

    class FakeRequest:
        class State:
            user_identity = {"user_id": "test-user"}
            db = mssp_session
        state = State()

    pw = "byo-pw-" + uuid4().hex
    tok = "byo-tok-" + uuid4().hex
    ipw = "byo-ipw-" + uuid4().hex
    payload = TenantOnboard(
        slug=f"pv{uuid4().hex[:8]}",
        display_name="BYO Wazuh Tenant",
        profile="provided",
        external_siem=ExternalSiemOnboard(
            indexer_url="https://indexer.example.com:9200",
            indexer_username="indexer-ro",
            indexer_password=ipw,
            api_url="https://wazuh.example.com:55000",
            api_username="soctalk-adapter",
            api_password=pw,
            api_token=tok,
            verify_ssl=False,
        ),
    )

    result = await onboard_tenant(payload, FakeRequest())
    assert result.profile == "provided"

    integration = (
        await mssp_session.execute(
            select(IntegrationConfig).where(
                IntegrationConfig.tenant_id == result.id
            )
        )
    ).scalar_one()
    # api side
    assert integration.wazuh_api_url == "https://wazuh.example.com:55000"
    assert integration.wazuh_username == "soctalk-adapter"
    assert integration.wazuh_password_plain == pw
    assert integration.wazuh_api_token_plain == tok
    # indexer side
    assert integration.wazuh_indexer_url == "https://indexer.example.com:9200"
    assert integration.wazuh_indexer_username == "indexer-ro"
    assert integration.wazuh_indexer_password_plain == ipw
    # flags
    assert integration.wazuh_verify_ssl is False


async def test_onboard_non_provided_leaves_external_wazuh_null(
    mssp_session: AsyncSession, seeded_org: Organization
):
    """For poc/persistent the wizard must ignore any ``external_siem`` block —
    those columns stay NULL (and verify_ssl keeps its default) so the
    controller fills in-cluster URLs. Guards against a regression where a
    smuggled external_siem leaks onto a non-provided tenant.
    """
    from soctalk.core.api.tenants import (
        ExternalSiemOnboard,
        TenantOnboard,
        onboard_tenant,
    )

    class FakeRequest:
        class State:
            user_identity = {"user_id": "test-user"}
            db = mssp_session
        state = State()

    # Even if a client smuggles a full external_siem on a poc onboard, drop it.
    payload = TenantOnboard(
        slug=f"pc{uuid4().hex[:8]}",
        display_name="PoC Tenant",
        profile="poc",
        external_siem=ExternalSiemOnboard(
            indexer_url="https://should-be-ignored:9200",
            indexer_username="ignored",
            indexer_password="ignored",
            api_url="https://should-be-ignored:55000",
            api_username="ignored",
            api_password="ignored",
            api_token="ignored",
            verify_ssl=False,
        ),
    )

    result = await onboard_tenant(payload, FakeRequest())
    assert result.profile == "poc"

    integration = (
        await mssp_session.execute(
            select(IntegrationConfig).where(
                IntegrationConfig.tenant_id == result.id
            )
        )
    ).scalar_one()
    assert integration.wazuh_api_url is None
    assert integration.wazuh_username is None
    assert integration.wazuh_password_plain is None
    assert integration.wazuh_api_token_plain is None
    assert integration.wazuh_indexer_url is None
    assert integration.wazuh_indexer_username is None
    assert integration.wazuh_indexer_password_plain is None
    # verify_ssl untouched → DB default True (not the smuggled False).
    assert integration.wazuh_verify_ssl is True


def _onboard_route_status() -> int:
    """Declared HTTP status for POST /api/mssp/tenants/onboard (202 Accepted)."""
    from soctalk.core.api.tenants import router

    for route in router.routes:
        if getattr(route, "path", "").endswith("/onboard"):
            return route.status_code  # type: ignore[attr-defined]
    raise AssertionError("onboard route not registered")


async def test_onboard_provided_profile_happy_path(
    mssp_session: AsyncSession, seeded_org: Organization
):
    """profile='provided' + a complete external_siem block → 202 Accepted, a
    Tenant row is created, and BOTH the Wazuh API
    (api_username→wazuh_username) and the Indexer
    (indexer_username→wazuh_indexer_username) credentials land on the
    IntegrationConfig.

    api_token is omitted to prove its absence never blocks onboarding.
    """
    from soctalk.core.api.tenants import (
        ExternalSiemOnboard,
        TenantOnboard,
        onboard_tenant,
    )

    class FakeRequest:
        class State:
            user_identity = {"user_id": "test-user"}
            db = mssp_session
        state = State()

    slug = f"hp{uuid4().hex[:8]}"
    payload = TenantOnboard(
        slug=slug,
        display_name="Provided Happy Path",
        profile="provided",
        external_siem=ExternalSiemOnboard(
            indexer_url="https://indexer.example.com:9200",
            indexer_username="indexer-ro",
            indexer_password="idx-pw-" + uuid4().hex,
            api_url="https://wazuh.example.com:55000",
            api_username="soctalk-adapter",
            api_password="api-pw-" + uuid4().hex,
            # api_token intentionally omitted (defaults to None) — must not 422.
        ),
    )

    # Success contract for the onboard wizard is HTTP 202 Accepted.
    assert _onboard_route_status() == 202

    result = await onboard_tenant(payload, FakeRequest())
    assert result.profile == "provided"

    # A Tenant row exists for the slug.
    tenant_row = (
        await mssp_session.execute(select(Tenant).where(Tenant.slug == slug))
    ).scalar_one()
    assert str(tenant_row.id) == str(result.id)

    integration = (
        await mssp_session.execute(
            select(IntegrationConfig).where(
                IntegrationConfig.tenant_id == tenant_row.id
            )
        )
    ).scalar_one()
    # Both credential families are populated.
    assert integration.wazuh_username == "soctalk-adapter"
    assert integration.wazuh_indexer_username == "indexer-ro"
    # api_token absent → stored NULL, and onboarding still succeeded.
    assert integration.wazuh_api_token_plain is None


async def test_onboard_provided_profile_missing_creds(
    mssp_session: AsyncSession, seeded_org: Organization
):
    """profile='provided' with external_siem=None → HTTP 422 with field-level
    errors and NO Tenant row created.
    """
    from fastapi import HTTPException

    from soctalk.core.api.tenants import TenantOnboard, onboard_tenant

    class FakeRequest:
        class State:
            user_identity = {"user_id": "test-user"}
            db = mssp_session
        state = State()

    slug = f"mc{uuid4().hex[:8]}"
    payload = TenantOnboard(
        slug=slug,
        display_name="Missing Creds",
        profile="provided",
        external_siem=None,
    )

    with pytest.raises(HTTPException) as exc_info:
        await onboard_tenant(payload, FakeRequest())
    assert exc_info.value.status_code == 422

    # No Tenant row was created for the rejected onboard.
    rows = (
        await mssp_session.execute(select(Tenant).where(Tenant.slug == slug))
    ).scalars().all()
    assert rows == []


async def test_onboard_provided_profile_partial_creds(
    mssp_session: AsyncSession, seeded_org: Organization
):
    """profile='provided' with an external_siem block whose api_password is
    empty → HTTP 422 and NO Tenant row created. A partially-filled block is
    just as invalid as a missing one.
    """
    from fastapi import HTTPException

    from soctalk.core.api.tenants import (
        ExternalSiemOnboard,
        TenantOnboard,
        onboard_tenant,
    )

    class FakeRequest:
        class State:
            user_identity = {"user_id": "test-user"}
            db = mssp_session
        state = State()

    slug = f"pp{uuid4().hex[:8]}"
    payload = TenantOnboard(
        slug=slug,
        display_name="Partial Creds",
        profile="provided",
        external_siem=ExternalSiemOnboard(
            indexer_url="https://indexer.example.com:9200",
            indexer_username="indexer-ro",
            indexer_password="idx-pw",
            api_url="https://wazuh.example.com:55000",
            api_username="soctalk-adapter",
            api_password="",  # empty → must reject
            api_token=None,
        ),
    )

    with pytest.raises(HTTPException) as exc_info:
        await onboard_tenant(payload, FakeRequest())
    assert exc_info.value.status_code == 422

    rows = (
        await mssp_session.execute(select(Tenant).where(Tenant.slug == slug))
    ).scalars().all()
    assert rows == []
