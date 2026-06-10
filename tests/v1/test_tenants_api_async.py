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
        llm_api_key="sk-byo-" + uuid4().hex,
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


class _FakeK8s:
    """Records the external-SIEM dual-write side effects.

    Mirrors the slice of :class:`K8sClient` the PATCH endpoint touches:
    a create-or-patch Secret write and a Deployment template-annotation
    patch (the rolling-restart mechanism). Everything is treated as
    idempotent + always-succeeds so the tests assert on what was called.
    """

    def __init__(self) -> None:
        self.secrets: dict[tuple[str, str], dict[str, str]] = {}
        self.deployment_patches: list[tuple[str, str, dict]] = []

    async def put_secret(self, namespace, name, data, *, labels=None) -> None:
        self.secrets[(namespace, name)] = dict(data)

    async def patch_deployment(self, namespace, name, patch) -> None:
        self.deployment_patches.append((namespace, name, patch))


async def test_patch_external_siem(
    mssp_session: AsyncSession, seeded_org: Organization, monkeypatch
):
    """PATCH /api/mssp/tenants/{id}/external-siem updates BOTH credential
    pairs, rewrites the ``tenant-external-siem-creds`` Secret, rolls the
    ``soctalk-adapter`` Deployment (annotation changes), and returns a
    masked view where passwords + token are NEVER echoed.
    """
    import soctalk.core.api.tenants as tenants_mod
    from soctalk.core.api.tenants import (
        ExternalSiemPatch,
        update_tenant_external_siem,
    )

    fake = _FakeK8s()
    monkeypatch.setattr(tenants_mod, "new_k8s_client", lambda: fake)

    slug = f"es{uuid4().hex[:8]}"
    tenant = Tenant(
        slug=slug,
        display_name="External SIEM Patch",
        state=TenantState.ACTIVE.value,
        profile="provided",
        organization_id=seeded_org.id,
    )
    mssp_session.add(tenant)
    await mssp_session.flush()
    mssp_session.add(
        IntegrationConfig(
            tenant_id=tenant.id,
            wazuh_indexer_url="https://old-indexer:9200",
            wazuh_indexer_username="old-idx",
            wazuh_indexer_password_plain="old-idx-pw",
            wazuh_api_url="https://old-wazuh:55000",
            wazuh_username="old-api",
            wazuh_password_plain="old-api-pw",
            wazuh_verify_ssl=True,
        )
    )
    await mssp_session.commit()

    class FakeRequest:
        class State:
            user_identity = {"user_id": "test-user"}
            db = mssp_session
        state = State()

    new_idx_pw = "new-idx-pw-" + uuid4().hex
    new_api_pw = "new-api-pw-" + uuid4().hex
    new_token = "new-token-" + uuid4().hex
    result = await update_tenant_external_siem(
        tenant.id,
        ExternalSiemPatch(
            indexer_username="new-idx",
            indexer_password=new_idx_pw,
            api_username="new-api",
            api_password=new_api_pw,
            api_token=new_token,
            verify_ssl=False,  # False is NOT None → must be written
        ),
        FakeRequest(),
    )

    # --- masked response: has_* flags set; plaintext NEVER echoed ---
    assert result.has_indexer_password is True
    assert result.has_api_password is True
    assert result.has_api_token is True
    assert result.indexer_username == "new-idx"
    assert result.api_username == "new-api"
    assert result.verify_ssl is False
    serialized = str(result.model_dump())
    assert new_idx_pw not in serialized
    assert new_api_pw not in serialized
    assert new_token not in serialized

    # --- adapter Deployment annotation changed (rolling restart) ---
    ns = f"tenant-{slug}"
    adapter_patches = [
        p
        for (pns, name, p) in fake.deployment_patches
        if pns == ns and name == "soctalk-adapter"
    ]
    assert adapter_patches, "expected a soctalk-adapter deployment patch"
    annotations = adapter_patches[-1]["spec"]["template"]["metadata"][
        "annotations"
    ]
    assert "soctalk.io/restartedAt" in annotations
    assert annotations["soctalk.io/restartedAt"].isdigit()

    # --- Secret rewritten with BOTH pairs + token, UPPERCASE keys ---
    secret = fake.secrets[(ns, "tenant-external-siem-creds")]
    assert secret["INDEXER_USERNAME"] == "new-idx"
    assert secret["INDEXER_PASSWORD"] == new_idx_pw
    assert secret["WAZUH_API_USERNAME"] == "new-api"
    assert secret["WAZUH_API_PASSWORD"] == new_api_pw
    assert secret["WAZUH_API_TOKEN"] == new_token

    # --- Postgres columns updated; untouched URLs preserved ---
    mssp_session.expunge_all()
    cfg = (
        await mssp_session.execute(
            select(IntegrationConfig).where(
                IntegrationConfig.tenant_id == tenant.id
            )
        )
    ).scalar_one()
    assert cfg.wazuh_indexer_password_plain == new_idx_pw
    assert cfg.wazuh_password_plain == new_api_pw
    assert cfg.wazuh_api_token_plain == new_token
    assert cfg.wazuh_verify_ssl is False
    assert cfg.wazuh_indexer_url == "https://old-indexer:9200"
    assert cfg.wazuh_api_url == "https://old-wazuh:55000"


async def test_patch_external_siem_works_for_poc_profile(
    mssp_session: AsyncSession, seeded_org: Organization, monkeypatch
):
    """The endpoint is profile-agnostic: a ``poc`` tenant can be repointed
    at an external SIEM after the fact. The columns + the Secret update even
    though the tenant is NOT on the ``provided`` profile, and there is no
    profile gate that 4xxs the request.
    """
    import soctalk.core.api.tenants as tenants_mod
    from soctalk.core.api.tenants import (
        ExternalSiemPatch,
        update_tenant_external_siem,
    )

    fake = _FakeK8s()
    monkeypatch.setattr(tenants_mod, "new_k8s_client", lambda: fake)

    slug = f"pc{uuid4().hex[:8]}"
    tenant = Tenant(
        slug=slug,
        display_name="PoC repoint",
        state=TenantState.ACTIVE.value,
        profile="poc",
        organization_id=seeded_org.id,
    )
    mssp_session.add(tenant)
    await mssp_session.flush()
    mssp_session.add(
        IntegrationConfig(
            tenant_id=tenant.id,
            wazuh_url="https://wazuh-poc.in-cluster",
        )
    )
    await mssp_session.commit()

    class FakeRequest:
        class State:
            user_identity = {"user_id": "test-user"}
            db = mssp_session
        state = State()

    idx_pw = "poc-idx-pw-" + uuid4().hex
    api_pw = "poc-api-pw-" + uuid4().hex
    result = await update_tenant_external_siem(
        tenant.id,
        ExternalSiemPatch(
            indexer_url="https://ext-indexer:9200",
            indexer_username="ext-idx",
            indexer_password=idx_pw,
            api_url="https://ext-wazuh:55000",
            api_username="ext-api",
            api_password=api_pw,
            # api_token intentionally omitted → key omitted from the Secret
        ),
        FakeRequest(),
    )

    assert result.has_indexer_password is True
    assert result.has_api_password is True
    assert result.has_api_token is False

    # Profile was never gated and is unchanged.
    tenant_row = (
        await mssp_session.execute(select(Tenant).where(Tenant.id == tenant.id))
    ).scalar_one()
    assert tenant_row.profile == "poc"

    # Columns updated despite the non-provided profile.
    mssp_session.expunge_all()
    cfg = (
        await mssp_session.execute(
            select(IntegrationConfig).where(
                IntegrationConfig.tenant_id == tenant.id
            )
        )
    ).scalar_one()
    assert cfg.wazuh_indexer_url == "https://ext-indexer:9200"
    assert cfg.wazuh_indexer_username == "ext-idx"
    assert cfg.wazuh_indexer_password_plain == idx_pw
    assert cfg.wazuh_api_url == "https://ext-wazuh:55000"
    assert cfg.wazuh_username == "ext-api"
    assert cfg.wazuh_password_plain == api_pw

    # Secret written to the tenant namespace; token key omitted when unset.
    secret = fake.secrets[(f"tenant-{slug}", "tenant-external-siem-creds")]
    assert secret["INDEXER_USERNAME"] == "ext-idx"
    assert secret["INDEXER_PASSWORD"] == idx_pw
    assert secret["WAZUH_API_USERNAME"] == "ext-api"
    assert secret["WAZUH_API_PASSWORD"] == api_pw
    assert "WAZUH_API_TOKEN" not in secret


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
        llm_api_key="sk-happy-" + uuid4().hex,
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


# ---------------------------------------------------------------------------
# Adapter-status proxy: GET /api/mssp/tenants/{id}/adapter-status
# ---------------------------------------------------------------------------
#
# The detail-page External-SIEM panel polls live adapter ingest status. The
# browser CANNOT reach the per-tenant adapter Service (cluster-internal DNS,
# no ingress), so the control plane SERVER-SIDE proxies to the adapter's
# /health/ready and relays the JSON. A wedged/absent adapter must degrade
# softly — HTTP 200 with ``{"reachable": false, "error": "<msg>"}`` — so the
# poller renders a degraded badge instead of surfacing an API error.


class _FakeAdapterResponse:
    """Minimal stand-in for the ``httpx.Response`` the adapter returns."""

    def __init__(self, payload: dict, status_code: int = 200) -> None:
        self._payload = payload
        self.status_code = status_code

    def raise_for_status(self) -> None:
        # The tests only exercise the 200 success path + a connection error
        # raised from .get(); a non-2xx here would simply be caught by the
        # handler's blanket except and folded into the soft-fail body.
        return None

    def json(self) -> dict:
        return self._payload


class _FakeAdapterHttpClient:
    """Stand-in for ``httpx.AsyncClient`` used by the adapter-status proxy.

    Records the URL fetched and either returns a canned response or raises a
    connection error to simulate an unreachable adapter — so the test never
    opens a real socket to the (non-existent) per-tenant adapter Service.
    """

    last_url: str | None = None

    def __init__(
        self, *, payload: dict | None = None, exc: Exception | None = None
    ) -> None:
        self._payload = payload
        self._exc = exc

    async def __aenter__(self) -> "_FakeAdapterHttpClient":
        return self

    async def __aexit__(self, *_a) -> bool:
        return False

    async def get(self, url: str) -> _FakeAdapterResponse:
        type(self).last_url = url
        if self._exc is not None:
            raise self._exc
        assert self._payload is not None
        return _FakeAdapterResponse(self._payload)


async def test_adapter_status_proxies_adapter_health_ready(
    mssp_session: AsyncSession, seeded_org: Organization, monkeypatch
):
    """GET /api/mssp/tenants/{id}/adapter-status server-side proxies to the
    tenant adapter's ``/health/ready`` and relays the JSON verbatim.

    The outbound httpx call is mocked — no real adapter is contacted. The
    proxied URL must be the in-cluster Service address
    ``http://soctalk-adapter.tenant-<slug>.svc.cluster.local:8080/health/ready``
    (NOT a browser-reachable URL), proving this is a server-side proxy rather
    than browser CORS.
    """
    import soctalk.core.api.tenants as tenants_mod
    from soctalk.core.api.tenants import get_tenant_adapter_status

    slug = f"as{uuid4().hex[:8]}"
    tenant = Tenant(
        slug=slug,
        display_name="Adapter Status",
        state=TenantState.ACTIVE.value,
        profile="poc",
        organization_id=seeded_org.id,
    )
    mssp_session.add(tenant)
    await mssp_session.commit()
    await mssp_session.refresh(tenant)

    payload = {
        "ok": True,
        "alerts_forwarded": 7,
        "last_alert_ts": "2026-06-09T00:00:00+00:00",
        "last_ingest_error": None,
    }
    captured: dict[str, _FakeAdapterHttpClient] = {}

    def _factory() -> _FakeAdapterHttpClient:
        client = _FakeAdapterHttpClient(payload=payload)
        captured["client"] = client
        return client

    monkeypatch.setattr(tenants_mod, "_new_adapter_http_client", _factory)

    class FakeRequest:
        class State:
            user_identity = {"user_id": "test-user"}
            db = mssp_session
        state = State()

    result = await get_tenant_adapter_status(tenant.id, FakeRequest())

    # Adapter JSON is proxied through unchanged.
    assert result["alerts_forwarded"] == 7
    assert result["last_alert_ts"] == "2026-06-09T00:00:00+00:00"
    assert result["last_ingest_error"] is None

    # Server-side proxy → in-cluster Service DNS, NOT a browser CORS request.
    assert (
        captured["client"].last_url
        == f"http://soctalk-adapter.tenant-{slug}"
        ".svc.cluster.local:8080/health/ready"
    )


async def test_adapter_status_soft_fails_on_unreachable_adapter(
    mssp_session: AsyncSession, seeded_org: Organization, monkeypatch
):
    """When the adapter is unreachable (DNS / connection error), the proxy must
    NOT raise / 5xx. It returns HTTP 200 with
    ``{"reachable": false, "error": "<msg>"}`` so the detail-page poller renders
    a degraded state instead of an API error.
    """
    import httpx

    import soctalk.core.api.tenants as tenants_mod
    from soctalk.core.api.tenants import get_tenant_adapter_status

    slug = f"dn{uuid4().hex[:8]}"
    tenant = Tenant(
        slug=slug,
        display_name="Adapter Down",
        state=TenantState.ACTIVE.value,
        profile="poc",
        organization_id=seeded_org.id,
    )
    mssp_session.add(tenant)
    await mssp_session.commit()
    await mssp_session.refresh(tenant)

    boom = httpx.ConnectError("Name or service not known")
    monkeypatch.setattr(
        tenants_mod,
        "_new_adapter_http_client",
        lambda: _FakeAdapterHttpClient(exc=boom),
    )

    class FakeRequest:
        class State:
            user_identity = {"user_id": "test-user"}
            db = mssp_session
        state = State()

    # Must NOT raise — the soft-fail body is returned as the default HTTP 200.
    result = await get_tenant_adapter_status(tenant.id, FakeRequest())
    assert result["reachable"] is False
    assert "Name or service not known" in result["error"]


async def test_adapter_status_unknown_tenant_404(
    mssp_session: AsyncSession, seeded_org: Organization
):
    """An unknown tenant id is a real 404 — distinct from the soft-fail body
    used for an unreachable (but existing) tenant's adapter.
    """
    from fastapi import HTTPException

    from soctalk.core.api.tenants import get_tenant_adapter_status

    class FakeRequest:
        class State:
            user_identity = {"user_id": "test-user"}
            db = mssp_session
        state = State()

    with pytest.raises(HTTPException) as exc_info:
        await get_tenant_adapter_status(uuid4(), FakeRequest())
    assert exc_info.value.status_code == 404


def test_adapter_status_route_declares_no_error_status():
    """The adapter-status route declares no explicit (error) status_code so the
    soft-fail body is served as the default HTTP 200, not a 4xx/5xx.
    """
    from soctalk.core.api.tenants import router

    for route in router.routes:
        if getattr(route, "path", "").endswith("/adapter-status"):
            assert route.status_code in (None, 200)
            return
    raise AssertionError("adapter-status route not registered")


# ---------------------------------------------------------------------------
# Per-tenant LLM credentials on onboard (tenant.llm.onboard-key)
# ---------------------------------------------------------------------------
#
# TenantOnboard carries llm_api_key + llm_provider. REQUIRED for
# profile='provided' (field-level 422 BEFORE any DB write → zero Tenant
# rows); optional for poc/persistent (install-shared fallback unchanged).
# Non-null values persist onto IntegrationConfig (llm_api_key_plain /
# llm_provider) in the SAME transaction as the Tenant row. The raw key is
# never echoed in any response body or error detail.


def _complete_external_siem():
    from soctalk.core.api.tenants import ExternalSiemOnboard

    return ExternalSiemOnboard(
        indexer_url="https://indexer.example.com:9200",
        indexer_username="indexer-ro",
        indexer_password="idx-pw-" + uuid4().hex,
        api_url="https://wazuh.example.com:55000",
        api_username="soctalk-adapter",
        api_password="api-pw-" + uuid4().hex,
    )


async def test_onboard_provided_without_llm_key_422_no_tenant_row(
    mssp_session: AsyncSession, seeded_org: Organization
):
    """profile='provided' with complete external_siem but NO llm_api_key →
    HTTP 422 with a field-level error at ['body', 'llm_api_key'], raised
    BEFORE any DB write so zero Tenant rows exist for the slug.
    """
    from fastapi import HTTPException

    from soctalk.core.api.tenants import TenantOnboard, onboard_tenant

    class FakeRequest:
        class State:
            user_identity = {"user_id": "test-user"}
            db = mssp_session
        state = State()

    slug = f"nk{uuid4().hex[:8]}"
    payload = TenantOnboard(
        slug=slug,
        display_name="No LLM Key",
        profile="provided",
        external_siem=_complete_external_siem(),
        # llm_api_key intentionally omitted.
    )

    with pytest.raises(HTTPException) as exc_info:
        await onboard_tenant(payload, FakeRequest())
    assert exc_info.value.status_code == 422
    # Field-level error shape: loc points at body.llm_api_key.
    locs = [tuple(e["loc"]) for e in exc_info.value.detail]
    assert ("body", "llm_api_key") in locs

    # Zero Tenant rows created for the rejected onboard.
    rows = (
        await mssp_session.execute(select(Tenant).where(Tenant.slug == slug))
    ).scalars().all()
    assert rows == []


async def test_onboard_provided_blank_llm_key_422(
    mssp_session: AsyncSession, seeded_org: Organization
):
    """A whitespace-only llm_api_key is just as missing as an absent one —
    422 with the field-level error, no Tenant row, and the (blank) key value
    never reflected into the error detail.
    """
    from fastapi import HTTPException

    from soctalk.core.api.tenants import TenantOnboard, onboard_tenant

    class FakeRequest:
        class State:
            user_identity = {"user_id": "test-user"}
            db = mssp_session
        state = State()

    slug = f"bk{uuid4().hex[:8]}"
    payload = TenantOnboard(
        slug=slug,
        display_name="Blank LLM Key",
        profile="provided",
        llm_api_key="   ",
        external_siem=_complete_external_siem(),
    )

    with pytest.raises(HTTPException) as exc_info:
        await onboard_tenant(payload, FakeRequest())
    assert exc_info.value.status_code == 422
    locs = [tuple(e["loc"]) for e in exc_info.value.detail]
    assert ("body", "llm_api_key") in locs

    rows = (
        await mssp_session.execute(select(Tenant).where(Tenant.slug == slug))
    ).scalars().all()
    assert rows == []


async def test_onboard_provided_with_llm_key_persists_never_echoes(
    mssp_session: AsyncSession, seeded_org: Organization
):
    """provided onboard with a key → 202 declared on the route, the key
    persists onto IntegrationConfig.llm_api_key_plain in the same transaction
    as the Tenant row, and the raw key is absent from the response body.
    """
    from soctalk.core.api.tenants import TenantOnboard, onboard_tenant

    class FakeRequest:
        class State:
            user_identity = {"user_id": "test-user"}
            db = mssp_session
        state = State()

    key = "sk-proj-onboard-" + uuid4().hex
    slug = f"lk{uuid4().hex[:8]}"
    payload = TenantOnboard(
        slug=slug,
        display_name="LLM Key Onboard",
        profile="provided",
        llm_api_key=key,
        external_siem=_complete_external_siem(),
    )

    assert _onboard_route_status() == 202
    result = await onboard_tenant(payload, FakeRequest())

    # The key is NEVER echoed in the response body.
    assert key not in str(result.model_dump())

    integration = (
        await mssp_session.execute(
            select(IntegrationConfig).where(
                IntegrationConfig.tenant_id == result.id
            )
        )
    ).scalar_one()
    assert integration.llm_api_key_plain == key


async def test_onboard_llm_provider_normalized_openai(
    mssp_session: AsyncSession, seeded_org: Organization
):
    """llm_provider='openai' is canonicalized to 'openai-compatible' on the
    persisted IntegrationConfig row (same normalizer as LlmConfigUpdate) so
    the next helm render passes the tenant chart's values.schema.json.
    """
    from soctalk.core.api.tenants import TenantOnboard, onboard_tenant

    class FakeRequest:
        class State:
            user_identity = {"user_id": "test-user"}
            db = mssp_session
        state = State()

    payload = TenantOnboard(
        slug=f"no{uuid4().hex[:8]}",
        display_name="Normalized Provider",
        profile="provided",
        llm_api_key="sk-openai-" + uuid4().hex,
        llm_provider="openai",
        external_siem=_complete_external_siem(),
    )

    result = await onboard_tenant(payload, FakeRequest())
    integration = (
        await mssp_session.execute(
            select(IntegrationConfig).where(
                IntegrationConfig.tenant_id == result.id
            )
        )
    ).scalar_one()
    assert integration.llm_provider == "openai-compatible"


async def test_onboard_sk_ant_key_infers_anthropic_and_flips_model(
    mssp_session: AsyncSession, seeded_org: Organization
):
    """An sk-ant- key with no explicit provider → llm_provider='anthropic'
    is inferred, and the clearly-mismatched default model (gpt-4o) is
    flipped to the Anthropic default so the runs-worker never renders an
    OpenAI model name against the Anthropic SDK.
    """
    from soctalk.core.api.tenants import TenantOnboard, onboard_tenant

    class FakeRequest:
        class State:
            user_identity = {"user_id": "test-user"}
            db = mssp_session
        state = State()

    payload = TenantOnboard(
        slug=f"an{uuid4().hex[:8]}",
        display_name="Anthropic Inference",
        profile="provided",
        llm_api_key="sk-ant-" + uuid4().hex,
        # llm_provider intentionally omitted → inferred from the key prefix.
        external_siem=_complete_external_siem(),
    )

    result = await onboard_tenant(payload, FakeRequest())
    integration = (
        await mssp_session.execute(
            select(IntegrationConfig).where(
                IntegrationConfig.tenant_id == result.id
            )
        )
    ).scalar_one()
    assert integration.llm_provider == "anthropic"
    # Default model flipped off gpt-4o (Anthropic SDK would reject it).
    assert integration.llm_model != "gpt-4o"
    assert integration.llm_model.startswith("claude")


async def test_onboard_non_sk_ant_key_keeps_openai_compatible_default(
    mssp_session: AsyncSession, seeded_org: Organization
):
    """A non-sk-ant key with no explicit provider keeps the
    openai-compatible default and the default model stays gpt-4o.
    """
    from soctalk.core.api.tenants import TenantOnboard, onboard_tenant

    class FakeRequest:
        class State:
            user_identity = {"user_id": "test-user"}
            db = mssp_session
        state = State()

    payload = TenantOnboard(
        slug=f"oc{uuid4().hex[:8]}",
        display_name="OpenAI-compatible Inference",
        profile="provided",
        llm_api_key="sk-proj-" + uuid4().hex,
        external_siem=_complete_external_siem(),
    )

    result = await onboard_tenant(payload, FakeRequest())
    integration = (
        await mssp_session.execute(
            select(IntegrationConfig).where(
                IntegrationConfig.tenant_id == result.id
            )
        )
    ).scalar_one()
    assert integration.llm_provider == "openai-compatible"
    assert integration.llm_model == "gpt-4o"


async def test_onboard_poc_without_llm_key_still_succeeds(
    mssp_session: AsyncSession, seeded_org: Organization
):
    """For poc the LLM key stays optional: onboarding without one succeeds
    (202 route contract) and llm_api_key_plain stays NULL so the controller's
    install-shared fallback path is unchanged.
    """
    from soctalk.core.api.tenants import TenantOnboard, onboard_tenant

    class FakeRequest:
        class State:
            user_identity = {"user_id": "test-user"}
            db = mssp_session
        state = State()

    payload = TenantOnboard(
        slug=f"po{uuid4().hex[:8]}",
        display_name="PoC No Key",
        profile="poc",
        # llm_api_key intentionally omitted — must NOT 422.
    )

    assert _onboard_route_status() == 202
    result = await onboard_tenant(payload, FakeRequest())
    assert result.profile == "poc"

    integration = (
        await mssp_session.execute(
            select(IntegrationConfig).where(
                IntegrationConfig.tenant_id == result.id
            )
        )
    ).scalar_one()
    assert integration.llm_api_key_plain is None
    # Column default preserved when no provider was supplied or inferred.
    assert integration.llm_provider == "openai-compatible"


async def test_onboard_poc_with_llm_key_persists(
    mssp_session: AsyncSession, seeded_org: Organization
):
    """Optional-for-poc still means *persisted* when supplied: a poc onboard
    carrying a key lands it on llm_api_key_plain in the same transaction.
    """
    from soctalk.core.api.tenants import TenantOnboard, onboard_tenant

    class FakeRequest:
        class State:
            user_identity = {"user_id": "test-user"}
            db = mssp_session
        state = State()

    key = "sk-poc-" + uuid4().hex
    payload = TenantOnboard(
        slug=f"pk{uuid4().hex[:8]}",
        display_name="PoC With Key",
        profile="poc",
        llm_api_key=key,
    )

    result = await onboard_tenant(payload, FakeRequest())
    assert key not in str(result.model_dump())

    integration = (
        await mssp_session.execute(
            select(IntegrationConfig).where(
                IntegrationConfig.tenant_id == result.id
            )
        )
    ).scalar_one()
    assert integration.llm_api_key_plain == key


async def test_onboard_422_detail_never_contains_llm_key(
    mssp_session: AsyncSession, seeded_org: Organization
):
    """A provided onboard that fails validation on the external-SIEM block
    while carrying an llm_api_key must not reflect the key into the 422
    error detail.
    """
    from fastapi import HTTPException

    from soctalk.core.api.tenants import TenantOnboard, onboard_tenant

    class FakeRequest:
        class State:
            user_identity = {"user_id": "test-user"}
            db = mssp_session
        state = State()

    key = "sk-secret-" + uuid4().hex
    payload = TenantOnboard(
        slug=f"se{uuid4().hex[:8]}",
        display_name="Secret Never Echoed",
        profile="provided",
        llm_api_key=key,
        external_siem=None,  # forces the 422
    )

    with pytest.raises(HTTPException) as exc_info:
        await onboard_tenant(payload, FakeRequest())
    assert exc_info.value.status_code == 422
    assert key not in str(exc_info.value.detail)
