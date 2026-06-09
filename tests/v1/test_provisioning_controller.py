"""Controller step idempotency + crash-resume, fakes only.

Fakes K8sClient and monkey-patches the two ``helm_*`` functions so the
controller runs end-to-end against an in-memory topology. Exercises:

- happy-path: pending → active, all lifecycle events emitted
- crash-resume: kill mid-run, re-enter, steps short-circuit
- failure propagates with the step name attached
"""

from __future__ import annotations

import os
from collections.abc import AsyncIterator
from uuid import uuid4

import pytest
import pytest_asyncio
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from soctalk.core.provisioning import controller as controller_mod
from soctalk.core.provisioning.controller import (
    ControllerSettings,
    ProvisionError,
    TenantController,
)
from soctalk.core.tenancy.models import (
    BrandingConfig,
    IntegrationConfig,
    Organization,
    Tenant,
    TenantLifecycleEvent,
    TenantSecret,
    TenantState,
)

SKIP_INTEGRATION = os.getenv("SKIP_INTEGRATION", "0") == "1"

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        SKIP_INTEGRATION,
        reason="SKIP_INTEGRATION set; controller tests need Postgres",
    ),
]


# ---------------------------------------------------------------------------
# Fake k8s + helm
# ---------------------------------------------------------------------------


class FakeK8s:
    """Records all side-effecting calls; treats everything as idempotent."""

    def __init__(self) -> None:
        self.namespaces: set[str] = set()
        self.secrets: dict[tuple[str, str], dict[str, str]] = {}
        self.pods_ready = True  # flip to False to simulate not-ready workloads
        self.calls: list[str] = []

    async def check_reachable(self) -> None:
        self.calls.append("check_reachable")

    async def storage_class_exists(self, name: str) -> bool:
        return True

    async def ensure_namespace(self, name, labels) -> None:
        self.calls.append(f"ensure_namespace:{name}")
        self.namespaces.add(name)

    async def delete_namespace(self, name) -> None:
        self.namespaces.discard(name)

    async def put_secret(self, namespace, name, data, *, labels=None) -> None:
        self.calls.append(f"put_secret:{namespace}/{name}")
        self.secrets[(namespace, name)] = data

    async def get_secret(self, namespace, name):
        """Mirror the real client: raise 404 ApiException if missing,
        otherwise return ``{"name", "namespace", "data"}``. The
        controller's ``_mint_tenant_admin_user`` retry path
        distinguishes 404 (rotate password) from other errors (fail).
        """
        self.calls.append(f"get_secret:{namespace}/{name}")
        if (namespace, name) not in self.secrets:
            from kubernetes.client.exceptions import ApiException
            raise ApiException(status=404, reason="Not Found")
        return {
            "name": name,
            "namespace": namespace,
            "data": self.secrets[(namespace, name)],
        }

    async def read_pods(self, namespace):
        # Two pods; readiness flipped wholesale by tests.
        return [
            {"name": "wazuh-manager-0", "phase": "Running", "ready": self.pods_ready},
            {"name": "wazuh-indexer-0", "phase": "Running", "ready": self.pods_ready},
        ]


async def _fake_helm_install_tenant(*_, **__):
    return type("R", (), {"returncode": 0, "stdout": "", "stderr": "", "ok": True})()


async def _fake_helm_install_wazuh(*_, **__):
    return type("R", (), {"returncode": 0, "stdout": "", "stderr": "", "ok": True})()


async def _fake_helm_version():
    return type("R", (), {"returncode": 0, "stdout": "v3.14.0", "stderr": "", "ok": True})()


@pytest.fixture
def patched_helm(monkeypatch):
    monkeypatch.setattr(controller_mod, "helm_install_tenant", _fake_helm_install_tenant)
    # helm_install_wazuh is imported into controller_mod at module load.
    monkeypatch.setattr(controller_mod, "helm_install_wazuh", _fake_helm_install_wazuh)
    # helm_version is imported lazily inside _step_preflight.
    from soctalk.core.provisioning import helm as helm_mod
    monkeypatch.setattr(helm_mod, "helm_version", _fake_helm_version)


# ---------------------------------------------------------------------------
# DB fixtures
# ---------------------------------------------------------------------------


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
    """Admin session — used only for TRUNCATE at fixture start."""
    engine = create_async_engine(_admin_url(), echo=False, pool_pre_ping=True)
    sm = async_sessionmaker(engine, expire_on_commit=False)
    async with sm() as s:
        yield s
    await engine.dispose()


@pytest_asyncio.fixture
async def session() -> AsyncIterator[AsyncSession]:
    # mssp role (BYPASSRLS) — the controller runs under this in production
    # worker, and tests need it to seed across tenants.
    engine = create_async_engine(_mssp_url(), echo=False, pool_pre_ping=True)
    sm = async_sessionmaker(engine, expire_on_commit=False)
    async with sm() as s:
        yield s
    await engine.dispose()


@pytest_asyncio.fixture
async def seeded_tenant(
    session: AsyncSession, admin_session: AsyncSession
) -> Tenant:
    """Fresh org + tenant + branding + integration, clean namespace collision."""
    from sqlalchemy import text

    # Admin does the TRUNCATE (mssp role doesn't have that grant).
    await admin_session.execute(
        text(
            "TRUNCATE tenant_lifecycle_events, integration_configs, "
            "branding_configs, tenant_secrets, provisioning_jobs, "
            "tenants, organizations CASCADE"
        )
    )
    await admin_session.commit()

    org = Organization(
        mssp_id=uuid4(), mssp_name="Test MSSP", slug="test-mssp",
        install_id=uuid4(), install_label="test",
    )
    session.add(org)
    await session.flush()

    tenant = Tenant(
        slug=f"tenant-{uuid4().hex[:8]}",
        display_name="Test Tenant",
        state=TenantState.PENDING.value,
        profile="poc",
        organization_id=org.id,
    )
    session.add(tenant)
    await session.flush()

    session.add_all([
        IntegrationConfig(tenant_id=tenant.id),
        BrandingConfig(tenant_id=tenant.id, app_name="Test"),
    ])
    await session.commit()
    return tenant


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


async def test_provision_happy_path_emits_each_step(
    session: AsyncSession, seeded_tenant: Tenant, patched_helm
):
    fake_k8s = FakeK8s()
    controller = TenantController(
        session, k8s=fake_k8s,
        settings=ControllerSettings(
            wazuh_chart_path="charts/wazuh",
            readiness_poll_interval_seconds=0.01,
            readiness_timeout_seconds=5.0,
        ),
    )

    result = await controller.provision(seeded_tenant.id, actor_id="test")
    assert result.state == TenantState.ACTIVE.value

    evs = (
        await session.execute(
            select(TenantLifecycleEvent)
            .where(TenantLifecycleEvent.tenant_id == seeded_tenant.id)
            .order_by(TenantLifecycleEvent.timestamp)
        )
    ).scalars().all()
    kinds = [e.event_type for e in evs]

    # Canonical order, plus final "active" transition.
    for must_have in (
        "provisioning_started",
        "preflight_ok",
        "secrets_minted",
        "namespace_ready",
        "secrets_applied",
        "helm_applied",  # appears twice (tenant + wazuh); at least one
        "workloads_ready",
        "integration_config_written",
        "active",
    ):
        assert must_have in kinds, f"missing lifecycle event: {must_have}"

    # Integration config got the Wazuh URL written.
    integ = (
        await session.execute(
            select(IntegrationConfig).where(
                IntegrationConfig.tenant_id == seeded_tenant.id
            )
        )
    ).scalar_one()
    assert integ.wazuh_url is not None and integ.wazuh_url.endswith(":55000")


async def test_provision_resume_after_crash_is_idempotent(
    session: AsyncSession, seeded_tenant: Tenant, patched_helm
):
    """Simulate crash right after helm_apply_tenant; re-enter; must succeed."""

    fake_k8s = FakeK8s()
    controller = TenantController(
        session, k8s=fake_k8s,
        settings=ControllerSettings(
            wazuh_chart_path="charts/wazuh",
            readiness_poll_interval_seconds=0.01,
            readiness_timeout_seconds=5.0,
        ),
    )

    # Poison helm_install_wazuh on the first pass to force a failure mid-run.
    from soctalk.core.provisioning import controller as ctrl
    original = ctrl.helm_install_wazuh
    calls = {"n": 0}

    async def flaky(*a, **kw):
        calls["n"] += 1
        if calls["n"] == 1:
            raise ctrl.HelmError("simulated crash")
        return await _fake_helm_install_wazuh(*a, **kw)

    ctrl.helm_install_wazuh = flaky
    try:
        with pytest.raises(ProvisionError):
            await controller.provision(seeded_tenant.id, actor_id="test")

        # Tenant should be degraded, failure recorded.
        tenant = (
            await session.execute(select(Tenant).where(Tenant.id == seeded_tenant.id))
        ).scalar_one()
        assert tenant.state == TenantState.DEGRADED.value

        # Resume: provision() again; retry_requested + remaining steps should fire.
        result = await controller.provision(seeded_tenant.id, actor_id="test")
        assert result.state == TenantState.ACTIVE.value
    finally:
        ctrl.helm_install_wazuh = original


async def test_preflight_failure_doesnt_mutate_tenant_beyond_degraded(
    session: AsyncSession, seeded_tenant: Tenant, patched_helm, monkeypatch
):
    fake_k8s = FakeK8s()

    async def fake_unreachable():
        raise RuntimeError("kube API timeout")

    monkeypatch.setattr(fake_k8s, "check_reachable", fake_unreachable)
    controller = TenantController(
        session, k8s=fake_k8s,
        settings=ControllerSettings(wazuh_chart_path="charts/wazuh"),
    )

    with pytest.raises(ProvisionError) as exc_info:
        await controller.provision(seeded_tenant.id, actor_id="test")
    assert exc_info.value.step == "preflight"

    # Nothing in k8s was touched beyond the failed probe.
    assert "ensure_namespace" not in " ".join(fake_k8s.calls)

    tenant = (
        await session.execute(select(Tenant).where(Tenant.id == seeded_tenant.id))
    ).scalar_one()
    assert tenant.state == TenantState.DEGRADED.value


# ---------------------------------------------------------------------------
# 'provided' profile: external Wazuh, no in-namespace SIEM
# ---------------------------------------------------------------------------


# External SIEM endpoints + creds the customer brings for a 'provided' tenant.
_PROVIDED_INDEXER_URL = "https://indexer.acme.example:9200"
_PROVIDED_API_URL = "https://wazuh.acme.example:55000"
_PROVIDED_INDEXER_USER = "idx-user"
_PROVIDED_INDEXER_PASS = "idx-pass"
_PROVIDED_API_USER = "api-user"
_PROVIDED_API_PASS = "api-pass"


@pytest_asyncio.fixture
async def provided_tenant(
    session: AsyncSession, admin_session: AsyncSession
) -> Tenant:
    """A pending 'provided'-profile tenant whose IntegrationConfig already
    carries BOTH the external indexer creds and the Wazuh API creds (the
    onboard endpoint guarantees these before profile='provided' is allowed).
    ``wazuh_api_token_plain`` is intentionally left NULL so the test can pin
    the "WAZUH_API_TOKEN omitted when absent" branch.
    """
    from sqlalchemy import text

    await admin_session.execute(
        text(
            "TRUNCATE tenant_lifecycle_events, integration_configs, "
            "branding_configs, tenant_secrets, provisioning_jobs, "
            "tenants, organizations CASCADE"
        )
    )
    await admin_session.commit()

    org = Organization(
        mssp_id=uuid4(), mssp_name="Test MSSP", slug="test-mssp",
        install_id=uuid4(), install_label="test",
    )
    session.add(org)
    await session.flush()

    tenant = Tenant(
        slug=f"tenant-{uuid4().hex[:8]}",
        display_name="Provided Tenant",
        state=TenantState.PENDING.value,
        profile="provided",
        organization_id=org.id,
    )
    session.add(tenant)
    await session.flush()

    session.add_all([
        IntegrationConfig(
            tenant_id=tenant.id,
            wazuh_enabled=True,
            # Customer-provided external endpoints (must survive provisioning).
            wazuh_url=_PROVIDED_API_URL,
            wazuh_api_url=_PROVIDED_API_URL,
            wazuh_indexer_url=_PROVIDED_INDEXER_URL,
            # Wazuh API (manager, :55000) HTTP-Basic creds.
            wazuh_username=_PROVIDED_API_USER,
            wazuh_password_plain=_PROVIDED_API_PASS,
            # Indexer (:9200) HTTP-Basic creds.
            wazuh_indexer_username=_PROVIDED_INDEXER_USER,
            wazuh_indexer_password_plain=_PROVIDED_INDEXER_PASS,
            # No pre-minted API token: WAZUH_API_TOKEN must be omitted.
            wazuh_api_token_plain=None,
        ),
        BrandingConfig(tenant_id=tenant.id, app_name="Provided"),
    ])
    await session.commit()
    return tenant


async def test_provision_provided_profile(
    session: AsyncSession, provided_tenant: Tenant, monkeypatch
):
    """Drive a 'provided' tenant pending -> active and assert the controller:

    - installs the soctalk-tenant chart exactly once,
    - never installs the wazuh-<slug> release,
    - writes Secret/tenant-external-siem-creds with the four credential keys
      (WAZUH_API_TOKEN omitted because wazuh_api_token_plain is NULL),
    - runs that secret step AFTER apply_secrets and BEFORE helm_apply_tenant,
    - emits exactly one 'wazuh_skipped_provided' lifecycle event,
    - leaves integration.wazuh_url / wazuh_indexer_url untouched,
    - mints an 'external-siem-creds' reference row but NO 'bootstrap' row.
    """
    fake_k8s = FakeK8s()

    # Recording helm shims. Both also push a marker into fake_k8s.calls so we
    # get one ordered timeline across secret writes + helm installs.
    tenant_calls: list[dict] = []
    wazuh_calls: list[dict] = []

    def _ok():
        return type("R", (), {"returncode": 0, "stdout": "", "stderr": "", "ok": True})()

    async def rec_install_tenant(*_a, **kw):
        fake_k8s.calls.append("helm_install_tenant")
        tenant_calls.append(kw)
        return _ok()

    async def rec_install_wazuh(*_a, **kw):
        fake_k8s.calls.append("helm_install_wazuh")
        wazuh_calls.append(kw)
        return _ok()

    monkeypatch.setattr(controller_mod, "helm_install_tenant", rec_install_tenant)
    monkeypatch.setattr(controller_mod, "helm_install_wazuh", rec_install_wazuh)
    from soctalk.core.provisioning import helm as helm_mod
    monkeypatch.setattr(helm_mod, "helm_version", _fake_helm_version)

    controller = TenantController(
        session, k8s=fake_k8s,
        settings=ControllerSettings(
            wazuh_chart_path="charts/wazuh",
            readiness_poll_interval_seconds=0.01,
            readiness_timeout_seconds=5.0,
        ),
    )

    result = await controller.provision(provided_tenant.id, actor_id="test")
    assert result.state == TenantState.ACTIVE.value

    # --- helm: exactly one soctalk-tenant install, zero wazuh installs ------
    assert len(tenant_calls) == 1, f"expected one tenant install, got {tenant_calls}"
    assert wazuh_calls == [], f"wazuh release must not be installed, got {wazuh_calls}"

    ns = f"tenant-{provided_tenant.slug}"

    # --- the external-SIEM Secret carries exactly the four basic-auth keys --
    assert (ns, "tenant-external-siem-creds") in fake_k8s.secrets
    secret = fake_k8s.secrets[(ns, "tenant-external-siem-creds")]
    assert set(secret.keys()) == {
        "INDEXER_USERNAME",
        "INDEXER_PASSWORD",
        "WAZUH_API_USERNAME",
        "WAZUH_API_PASSWORD",
    }
    assert secret["INDEXER_USERNAME"] == _PROVIDED_INDEXER_USER
    assert secret["INDEXER_PASSWORD"] == _PROVIDED_INDEXER_PASS
    assert secret["WAZUH_API_USERNAME"] == _PROVIDED_API_USER
    assert secret["WAZUH_API_PASSWORD"] == _PROVIDED_API_PASS
    # No pre-minted API token on the integration row -> key omitted.
    assert "WAZUH_API_TOKEN" not in secret

    # --- step ordering: apply_secrets < write_external_siem_secret < helm ---
    calls = fake_k8s.calls
    i_adapter = calls.index(f"put_secret:{ns}/adapter-token")          # apply_secrets
    i_ext = calls.index(f"put_secret:{ns}/tenant-external-siem-creds")  # new step
    i_helm = calls.index("helm_install_tenant")                        # helm_apply_tenant
    assert i_adapter < i_ext < i_helm

    # --- lifecycle events: wazuh skipped once; secret-applied marker present-
    evs = (
        await session.execute(
            select(TenantLifecycleEvent)
            .where(TenantLifecycleEvent.tenant_id == provided_tenant.id)
            .order_by(TenantLifecycleEvent.timestamp)
        )
    ).scalars().all()
    kinds = [e.event_type for e in evs]
    assert kinds.count("wazuh_skipped_provided") == 1
    assert "external_siem_secret_applied" in kinds

    # --- integration endpoints unchanged (no in-cluster clobber) ------------
    integ = (
        await session.execute(
            select(IntegrationConfig).where(
                IntegrationConfig.tenant_id == provided_tenant.id
            )
        )
    ).scalar_one()
    assert integ.wazuh_url == _PROVIDED_API_URL
    assert integ.wazuh_indexer_url == _PROVIDED_INDEXER_URL

    # --- mint rows: external-siem-creds present, bootstrap absent -----------
    secret_rows = (
        await session.execute(
            select(TenantSecret).where(
                TenantSecret.tenant_id == provided_tenant.id
            )
        )
    ).scalars().all()
    purposes = {r.purpose for r in secret_rows}
    assert "external-siem-creds" in purposes
    assert "bootstrap" not in purposes
    assert {"llm", "adapter-token", "runs-worker-token"} <= purposes
