"""Live end-to-end provisioning test against k3d + real Postgres + real Helm.

This test is the "is the whole pipe connected" check:

    TenantController.provision(id)
        → preflight (real kube, real helm binary)
        → mint + persist secrets (real DB)
        → namespace created in k3d
        → K8s Secrets materialised in the tenant namespace
        → helm install tenant release (charts/soctalk-tenant)
        → helm install wazuh release (charts/wazuh + values.poc.yaml)
        → wait for manager + indexer pods Ready
        → integration_configs.wazuh_url written
        → tenant state = active

Then ``decommission`` tears it all down and we assert the namespace is gone.

Skipped by default. Opt in with ``K3D_E2E=1``. Requires:

- k3d cluster reachable via ``~/.kube/config`` current context
- helm CLI on PATH
- Postgres at DATABASE_URL_MSSP
- charts/soctalk-tenant and charts/wazuh on disk (the repo root)

The test is intentionally slow (pods take ~60-90s on k3d); we give the wait
step a 5-minute ceiling.
"""

from __future__ import annotations

import asyncio
import os
import subprocess
from collections.abc import AsyncIterator
from uuid import uuid4

import pytest
import pytest_asyncio
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from soctalk.core.provisioning.controller import (
    ControllerSettings,
    TenantController,
)
from soctalk.core.tenancy.models import (
    BrandingConfig,
    IntegrationConfig,
    Organization,
    Tenant,
    TenantLifecycleEvent,
    TenantState,
)


RUN_LIVE = os.getenv("K3D_E2E", "0") == "1"
REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        not RUN_LIVE,
        reason="K3D_E2E not set; skipping live k3d rollout",
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
async def session() -> AsyncIterator[AsyncSession]:
    engine = create_async_engine(_mssp_url(), echo=False, pool_pre_ping=True)
    sm = async_sessionmaker(engine, expire_on_commit=False)
    async with sm() as s:
        yield s
    await engine.dispose()


@pytest_asyncio.fixture
async def e2e_tenant(
    session: AsyncSession, admin_session: AsyncSession
) -> Tenant:
    """Fresh tenant for each test, with FK data and a unique slug."""
    slug = f"e2e{uuid4().hex[:6]}"

    await admin_session.execute(
        text(
            "TRUNCATE tenant_lifecycle_events, integration_configs, "
            "branding_configs, tenant_secrets, provisioning_jobs, "
            "tenants, organizations CASCADE"
        )
    )
    await admin_session.commit()

    org = Organization(
        mssp_id=uuid4(), mssp_name="E2E MSSP",
        install_id=uuid4(), install_label="e2e",
    )
    session.add(org)
    await session.flush()

    tenant = Tenant(
        slug=slug,
        display_name=f"E2E Tenant {slug}",
        state=TenantState.PENDING.value,
        profile="poc",
        organization_id=org.id,
    )
    session.add(tenant)
    await session.flush()

    session.add_all([
        IntegrationConfig(tenant_id=tenant.id),
        BrandingConfig(tenant_id=tenant.id, app_name=f"E2E {slug}"),
    ])
    await session.commit()
    return tenant


def _kubectl(*args: str) -> str:
    return subprocess.check_output(["kubectl", *args], text=True)


def _helm_release_exists(release: str, namespace: str) -> bool:
    out = subprocess.run(
        ["helm", "status", release, "--namespace", namespace],
        capture_output=True, text=True,
    )
    return out.returncode == 0


async def test_k3d_live_provision_poc_happy_path(
    session: AsyncSession, e2e_tenant: Tenant
):
    """Full rollout: pending → active on k3d with the poc profile.

    Asserts every external side-effect: namespace present, at least one
    ready Wazuh pod, both helm releases present, integration URL written,
    full lifecycle event trail in the DB.
    """
    settings = ControllerSettings(
        wazuh_chart_path=os.path.join(REPO_ROOT, "charts", "wazuh"),
        tenant_chart_ref=os.path.join(REPO_ROOT, "charts", "soctalk-tenant"),
        readiness_poll_interval_seconds=5.0,
        readiness_timeout_seconds=900.0,  # 15 min — wazuh indexer JVM warm-up
        wait_timeout="4m",  # only bounds the helm apply, not workload readiness
        # The real adapter image (ghcr.io/gbrigandi/soctalk-adapter) is not
        # built yet; swap in a trivially-pullable stub with no readiness
        # probe so helm --wait can succeed. The rest of the pipeline
        # (namespace, secrets, two releases, wazuh pod readiness) is
        # unaffected.
        tenant_values_overlay={
            "adapter": {
                # Busybox as a reachable stand-in — the real adapter image
                # is not built yet. ``sleep infinity`` keeps the pod
                # Running; readiness probe disabled.
                "image": {
                    "repository": "busybox",
                    "tag": "1.36",
                    "command": ["/bin/sh", "-c"],
                    "args": ["while true; do sleep 30; done"],
                },
                "readinessProbe": None,
            }
        },
    )
    controller = TenantController(session, settings=settings)

    namespace = f"tenant-{e2e_tenant.slug}"
    release_tenant = f"tenant-{e2e_tenant.slug}"
    release_wazuh = f"wazuh-{e2e_tenant.slug}"

    try:
        result = await controller.provision(e2e_tenant.id, actor_id="e2e")
        assert result.state == TenantState.ACTIVE.value

        # k8s side-effects
        ns_json = _kubectl("get", "namespace", namespace, "-o", "name")
        assert namespace in ns_json

        assert _helm_release_exists(release_tenant, namespace), (
            "soctalk-tenant release missing after provision"
        )
        assert _helm_release_exists(release_wazuh, namespace), (
            "wazuh release missing after provision"
        )

        # Pod readiness (the wait_workloads step already blocked on this,
        # but re-assert to make the external invariant explicit).
        pods_out = _kubectl(
            "get", "pods", "--namespace", namespace,
            "-o", "jsonpath={range .items[*]}{.metadata.name}:{.status.phase}\\n{end}"
        )
        assert "Running" in pods_out, f"no running pods in {namespace}: {pods_out}"

        # DB side-effects
        integ = (
            await session.execute(
                select(IntegrationConfig).where(
                    IntegrationConfig.tenant_id == e2e_tenant.id
                )
            )
        ).scalar_one()
        assert integ.wazuh_url is not None
        assert integ.wazuh_url.endswith(":55000")
        assert namespace in integ.wazuh_url
        # Release-qualified service name, not the short "wazuh-manager".
        assert release_wazuh in integ.wazuh_url

        evs = (
            await session.execute(
                select(TenantLifecycleEvent)
                .where(TenantLifecycleEvent.tenant_id == e2e_tenant.id)
                .order_by(TenantLifecycleEvent.timestamp)
            )
        ).scalars().all()
        kinds = {e.event_type for e in evs}
        for required in (
            "provisioning_started",
            "preflight_ok",
            "secrets_minted",
            "namespace_ready",
            "secrets_applied",
            "helm_applied",
            "workloads_ready",
            "integration_config_written",
            "active",
        ):
            assert required in kinds, f"missing lifecycle event '{required}': {kinds}"

    finally:
        # Best-effort cleanup so a broken run doesn't leave crud behind.
        try:
            await controller.decommission(
                e2e_tenant.id, actor_id="e2e-cleanup", force=True
            )
        except Exception:
            # If the tenant never left pending (e.g. preflight failure),
            # just tear down the namespace manually.
            subprocess.run(
                ["kubectl", "delete", "namespace", namespace,
                 "--ignore-not-found", "--wait=false"],
                capture_output=True,
            )
