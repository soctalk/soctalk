"""Tenant platform fingerprint and the roll decision (pure, no DB).

A soctalk-system upgrade changes the tenant chart and the tenant image tags
but never re-rendered existing tenants: they kept the previous adapter,
runs-worker and NetworkPolicies, silently. Renders now record the platform
fingerprint they used; a different current fingerprint marks the tenant
outdated, and (opt-in) the worker rolls it. These tests pin what changes the
fingerprint, and the ordering rule that keeps an outgoing api pod from rolling
tenants back during a rolling update.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from soctalk.core.provisioning import platform as pf
from soctalk.core.provisioning.controller import ControllerSettings

T0 = datetime(2026, 11, 2, 12, 0, 0, tzinfo=UTC)


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for k in (
        "SOCTALK_TENANT_ADAPTER_IMAGE_REPO", "SOCTALK_TENANT_ADAPTER_IMAGE_TAG",
        "SOCTALK_TENANT_RUNS_WORKER_IMAGE_REPO", "SOCTALK_TENANT_RUNS_WORKER_IMAGE_TAG",
        "SOCTALK_TENANT_LINUX_EP_IMAGE_REPO", "SOCTALK_TENANT_LINUX_EP_IMAGE_TAG",
        "SOCTALK_TENANT_BASE_DOMAIN", "SOCTALK_INGRESS_CLASS_NAME",
        "SOCTALK_ADAPTER_MIN_SEVERITY", "SOCTALK_TENANT_TRIAGE_POLICIES_DIR",
        "SOCTALK_TENANT_PLAYBOOKS_DIR", "SOCTALK_TENANT_ROLL_ON_UPGRADE",
        "SOCTALK_TENANT_ROLL_GRACE_SECONDS", "SOCTALK_TENANT_ROLL_BATCH_SIZE",
    ):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("SOCTALK_TENANT_ADAPTER_IMAGE_TAG", "1.0.0")
    monkeypatch.setenv("SOCTALK_TENANT_RUNS_WORKER_IMAGE_TAG", "1.0.0")
    monkeypatch.setenv("SOCTALK_TENANT_LINUX_EP_IMAGE_TAG", "1.0.0")


def _fp(settings=None) -> str:
    return pf.fingerprint(pf.tenant_platform_inputs(settings or ControllerSettings()))


# --- what changes the fingerprint -------------------------------------------


def test_fingerprint_is_stable_for_the_same_platform():
    assert _fp() == _fp()


@pytest.mark.parametrize(
    "env",
    [
        "SOCTALK_TENANT_ADAPTER_IMAGE_TAG",
        "SOCTALK_TENANT_RUNS_WORKER_IMAGE_TAG",
        "SOCTALK_TENANT_LINUX_EP_IMAGE_TAG",
        "SOCTALK_TENANT_ADAPTER_IMAGE_REPO",
        "SOCTALK_TENANT_BASE_DOMAIN",
        "SOCTALK_ADAPTER_MIN_SEVERITY",
    ],
)
def test_install_wide_render_inputs_change_the_fingerprint(monkeypatch, env):
    before = _fp()
    monkeypatch.setenv(env, "changed-value")
    assert _fp() != before


def test_chart_version_and_network_policy_switch_change_the_fingerprint():
    base = _fp(ControllerSettings(tenant_chart_version="0.2.1"))
    assert _fp(ControllerSettings(tenant_chart_version="0.2.2")) != base
    assert _fp(ControllerSettings(tenant_chart_version="0.2.1",
                                  tenant_network_policies_enabled=False)) != base


def test_local_chart_content_changes_the_fingerprint_at_the_same_version(tmp_path):
    """The api image bundles the tenant chart; a new build keeps
    ``version: 0.2.1`` while its templates change (a NetworkPolicy fix)."""
    chart = tmp_path / "soctalk-tenant"
    (chart / "templates").mkdir(parents=True)
    (chart / "Chart.yaml").write_text("version: 0.2.1\n")
    (chart / "templates" / "20-networkpolicies.yaml").write_text("kind: NetworkPolicy\n")
    s = ControllerSettings(tenant_chart_ref=str(chart), tenant_chart_version="")
    before = _fp(s)
    (chart / "templates" / "20-networkpolicies.yaml").write_text(
        "kind: NetworkPolicy\n---\nkind: NetworkPolicy\n"
    )
    assert _fp(s) != before


def _bundled_chart(root, *, generated: str, archive_mtime: int, template: str = "kind: Pod\n"):
    """A tenant chart as the api image bundles it after ``helm dependency
    build``: a Chart.lock stamped with the build time and subchart archives
    whose tar/gzip headers carry their own timestamps."""
    import gzip
    import io
    import tarfile

    chart = root / "soctalk-tenant"
    (chart / "charts").mkdir(parents=True, exist_ok=True)
    (chart / "Chart.yaml").write_text("version: 0.2.1\n")
    (chart / "Chart.lock").write_text(
        "dependencies:\n- name: wazuh\n  version: 0.2.1\n"
        f"digest: sha256:abc\ngenerated: \"{generated}\"\n"
    )
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w") as tar:
        for name, body in (("wazuh/Chart.yaml", "version: 0.2.1\n"),
                           ("wazuh/templates/pod.yaml", template)):
            data = body.encode()
            info = tarfile.TarInfo(name)
            info.size, info.mtime = len(data), archive_mtime
            tar.addfile(info, io.BytesIO(data))
    (chart / "charts" / "wazuh-0.2.1.tgz").write_bytes(
        gzip.compress(raw.getvalue(), mtime=archive_mtime)
    )
    return chart


def test_rebuilding_the_same_chart_keeps_the_digest(tmp_path):
    """Every api image build re-runs ``helm dependency build``, which
    restamps Chart.lock and repacks the subchart archives. Hashing those
    bytes marked every tenant outdated after any rebuild (and, with
    rollOnUpgrade on, re-rolled the whole fleet for nothing)."""
    a = _bundled_chart(tmp_path / "a", generated="2026-11-02T10:08:28Z", archive_mtime=1_000)
    b = _bundled_chart(tmp_path / "b", generated="2026-11-02T10:58:41Z", archive_mtime=2_000)
    assert pf._tree_digest(str(a)) == pf._tree_digest(str(b))


def test_a_real_change_inside_a_subchart_still_changes_the_digest(tmp_path):
    a = _bundled_chart(tmp_path / "a", generated="t1", archive_mtime=1_000)
    b = _bundled_chart(tmp_path / "b", generated="t1", archive_mtime=1_000,
                       template="kind: Pod\nspec: {}\n")
    assert pf._tree_digest(str(a)) != pf._tree_digest(str(b))


def test_oci_chart_ref_has_no_content_digest():
    inputs = pf.tenant_platform_inputs(
        ControllerSettings(tenant_chart_ref="oci://ghcr.io/x/soctalk-tenant")
    )
    assert inputs["chart_digest"] == ""


def test_triage_policy_directory_content_changes_the_fingerprint(monkeypatch, tmp_path):
    monkeypatch.setenv("SOCTALK_TENANT_TRIAGE_POLICIES_DIR", str(tmp_path))
    (tmp_path / "a.yaml").write_text("name: a\n")
    before = _fp()
    (tmp_path / "a.yaml").write_text("name: a2\n")
    assert _fp() != before


def test_values_overlay_changes_the_fingerprint():
    assert _fp(ControllerSettings(tenant_values_overlay={"adapter": {"x": 1}})) != _fp()


def test_fingerprint_image_matches_what_the_render_uses(monkeypatch):
    """The fingerprint and render_tenant_values resolve images through the
    same helpers, so they cannot disagree about a tenant's adapter."""
    from soctalk.core.provisioning.render import tenant_image_repo, tenant_image_tag

    monkeypatch.setenv("SOCTALK_TENANT_ADAPTER_IMAGE_TAG", "9.9.9-test")
    inputs = pf.tenant_platform_inputs(ControllerSettings())
    assert inputs["adapter_image"] == f"{tenant_image_repo('adapter')}:9.9.9-test"
    assert tenant_image_tag("adapter") == "9.9.9-test"


def test_render_record_carries_fingerprint_start_time_and_audit_fields():
    rec = pf.render_record(ControllerSettings())
    assert rec["platform_fingerprint"] == _fp()
    assert rec["platform_started_at"] == pf.PROCESS_STARTED_AT.isoformat()
    assert set(rec["platform"]) == {
        "adapter_image", "runs_worker_image", "chart_version", "chart_digest",
    }


@pytest.mark.parametrize(
    "details,expected",
    [
        (None, True),  # never rendered with a recorded platform
        ({}, True),
        ({"chart": "soctalk-tenant"}, True),  # rendered before recording existed
        ({"platform_fingerprint": "other"}, True),
        ({"platform_fingerprint": "CUR"}, False),
    ],
)
def test_is_outdated(details, expected):
    assert pf.is_outdated(details, "CUR") is expected


# --- roll settings ----------------------------------------------------------


def test_roll_is_off_by_default():
    assert pf.RollSettings.from_env() == pf.RollSettings()
    assert pf.RollSettings().enabled is False


def test_roll_settings_from_env(monkeypatch):
    monkeypatch.setenv("SOCTALK_TENANT_ROLL_ON_UPGRADE", "1")
    monkeypatch.setenv("SOCTALK_TENANT_ROLL_GRACE_SECONDS", "0")
    monkeypatch.setenv("SOCTALK_TENANT_ROLL_BATCH_SIZE", "0")
    s = pf.RollSettings.from_env()
    assert s.enabled is True
    assert s.grace_seconds == 0  # zero is honoured, not "unset"
    assert s.batch_size == 1  # clamped: a batch of 0 would never roll


def test_malformed_roll_numbers_fall_back(monkeypatch):
    monkeypatch.setenv("SOCTALK_TENANT_ROLL_GRACE_SECONDS", "soon")
    monkeypatch.setenv("SOCTALK_TENANT_ROLL_BATCH_SIZE", "many")
    s = pf.RollSettings.from_env()
    assert (s.grace_seconds, s.batch_size) == (120.0, 5)


# --- roll decision ----------------------------------------------------------


ON = pf.RollSettings(enabled=True, grace_seconds=60, batch_size=5)


def _render(fp: str, started: datetime | None) -> dict:
    d = {"chart": "soctalk-tenant", "platform_fingerprint": fp}
    if started is not None:
        d["platform_started_at"] = started.isoformat()
    return d


def _pick(ids, renders, busy=frozenset(), *, started=T0, now=T0 + timedelta(minutes=5),
          settings=ON, current="NEW"):
    return pf.select_tenants_to_roll(
        ids, renders, set(busy), current_fingerprint=current,
        process_started_at=started, now=now, settings=settings,
    )


def test_outdated_tenant_rendered_by_an_older_process_is_rolled():
    t = uuid4()
    assert _pick([t], {t: _render("OLD", T0 - timedelta(days=1))}) == [(t, "OLD")]


def test_tenant_already_on_the_current_platform_is_left_alone():
    t = uuid4()
    assert _pick([t], {t: _render("NEW", T0 - timedelta(days=1))}) == []


def test_outgoing_pod_never_rolls_back_a_newer_pods_render():
    """Rolling update: this (old) process started at T0; the incoming pod
    started later and already rendered the tenant with its platform."""
    t = uuid4()
    newer = _render("NEWER-PLATFORM", T0 + timedelta(seconds=30))
    assert _pick([t], {t: newer}, current="OLD-PLATFORM") == []


def test_a_process_may_supersede_its_own_render():
    """Same process, input changed in place (a remounted policies dir)."""
    t = uuid4()
    assert _pick([t], {t: _render("OLD", T0)}) == [(t, "OLD")]


def test_tenant_rendered_before_recording_existed_is_rolled_once():
    t = uuid4()
    assert _pick([t], {t: {"chart": "soctalk-tenant"}}) == [(t, None)]
    assert _pick([t], {t: None}) == [(t, None)]


def test_tenant_with_an_active_job_is_skipped():
    t = uuid4()
    assert _pick([t], {t: _render("OLD", None)}, busy={t}) == []


def test_nothing_rolls_during_the_startup_grace():
    t = uuid4()
    assert _pick([t], {t: _render("OLD", None)}, now=T0 + timedelta(seconds=59)) == []


def test_disabled_rolls_nothing():
    t = uuid4()
    assert _pick([t], {t: _render("OLD", None)}, settings=pf.RollSettings()) == []


def test_batch_size_caps_one_sweep_in_tenant_order():
    ids = [uuid4() for _ in range(8)]
    renders = {t: _render("OLD", None) for t in ids}
    picked = _pick(ids, renders, settings=pf.RollSettings(enabled=True, grace_seconds=0,
                                                          batch_size=3))
    assert [t for t, _ in picked] == ids[:3]


# --- dashboard flag -----------------------------------------------------------
# (The RLS behaviour against real roles is in test_tenant_platform_dashboard_rls.py.)


def _fake_mssp_sessionmaker(monkeypatch):
    import contextlib

    from soctalk.core.tenancy import db as tenancy_db

    @contextlib.asynccontextmanager
    async def _session():
        yield None

    monkeypatch.setattr(tenancy_db, "get_mssp_sessionmaker", lambda: _session)


async def test_dashboard_flags_only_tenants_with_a_release(monkeypatch):
    from soctalk.core.api import mssp_dashboard as dash

    a, b, c = uuid4(), uuid4(), uuid4()
    seen: list = []

    async def fake_renders(_db, ids):
        seen.extend(ids)
        return {a: _render("OLD", None), b: _render("CUR", None)}

    monkeypatch.setattr(pf, "latest_tenant_renders", fake_renders)
    monkeypatch.setattr(pf, "current_fingerprint", lambda: "CUR")
    _fake_mssp_sessionmaker(monkeypatch)
    rows = [
        {"tenant_id": str(a), "state": "active"},
        {"tenant_id": str(b), "state": "degraded"},
        {"tenant_id": str(c), "state": "provisioning"},
    ]
    flags = await dash._platform_outdated_by_tenant(rows)
    assert flags == {str(a): True, str(b): False}
    assert c not in seen


async def test_dashboard_flag_failure_is_not_fatal(monkeypatch):
    from soctalk.core.api import mssp_dashboard as dash

    def boom():
        raise RuntimeError("chart dir unreadable")

    monkeypatch.setattr(pf, "current_fingerprint", boom)
    _fake_mssp_sessionmaker(monkeypatch)
    rows = [{"tenant_id": str(uuid4()), "state": "active"}]
    assert await dash._platform_outdated_by_tenant(rows) == {}


# --- soctalk-system chart wiring ----------------------------------------------


def _api_env(*sets: str) -> dict[str, str]:
    import shutil
    import subprocess
    from pathlib import Path

    yaml = pytest.importorskip("yaml")
    helm = shutil.which("helm")
    if not helm:
        pytest.skip("helm not installed")
    chart = Path(__file__).resolve().parents[2] / "charts" / "soctalk-system"
    args = [helm, "template", "t", str(chart)]
    for s in sets:
        args += ["--set", s]
    out = subprocess.run(args, capture_output=True, text=True, check=True).stdout
    for doc in yaml.safe_load_all(out):
        if doc and doc.get("kind") == "Deployment" and doc["metadata"]["name"].endswith("-api"):
            containers = doc["spec"]["template"]["spec"]["containers"]
            api = next(c for c in containers if c["name"] == "api")
            return {e["name"]: e.get("value") for e in api.get("env", [])}
    raise AssertionError("api Deployment not rendered")


def test_chart_defaults_keep_the_roll_off():
    env = _api_env()
    assert env["SOCTALK_TENANT_ROLL_ON_UPGRADE"] == "0"
    assert env["SOCTALK_TENANT_ROLL_BATCH_SIZE"] == "5"
    assert env["SOCTALK_TENANT_ROLL_GRACE_SECONDS"] == "120"


def test_chart_renders_roll_settings_including_zero_grace():
    env = _api_env(
        "tenantProvisioning.rollOnUpgrade=true",
        "tenantProvisioning.rollGraceSeconds=0",
        "tenantProvisioning.rollBatchSize=2",
    )
    assert env["SOCTALK_TENANT_ROLL_ON_UPGRADE"] == "1"
    assert env["SOCTALK_TENANT_ROLL_GRACE_SECONDS"] == "0"
    assert env["SOCTALK_TENANT_ROLL_BATCH_SIZE"] == "2"


def test_chart_schema_rejects_an_empty_batch():
    import subprocess

    with pytest.raises(subprocess.CalledProcessError):
        _api_env("tenantProvisioning.rollBatchSize=0")
