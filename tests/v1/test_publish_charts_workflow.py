"""Released chart versions must be immutable; main ships pre-releases.

``publish-images.yml`` ran on every push to main and ``helm push``ed all four
charts at their ``Chart.yaml`` version, on the belief that re-pushing an
existing version is a no-op. On an OCI registry it overwrites the tag: the
released ``soctalk-system 0.2.1`` kept changing digest with every merge and
carried unreleased templates, so ``helm upgrade --version 0.2.1`` was not
reproducible. The demo (``deploy-demo.yml``) silently depended on that
overwrite to track main.

These tests run the workflows' real ``run:`` scripts with a stub ``helm`` on
PATH that models the registry (which versions exist, what gets pushed).
"""

from __future__ import annotations

import os
import re
import stat
import subprocess
from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml")

REPO = Path(__file__).resolve().parents[2]
CHARTS = ("soctalk-system", "soctalk-tenant", "wazuh", "linux-ep")
SHA = "9892f5e8e5d1c0ffee0000000000000000000000"
PRE = "0.2.1-main.g9892f5e"

_STUB_HELM = r'''#!/usr/bin/env python3
"""Stub helm: models an OCI chart registry in $STUB_REGISTRY (one name:version
per line) and logs pushes to $STUB_PUSHES."""
import os, re, sys
from pathlib import Path
reg = Path(os.environ["STUB_REGISTRY"]); pushes = Path(os.environ["STUB_PUSHES"])
a = sys.argv[1:]
def opt(name):
    return a[a.index(name) + 1] if name in a else None
def chart_meta(d):
    text = (Path(d) / "Chart.yaml").read_text()
    return (re.search(r"^name:\s*(\S+)", text, re.M).group(1),
            re.search(r"^version:\s*(\S+)", text, re.M).group(1))
if a[:2] == ["dependency", "update"] or a[:2] == ["registry", "login"]:
    sys.exit(0)
if a and a[0] == "package":
    name, version = chart_meta(a[1])
    version = opt("--version") or version
    dest = Path(opt("--destination") or ".")
    dest.mkdir(parents=True, exist_ok=True)
    (dest / f"{name}-{version}.tgz").write_text(f"{name}:{version}\n")
    sys.exit(0)
if a[:2] == ["show", "chart"]:
    if os.environ.get("STUB_SHOW_ERROR"):
        print("Error: unexpected status from GET request: 503 Service Unavailable", file=sys.stderr)
        sys.exit(1)
    name = a[2].rstrip("/").rsplit("/", 1)[-1]
    want = f"{name}:{opt('--version')}"
    have = reg.read_text().split() if reg.exists() else []
    if want in have:
        print(f"name: {name}"); sys.exit(0)
    print(f"Error: {a[2]}:{opt('--version')}: not found", file=sys.stderr); sys.exit(1)
if a and a[0] == "push":
    ref = Path(a[1]).read_text().strip()
    with reg.open("a") as f: f.write(ref + "\n")
    with pushes.open("a") as f: f.write(ref + "\n")
    sys.exit(0)
sys.exit(0)
'''


def _step_script(workflow: str, job: str, step_name: str) -> dict:
    wf = yaml.safe_load((REPO / ".github" / "workflows" / workflow).read_text())
    for step in wf["jobs"][job]["steps"]:
        if step.get("name") == step_name:
            return step
    raise AssertionError(f"{workflow}: no step {step_name!r} in job {job!r}")


def _neutralise_expressions(script: str, values: dict[str, str]) -> str:
    """Replace ``${{ expr }}`` the way Actions would, from ``values`` (empty
    string for anything not given)."""
    return re.sub(
        r"\$\{\{\s*(.*?)\s*\}\}", lambda m: values.get(m.group(1), ""), script
    )


def _sandbox(tmp_path: Path, released: list[str]) -> dict[str, str]:
    for name in CHARTS:
        d = tmp_path / "charts" / name
        d.mkdir(parents=True)
        (d / "Chart.yaml").write_text(f"apiVersion: v2\nname: {name}\nversion: 0.2.1\n")
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    helm = bin_dir / "helm"
    helm.write_text(_STUB_HELM)
    helm.chmod(helm.stat().st_mode | stat.S_IXUSR)
    (tmp_path / "registry").write_text("".join(f"{r}\n" for r in released))
    return {
        **os.environ,
        "PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}",
        "STUB_REGISTRY": str(tmp_path / "registry"),
        "STUB_PUSHES": str(tmp_path / "pushes"),
        "GITHUB_SHA": SHA,
        "RUNNER_TEMP": str(tmp_path / "runner-temp"),
    }


def _run_publish(tmp_path: Path, released: list[str], **extra_env: str) -> list[str]:
    env = _sandbox(tmp_path, released)
    env.update(extra_env)
    step = _step_script("publish-images.yml", "charts", "Package and push charts")
    script = _neutralise_expressions(step["run"], {"github.sha": SHA})
    # Keep the old hard-coded output dir inside the sandbox too.
    script = script.replace("/tmp/helm-out", str(tmp_path / "helm-out"))
    env.update({k: _neutralise_expressions(str(v), {"github.sha": SHA})
                for k, v in (step.get("env") or {}).items()})
    (tmp_path / "runner-temp").mkdir(exist_ok=True)
    subprocess.run(["bash", "-c", script], cwd=tmp_path, env=env, check=True,
                   capture_output=True, text=True)
    pushes = tmp_path / "pushes"
    return pushes.read_text().split() if pushes.exists() else []


def test_main_never_overwrites_a_released_chart_version(tmp_path):
    pushed = _run_publish(tmp_path, released=[f"{c}:0.2.1" for c in CHARTS])
    assert not [p for p in pushed if p.endswith(":0.2.1")], pushed


def test_main_publishes_a_per_commit_prerelease_of_every_chart(tmp_path):
    pushed = _run_publish(tmp_path, released=[f"{c}:0.2.1" for c in CHARTS])
    assert sorted(pushed) == sorted(f"{c}:{PRE}" for c in CHARTS)


def test_a_new_version_is_still_published_on_its_first_main_push(tmp_path):
    """Step 1 of cut-k8s-release: the version-bump commit's push publishes
    X.Y.Z when it does not exist yet."""
    pushed = _run_publish(tmp_path, released=[])
    assert sorted(pushed) == sorted([f"{c}:0.2.1" for c in CHARTS]
                                    + [f"{c}:{PRE}" for c in CHARTS])


def test_a_registry_error_fails_the_job_instead_of_overwriting(tmp_path):
    """Only "not found" means "not published". Any other lookup failure must
    not be read as absent, or a transient error would overwrite a release."""
    with pytest.raises(subprocess.CalledProcessError):
        _run_publish(tmp_path, released=[f"{c}:0.2.1" for c in CHARTS],
                     STUB_SHOW_ERROR="1")
    assert not (tmp_path / "pushes").exists()


def _resolve_demo_version(tmp_path: Path, chart_version_input: str = "",
                          key: str = "version") -> str:
    for name in CHARTS:
        d = tmp_path / "charts" / name
        d.mkdir(parents=True, exist_ok=True)
        (d / "Chart.yaml").write_text(f"apiVersion: v2\nname: {name}\nversion: 0.2.1\n")
    step = _step_script("deploy-demo.yml", "deploy", "Resolve chart version")
    exprs = {
        "inputs.chart_version": chart_version_input,
        "github.event.workflow_run.head_sha || github.sha": SHA,
        "github.event.workflow_run.head_sha": SHA,
        "github.sha": SHA,
    }
    env = {**os.environ, "GITHUB_OUTPUT": str(tmp_path / "out")}
    env.update({k: _neutralise_expressions(str(v), exprs)
                for k, v in (step.get("env") or {}).items()})
    subprocess.run(["bash", "-c", _neutralise_expressions(step["run"], exprs)],
                   cwd=tmp_path, env=env, check=True, capture_output=True, text=True)
    out = dict(line.split("=", 1) for line in (tmp_path / "out").read_text().splitlines())
    return out[key]


def test_demo_deploys_the_prerelease_of_the_commit_that_was_published(tmp_path):
    assert _resolve_demo_version(tmp_path) == PRE


def test_demo_manual_version_input_still_wins(tmp_path):
    assert _resolve_demo_version(tmp_path, "0.2.1") == "0.2.1"


def test_demo_tenants_use_the_same_chart_version_as_the_system_chart():
    """The api provisions tenants from oci://.../soctalk-tenant at
    tenantProvisioning.tenantChartVersion; on demo that must be the same
    main pre-release, or demo tenants freeze on the released chart."""
    step = _step_script("deploy-demo.yml", "deploy", "helm upgrade --install soctalk-system")
    assert "tenantProvisioning.tenantChartVersion" in step["run"]


def test_demo_tenant_chart_follows_the_same_commit(tmp_path):
    assert _resolve_demo_version(tmp_path, key="tenant_version") == PRE


def test_demo_manual_release_keeps_the_tenant_chart_default(tmp_path):
    assert _resolve_demo_version(tmp_path, "0.2.1", key="tenant_version") == ""
