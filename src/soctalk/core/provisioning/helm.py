"""Helm subprocess wrapper.

V1 drives Helm via the CLI (``helm install``, ``helm upgrade``, ``helm uninstall``)
rather than embedding the Go SDK: simpler and async-friendly. The CLI is
expected on PATH in the SocTalk controller image.
"""

from __future__ import annotations

import asyncio
import json
import os
import shlex
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import structlog
import yaml

logger = structlog.get_logger()


class HelmError(RuntimeError):
    pass


@dataclass
class HelmResult:
    returncode: int
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        return self.returncode == 0


async def _run_helm(args: list[str], timeout: float = 600.0) -> HelmResult:
    cmd = ["helm", *args]
    logger.info("helm_invoke", cmd=" ".join(shlex.quote(a) for a in cmd))
    proc = await asyncio.create_subprocess_exec(
        *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
    )
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        raise HelmError(f"helm command timed out after {timeout}s")
    return HelmResult(
        returncode=proc.returncode or 0,
        stdout=stdout.decode(),
        stderr=stderr.decode(),
    )


async def helm_install_tenant(
    release_name: str,
    namespace: str,
    chart_ref: str,
    values: dict[str, Any],
    *,
    wait: bool = True,
    timeout: str = "15m",
) -> HelmResult:
    """Run ``helm upgrade --install`` for a tenant release.

    ``chart_ref`` may be a local path (dev) or an OCI reference like
    ``oci://ghcr.io/gbrigandi/charts/soctalk-tenant`` with a ``--version`` arg
    added by the caller.
    """
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".yaml", delete=False
    ) as vf:
        yaml.safe_dump(values, vf)
        values_path = vf.name
    try:
        # ``--create-namespace`` intentionally omitted: the controller's
        # ``_step_ensure_namespace`` creates ``tenant-<slug>`` first with
        # the labels the chart's ValidatingAdmissionPolicy enforces.
        # Letting Helm CREATE it would race the controller and Helm's
        # request payload doesn't carry our labels, so the VAP would
        # deny it.
        args = [
            "upgrade",
            "--install",
            release_name,
            chart_ref,
            "--namespace",
            namespace,
            "-f",
            values_path,
        ]
        if wait:
            args.extend(["--wait", "--timeout", timeout])
        result = await _run_helm(args, timeout=900.0)
        if not result.ok:
            raise HelmError(
                f"helm install {release_name} failed: {result.stderr}"
            )
        return result
    finally:
        Path(values_path).unlink(missing_ok=True)


async def helm_install_wazuh(
    release_name: str,
    namespace: str,
    chart_path: str,
    *,
    profile: str,
    per_tenant_values: dict[str, Any],
    wait: bool = True,
    timeout: str = "15m",
) -> HelmResult:
    """Install the per-tenant Wazuh release.

    Layers three values sources via ``-f`` flags in order, with Helm
    applying later files on top of earlier ones:

        1. ``<chart_path>/values.yaml``           (chart defaults)
        2. ``<chart_path>/values.<profile>.yaml`` (profile overrides)
        3. <tempfile from per_tenant_values>      (minted creds, tenant id)

    The chart is a local path here (not OCI), because wazuh ships in-repo
    today. When we publish it we'll swap to an OCI ref like the tenant
    chart.
    """
    if profile not in ("poc", "persistent"):
        raise HelmError(f"unsupported wazuh profile: {profile}")

    profile_values_path = Path(chart_path) / f"values.{profile}.yaml"
    if not profile_values_path.exists():
        raise HelmError(
            f"profile values file missing: {profile_values_path}"
        )

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".yaml", delete=False
    ) as vf:
        yaml.safe_dump(per_tenant_values, vf)
        tenant_values_path = vf.name
    try:
        args = [
            "upgrade",
            "--install",
            release_name,
            chart_path,
            "--namespace",
            namespace,
            "-f",
            str(profile_values_path),
            "-f",
            tenant_values_path,
        ]
        if wait:
            args.extend(["--wait", "--timeout", timeout])
        result = await _run_helm(args, timeout=900.0)
        if not result.ok:
            raise HelmError(
                f"helm install {release_name} (wazuh) failed: {result.stderr}"
            )
        return result
    finally:
        Path(tenant_values_path).unlink(missing_ok=True)


async def helm_version() -> HelmResult:
    """Probe the helm binary is present and runnable."""
    result = await _run_helm(["version", "--short"], timeout=30.0)
    if not result.ok:
        raise HelmError(f"helm version failed: {result.stderr}")
    return result


async def helm_uninstall(
    release_name: str, namespace: str, *, keep_history: bool = False
) -> HelmResult:
    args = ["uninstall", release_name, "--namespace", namespace]
    if keep_history:
        args.append("--keep-history")
    return await _run_helm(args, timeout=600.0)


async def helm_status(release_name: str, namespace: str) -> dict[str, Any]:
    args = ["status", release_name, "--namespace", namespace, "-o", "json"]
    result = await _run_helm(args, timeout=60.0)
    if not result.ok:
        raise HelmError(f"helm status failed: {result.stderr}")
    return json.loads(result.stdout)


async def helm_list(namespace: str) -> list[dict[str, Any]]:
    args = ["list", "--namespace", namespace, "-o", "json"]
    result = await _run_helm(args, timeout=60.0)
    if not result.ok:
        raise HelmError(f"helm list failed: {result.stderr}")
    return json.loads(result.stdout)
