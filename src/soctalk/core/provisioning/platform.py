"""The install-wide inputs a tenant release is rendered with, and drift on them.

A tenant release is rendered from two kinds of input: the tenant's own
configuration (DB rows; every chart-affecting PATCH already queues a
``tenant.reconcile``) and the *platform*: the tenant chart, the tenant image
tags, and the other install-level settings the control plane is deployed
with. A ``soctalk-system`` upgrade changes only the platform, and nothing used
to notice: existing tenants kept the previous adapter, runs-worker and
NetworkPolicies until some unrelated PATCH happened to re-render them, and
nothing said so.

Each successful tenant render now records the platform fingerprint it used
(on its ``helm_applied`` lifecycle event, which is append-only and therefore
not raced by the adapter heartbeat's read-modify-write of
``tenants.runtime``). Comparing that with the running control plane's
fingerprint tells an operator which tenants are behind, and lets the worker
roll them when the install opts in (``SOCTALK_TENANT_ROLL_ON_UPGRADE``).

Ordering. During a rolling update the outgoing and incoming api pods both run
a worker. To keep an outgoing pod from rolling tenants *back* to its older
platform, a render is only ever superseded by a process that started no
earlier than the process that made it (``started_at`` is recorded next to the
fingerprint). Platform changes arrive by restarting pods, so a later start
means a newer platform, and ``helm rollback`` (new pods with the old spec)
rolls tenants back the same way.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any
from uuid import UUID

if TYPE_CHECKING:
    from soctalk.core.provisioning.controller import ControllerSettings

#: When this control-plane process started. Recorded on every render it makes
#: and used to order renders made by different processes (see module doc).
PROCESS_STARTED_AT: datetime = datetime.now(UTC)

#: ``details.chart`` of the tenant-chart ``helm_applied`` event (the wazuh
#: release emits its own ``helm_applied`` with ``chart: wazuh``).
TENANT_CHART_EVENT = "soctalk-tenant"

_FINGERPRINT_LEN = 16


def _tree_digest(path: str) -> str:
    """Content digest of a local chart or directory; "" for anything else
    (an OCI reference is pinned by its version instead).

    A local chart bundled in the api image keeps its ``Chart.yaml`` version
    across builds while its templates change, so the version alone cannot
    tell two platforms apart.
    """
    if not path:
        return ""
    p = Path(path)
    h = hashlib.sha256()
    try:
        if p.is_file():
            h.update(p.read_bytes())
            return h.hexdigest()[:_FINGERPRINT_LEN]
        if not p.is_dir():
            return ""
        for f in sorted(x for x in p.rglob("*") if x.is_file()):
            h.update(str(f.relative_to(p)).encode())
            h.update(b"\0")
            h.update(f.read_bytes())
            h.update(b"\0")
    except OSError:
        return "unreadable"
    return h.hexdigest()[:_FINGERPRINT_LEN]


def tenant_platform_inputs(settings: ControllerSettings) -> dict[str, str]:
    """Every install-wide input ``_step_helm_apply_tenant`` renders with.

    Keep in step with ``render_tenant_values`` and the helm call: an input
    missing here is a platform change that never marks tenants outdated.
    """
    from soctalk.core.provisioning.render import tenant_image_repo, tenant_image_tag

    overlay = settings.tenant_values_overlay or {}
    policies_dir = os.getenv("SOCTALK_TENANT_TRIAGE_POLICIES_DIR") or os.getenv(
        "SOCTALK_TENANT_PLAYBOOKS_DIR", ""
    )
    inputs = {
        "chart_ref": settings.tenant_chart_ref,
        "chart_version": settings.tenant_chart_version or "",
        "chart_digest": _tree_digest(settings.tenant_chart_ref),
        "network_policies_enabled": "1" if settings.tenant_network_policies_enabled else "0",
        "values_overlay": (
            hashlib.sha256(json.dumps(overlay, sort_keys=True, default=str).encode())
            .hexdigest()[:_FINGERPRINT_LEN]
            if overlay
            else ""
        ),
        "base_domain": os.getenv("SOCTALK_TENANT_BASE_DOMAIN", "").strip(),
        "ingress_class": os.getenv("SOCTALK_INGRESS_CLASS_NAME", ""),
        "adapter_min_severity_default": os.getenv("SOCTALK_ADAPTER_MIN_SEVERITY", ""),
        "triage_policies": _tree_digest(policies_dir),
    }
    for component in ("adapter", "runs_worker", "linux_ep"):
        inputs[f"{component}_image"] = (
            f"{tenant_image_repo(component)}:{tenant_image_tag(component)}"
        )
    return inputs


def fingerprint(inputs: dict[str, str]) -> str:
    return hashlib.sha256(
        json.dumps(inputs, sort_keys=True).encode()
    ).hexdigest()[:_FINGERPRINT_LEN]


def render_record(settings: ControllerSettings) -> dict[str, Any]:
    """What a render stores in its ``helm_applied`` event details."""
    inputs = tenant_platform_inputs(settings)
    return {
        "platform_fingerprint": fingerprint(inputs),
        "platform_started_at": PROCESS_STARTED_AT.isoformat(),
        # A few human-readable inputs for the audit trail; the fingerprint
        # covers all of them.
        "platform": {
            k: inputs[k]
            for k in ("adapter_image", "runs_worker_image", "chart_version", "chart_digest")
        },
    }


def _parse_ts(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        ts = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return ts if ts.tzinfo else ts.replace(tzinfo=UTC)


def is_outdated(render_details: dict[str, Any] | None, current_fingerprint: str) -> bool:
    """True when the tenant's last render used another platform, or predates
    platform recording (no fingerprint: assume behind)."""
    if not render_details:
        return True
    return render_details.get("platform_fingerprint") != current_fingerprint


@dataclass(frozen=True)
class RollSettings:
    """Automatic roll of outdated tenants by the provisioning worker."""

    enabled: bool = False
    #: Minimum process uptime before rolling, so an incoming pod lets the
    #: outgoing one finish terminating first.
    grace_seconds: float = 120.0
    #: At most this many reconciles queued per sweep (the worker runs one
    #: job at a time; new provisions should not queue behind the whole fleet).
    batch_size: int = 5

    @classmethod
    def from_env(cls) -> RollSettings:
        def _num(name: str, default: float) -> float:
            try:
                return max(0.0, float(os.getenv(name, "") or default))
            except ValueError:
                return default

        return cls(
            enabled=os.getenv("SOCTALK_TENANT_ROLL_ON_UPGRADE", "0").strip().lower()
            in {"1", "true", "yes", "on"},
            grace_seconds=_num("SOCTALK_TENANT_ROLL_GRACE_SECONDS", cls.grace_seconds),
            batch_size=max(1, int(_num("SOCTALK_TENANT_ROLL_BATCH_SIZE", cls.batch_size))),
        )


def select_tenants_to_roll(
    active_tenant_ids: list[UUID],
    latest_renders: dict[UUID, dict[str, Any] | None],
    busy_tenant_ids: set[UUID],
    *,
    current_fingerprint: str,
    process_started_at: datetime,
    now: datetime,
    settings: RollSettings,
) -> list[tuple[UUID, str | None]]:
    """Pure roll decision: ``(tenant_id, previous_fingerprint)`` pairs to queue.

    A tenant is rolled when its last tenant-chart render used another
    platform, that render was made by a process that started no later than
    this one (an outgoing pod never undoes an incoming pod's work), and no
    provisioning job is already active for it.
    """
    if not settings.enabled:
        return []
    if (now - process_started_at).total_seconds() < settings.grace_seconds:
        return []
    picked: list[tuple[UUID, str | None]] = []
    for tid in active_tenant_ids:
        if tid in busy_tenant_ids:
            continue
        details = latest_renders.get(tid)
        if not is_outdated(details, current_fingerprint):
            continue
        rendered_by = _parse_ts((details or {}).get("platform_started_at"))
        if rendered_by is not None and rendered_by > process_started_at:
            continue
        picked.append((tid, (details or {}).get("platform_fingerprint")))
        if len(picked) >= settings.batch_size:
            break
    return picked


async def latest_tenant_renders(
    session: Any, tenant_ids: list[UUID]
) -> dict[UUID, dict[str, Any] | None]:
    """Details of each tenant's most recent tenant-chart ``helm_applied``
    event (None when it has never been rendered). One indexed query
    (``ix_tle_tenant_ts``) for the whole set."""
    from sqlalchemy import text

    out: dict[UUID, dict[str, Any] | None] = {tid: None for tid in tenant_ids}
    if not tenant_ids:
        return out
    rows = (
        await session.execute(
            text(
                """
                SELECT DISTINCT ON (e.tenant_id) e.tenant_id, e.details
                FROM tenant_lifecycle_events e
                WHERE e.tenant_id = ANY(:ids)
                  AND e.event_type = 'helm_applied'
                  AND e.details->>'chart' = :chart
                ORDER BY e.tenant_id, e.timestamp DESC
                """
            ),
            {"ids": [str(t) for t in tenant_ids], "chart": TENANT_CHART_EVENT},
        )
    ).all()
    for tid, details in rows:
        key = tid if isinstance(tid, UUID) else UUID(str(tid))
        out[key] = details if isinstance(details, dict) else None
    return out


def current_fingerprint() -> str:
    """Fingerprint of the platform this process renders tenants with."""
    from soctalk.core.provisioning.controller import ControllerSettings

    return fingerprint(tenant_platform_inputs(ControllerSettings.from_env()))
