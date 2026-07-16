"""Response-playbook registry: declarative YAML files, fail-closed (issue #49).

Unlike the triage-policy registry (worker-side, env-scoped to one tenant), this
loads on the L1 API plane, which serves every tenant: ALL valid files load, and
tenant scoping is applied at match time against the completing run's tenant
identifiers (UUID + slug). There are no built-in response playbooks — an
install with no authored files dispatches nothing.

File loading (``SOCTALK_RESPONSE_PLAYBOOK_DIR``, ``*.yaml``/``*.yml``) fails
closed per file, and file-loaded playbooks default to ``status: shadow``
(intended actions audited, nothing enqueued) until the author explicitly sets
``status: active`` — the #44 activation gate, applied to this layer.
"""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path

import structlog

from soctalk.response.models import ResponsePlaybook

logger = structlog.get_logger()

_MAX_FILE_BYTES = 64 * 1024

RESPONSE_PLAYBOOK_DIR_ENV = "SOCTALK_RESPONSE_PLAYBOOK_DIR"


def parse_response_playbook_text(text: str) -> ResponsePlaybook:
    """Parse + fully validate one YAML response-playbook document. Raises on
    ANY problem (fail closed). Documents default to shadow unless they say
    ``status: active`` themselves."""
    import yaml

    if len(text.encode()) > _MAX_FILE_BYTES:
        raise ValueError(f"response playbook exceeds {_MAX_FILE_BYTES} bytes")
    raw = yaml.safe_load(text)
    if not isinstance(raw, dict):
        raise ValueError("response playbook file must be a mapping at its root")
    raw.setdefault("status", "shadow")
    return ResponsePlaybook.model_validate(raw)


def load_response_playbook_file(path: Path) -> ResponsePlaybook:
    if path.stat().st_size > _MAX_FILE_BYTES:
        raise ValueError(f"response playbook file exceeds {_MAX_FILE_BYTES} bytes")
    return parse_response_playbook_text(path.read_text())


@lru_cache(maxsize=1)
def _registry() -> tuple[ResponsePlaybook, ...]:
    """Validated file playbooks, priority-sorted (stable). Cached for process
    lifetime — an edit rolls out with the API deployment, which is the
    activation gate working as intended. Every load/skip is logged as the
    activation audit trail."""
    directory = os.getenv(RESPONSE_PLAYBOOK_DIR_ENV, "")
    if not directory:
        return ()
    root = Path(directory)
    if not root.is_dir():
        logger.warning("response_playbook_dir_missing", dir=directory)
        return ()
    loaded: list[ResponsePlaybook] = []
    seen_ids: set[str] = set()
    for path in sorted(root.glob("*.y*ml")):
        try:
            pb = load_response_playbook_file(path)
        except Exception as exc:  # noqa: BLE001 — a bad file must never dispatch
            logger.error(
                "response_playbook_file_rejected", file=str(path), error=str(exc)[:300]
            )
            continue
        if pb.id in seen_ids:
            logger.error(
                "response_playbook_file_rejected", file=str(path),
                playbook=pb.id, error="duplicate playbook id",
            )
            continue
        seen_ids.add(pb.id)
        logger.info(
            "response_playbook_loaded",
            file=str(path), playbook=pb.id, version=pb.version,
            status=pb.status, priority=pb.priority, tenant=pb.tenant,
        )
        loaded.append(pb)
    loaded.sort(key=lambda p: p.priority)
    return tuple(loaded)


def reset_registry_cache() -> None:
    """For tests that change SOCTALK_RESPONSE_PLAYBOOK_DIR at runtime."""
    _registry.cache_clear()


def all_response_playbooks() -> tuple[ResponsePlaybook, ...]:
    return _registry()


def _matches(
    pb: ResponsePlaybook,
    *,
    rule_groups: set[str],
    rule_ids: set[str],
    tenant_identifiers: frozenset[str],
) -> bool:
    if pb.tenant != "*" and pb.tenant not in tenant_identifiers:
        return False
    match = pb.applies_to
    if not match.rule_groups and not match.rule_ids:
        return True
    if match.rule_groups and rule_groups.intersection(
        g.lower() for g in match.rule_groups
    ):
        return True
    return bool(match.rule_ids) and bool(rule_ids.intersection(match.rule_ids))


def match_response_playbooks(
    *,
    rule_groups: set[str],
    rule_ids: set[str],
    tenant_identifiers: frozenset[str],
    status: str,
) -> list[ResponsePlaybook]:
    """Every matching playbook with the given status, priority-sorted. The
    caller enqueues for ``active`` and audits for ``shadow`` — matching itself
    is pure and never a security judgment."""
    return [
        pb
        for pb in _registry()
        if pb.status == status
        and _matches(
            pb,
            rule_groups=rule_groups,
            rule_ids=rule_ids,
            tenant_identifiers=tenant_identifiers,
        )
    ]
