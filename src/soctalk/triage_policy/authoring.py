"""Authored playbooks: DB-backed shadow/draft playbooks created via the API (#44 follow-on).

Authoring is strictly SHADOW/DRAFT + export-to-YAML — authored playbooks NEVER govern the
worker directly. Active enforcement stays on the vetted file -> git -> worker-rollout path.

Every authored definition is validated with the SAME ``TriagePolicy`` model and the same
fail-closed restrictions as file playbooks (shadow-only status, priority floor, no
``deterministic_disposition``, no built-in id collision, ``extra="forbid"``, sandboxed
guardrail conditions), PLUS stricter reference checks: unknown required steps / legal
actions / decision modules are REJECTED at author time rather than warned-and-ignored at
runtime. The store is an append-only revision log; the current state of a playbook is its
highest revision.
"""

from __future__ import annotations

import json
import re
from typing import Any
from uuid import UUID, uuid4

import yaml
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from soctalk.models.enums import SupervisorAction
from soctalk.triage_policy.models import KNOWN_STEP_NODES, TriagePolicy
from soctalk.triage_policy.registry import BUILTIN_TRIAGE_POLICIES, FILE_PRIORITY_FLOOR

# Only the authorization engine exists as a decision module today (registry.py).
KNOWN_DECISION_MODULES = frozenset({"authorization_engine"})
_VALID_ACTIONS = frozenset(a.value for a in SupervisorAction)
# The only phases the gate reads (soctalk.triage_policy.gate); an unknown phase key would
# fail open (unconstrained) if promoted, so reject it at author time.
KNOWN_PHASES = frozenset({"triage", "decide"})
# Authoring lifecycle statuses (the DB row's status; the stored DEFINITION is always
# shadow). 'active' is deliberately absent — authored playbooks never govern.
AUTHORED_STATUSES = frozenset({"draft", "shadow"})
# A playbook id is a path segment (PUT/DELETE/export address by it) and a YAML filename
# stem on rollout — constrain it to a safe slug.
_SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,127}$")
# Mirror the file-playbook cap so an authored definition can't bloat the row / a run.
_MAX_AUTHORED_BYTES = 64 * 1024


class TriagePolicyValidationError(ValueError):
    """An authored playbook definition failed validation (author-facing message)."""


class TriagePolicyConflictError(Exception):
    """A concurrent create/edit collided on the revision number — retry."""


def validate_authored(raw: dict[str, Any]) -> TriagePolicy:
    """Validate an authored playbook definition fail-closed. Returns the parsed TriagePolicy
    (status forced to 'shadow' — authored playbooks are never active). Raises
    ``TriagePolicyValidationError`` with an author-facing message on any problem."""
    if not isinstance(raw, dict):
        raise TriagePolicyValidationError("playbook must be a mapping")
    if len(json.dumps(raw, default=str)) > _MAX_AUTHORED_BYTES:
        raise TriagePolicyValidationError(f"playbook definition exceeds {_MAX_AUTHORED_BYTES} bytes")
    # The stored definition is always shadow — an authored playbook cannot declare itself
    # active. (The DB row carries the draft/shadow lifecycle separately.)
    definition = {**raw, "status": "shadow"}
    try:
        pb = TriagePolicy.model_validate(definition)
    except Exception as exc:  # noqa: BLE001 — surface pydantic errors as author feedback
        raise TriagePolicyValidationError(str(exc)) from exc

    if not _SLUG_RE.match(pb.id):
        raise TriagePolicyValidationError(
            "id must be a slug: lowercase letters, digits, hyphens (^[a-z0-9][a-z0-9-]{0,127}$)"
        )
    bad_phases = [p for p in pb.legal_actions if p not in KNOWN_PHASES]
    if bad_phases:
        raise TriagePolicyValidationError(
            f"unknown legal_actions phases (only triage|decide): {', '.join(bad_phases)}"
        )
    if pb.priority < FILE_PRIORITY_FLOOR:
        raise TriagePolicyValidationError(
            f"priority must be >= {FILE_PRIORITY_FLOOR} — built-in protections may not be "
            f"outranked (got {pb.priority})"
        )
    if pb.deterministic_disposition is not None:
        raise TriagePolicyValidationError(
            "deterministic_disposition is a built-in-only capability and cannot be authored"
        )
    if any(pb.id == b.id for b in BUILTIN_TRIAGE_POLICIES):
        raise TriagePolicyValidationError(f"id '{pb.id}' collides with a built-in playbook")

    bad_steps = [s for s in pb.required_steps if s not in KNOWN_STEP_NODES]
    if bad_steps:
        raise TriagePolicyValidationError(f"unknown required_steps: {', '.join(bad_steps)}")
    bad_modules = [m for m in pb.decision_modules if m not in KNOWN_DECISION_MODULES]
    if bad_modules:
        raise TriagePolicyValidationError(f"unknown decision_modules: {', '.join(bad_modules)}")
    for phase, actions in pb.legal_actions.items():
        bad = [a for a in actions if a not in _VALID_ACTIONS]
        if bad:
            raise TriagePolicyValidationError(
                f"unknown legal_actions in phase '{phase}': {', '.join(bad)}"
            )
    return pb


# --------------------------------------------------------------------------- store


async def _latest_revision(
    db: AsyncSession, *, tenant_id: UUID, playbook_id: str
) -> dict[str, Any] | None:
    row = (await db.execute(
        text(
            "SELECT revision, status, definition, created_by, created_at "
            "FROM authored_playbook_revisions "
            "WHERE tenant_id = :t AND playbook_id = :p "
            "ORDER BY revision DESC LIMIT 1"
        ),
        {"t": str(tenant_id), "p": playbook_id},
    )).mappings().first()
    return dict(row) if row else None


async def list_authored(db: AsyncSession, *, tenant_id: UUID) -> list[dict[str, Any]]:
    """Latest revision of each non-retired authored playbook for the tenant."""
    rows = (await db.execute(
        text(
            """
            SELECT DISTINCT ON (playbook_id)
                   playbook_id, revision, status, definition, created_by, created_at
            FROM authored_playbook_revisions
            WHERE tenant_id = :t
            ORDER BY playbook_id, revision DESC
            """
        ),
        {"t": str(tenant_id)},
    )).mappings().all()
    return [dict(r) for r in rows if r["status"] != "retired"]


async def get_authored(
    db: AsyncSession, *, tenant_id: UUID, playbook_id: str
) -> dict[str, Any] | None:
    latest = await _latest_revision(db, tenant_id=tenant_id, playbook_id=playbook_id)
    if latest is None or latest["status"] == "retired":
        return None
    return latest


async def _insert_revision(
    db: AsyncSession, *, tenant_id: UUID, playbook_id: str, revision: int,
    status: str, definition: dict[str, Any], created_by: UUID | None,
) -> None:
    await db.execute(
        text(
            "INSERT INTO authored_playbook_revisions "
            "(id, tenant_id, playbook_id, revision, status, definition, created_by) "
            "VALUES (:id, :t, :p, :rev, :st, CAST(:def AS JSONB), :by)"
        ),
        {"id": str(uuid4()), "t": str(tenant_id), "p": playbook_id, "rev": revision,
         "st": status, "def": _json(definition),
         "by": str(created_by) if created_by else None},
    )


async def upsert_authored(
    db: AsyncSession, *, tenant_id: UUID, definition: dict[str, Any],
    status: str = "shadow", created_by: UUID | None = None,
) -> dict[str, Any]:
    """Create or edit an authored playbook (appends a new revision). Validates fail-closed.
    ``status`` is the authoring lifecycle (draft|shadow). Raises TriagePolicyValidationError."""
    if status not in AUTHORED_STATUSES:
        raise TriagePolicyValidationError("status must be 'draft' or 'shadow'")
    # Force the concrete tenant: a tenant-authored playbook must never store/export
    # tenant="*" (which the file registry treats as applies-everywhere).
    pb = validate_authored({**definition, "tenant": str(tenant_id)})
    latest = await _latest_revision(db, tenant_id=tenant_id, playbook_id=pb.id)
    revision = (latest["revision"] + 1) if latest else 1
    stored = pb.model_dump()
    try:
        await _insert_revision(
            db, tenant_id=tenant_id, playbook_id=pb.id, revision=revision,
            status=status, definition=stored, created_by=created_by,
        )
        await db.flush()  # surface a duplicate-revision race here, not at commit
    except IntegrityError as exc:
        raise TriagePolicyConflictError(
            "a concurrent edit created a newer revision — reload and retry"
        ) from exc
    return {"playbook_id": pb.id, "revision": revision, "status": status, "definition": stored}


async def retire_authored(
    db: AsyncSession, *, tenant_id: UUID, playbook_id: str, retired_by: UUID | None = None,
) -> bool:
    """Soft-delete: append a 'retired' revision keeping the definition for history.
    Returns False if the playbook doesn't exist or is already retired."""
    latest = await _latest_revision(db, tenant_id=tenant_id, playbook_id=playbook_id)
    if latest is None or latest["status"] == "retired":
        return False
    await _insert_revision(
        db, tenant_id=tenant_id, playbook_id=playbook_id, revision=latest["revision"] + 1,
        status="retired", definition=dict(latest["definition"]), created_by=retired_by,
    )
    return True


async def set_authored_status(
    db: AsyncSession, *, tenant_id: UUID, playbook_id: str, status: str,
    created_by: UUID | None = None,
) -> dict[str, Any] | None:
    """Activate ('active') or deactivate ('shadow') an authored playbook by appending a
    status revision. Re-validates the stored definition fail-closed before it can govern
    (Codex: old rows must re-clear the validator). Returns the new state, or None if the
    playbook doesn't exist / is retired."""
    if status not in ("active", "shadow"):
        raise TriagePolicyValidationError("status must be 'active' or 'shadow'")
    latest = await _latest_revision(db, tenant_id=tenant_id, playbook_id=playbook_id)
    if latest is None or latest["status"] == "retired":
        return None
    definition = dict(latest["definition"])
    # Gate ACTIVATION on a fresh fail-closed validation (a row valid at author time can go
    # invalid after a code change, e.g. a new built-in id collision). Deactivation must NOT
    # revalidate — turning a now-invalid playbook OFF must always succeed.
    if status == "active":
        validate_authored(definition)
    revision = latest["revision"] + 1
    try:
        await _insert_revision(
            db, tenant_id=tenant_id, playbook_id=playbook_id, revision=revision,
            status=status, definition=definition, created_by=created_by,
        )
        await db.flush()
    except IntegrityError as exc:
        raise TriagePolicyConflictError("a concurrent edit collided — reload and retry") from exc
    return {"playbook_id": playbook_id, "revision": revision, "status": status,
            "definition": definition}


async def render_active_authored_values(
    db: AsyncSession, *, tenant_id: UUID
) -> dict[str, str]:
    """Active authored playbooks as ``{configmap_filename: yaml_text}`` for chart delivery.

    FAIL-CLOSED: each active row is rendered to YAML (status forced 'active', tenant pinned)
    and re-validated with ``parse_triage_policy_text`` — the worker's own loader. Raises on ANY
    invalid/oversized row so the reconcile fails loudly instead of silently under-enforcing
    what the UI reports as active."""
    from soctalk.triage_policy.registry import parse_triage_policy_text

    rows = (await db.execute(
        text(
            """
            SELECT DISTINCT ON (playbook_id) playbook_id, revision, status, definition
            FROM authored_playbook_revisions
            WHERE tenant_id = :t
            ORDER BY playbook_id, revision DESC
            """
        ),
        {"t": str(tenant_id)},
    )).mappings().all()

    out: dict[str, str] = {}
    for r in rows:
        if r["status"] != "active":
            continue
        # Fail closed with the FULL authored validator (built-in id collision + authored
        # rules) AND the worker's own file parser on the exact bytes shipped — so an active
        # row the worker would reject/weaken fails the reconcile here instead of silently
        # shipping and under-enforcing.
        validate_authored(dict(r["definition"]))
        doc = {**dict(r["definition"]), "status": "active", "tenant": str(tenant_id)}
        yaml_text = yaml.safe_dump(doc, sort_keys=True, default_flow_style=False)
        parse_triage_policy_text(yaml_text)
        out[f"authored-{r['playbook_id']}.yaml"] = yaml_text
    return out


def to_yaml(definition: dict[str, Any]) -> str:
    """Export an authored definition as YAML for git / worker rollout. The author sets
    ``status: active`` in git when promoting — export keeps it shadow."""
    return yaml.safe_dump(definition, sort_keys=True, default_flow_style=False)


def _json(obj: Any) -> str:
    import json
    return json.dumps(obj, separators=(",", ":"), sort_keys=True, default=str)
