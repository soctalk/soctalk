"""Authored response playbooks: DB-backed playbooks created via the API (#49 phase 2).

Mirrors ``soctalk.triage_policy.authoring`` — an append-only revision log, latest
revision per (tenant, id), fail-closed validation with the SAME ``ResponsePlaybook``
model as file playbooks. The difference: an authored response playbook CAN be genuinely
``active``. The response dispatcher runs on L1 with DB access, so it reads active/shadow
authored rows live at complete_run time — activation is a runtime flip, no deploy.

Every definition is validated fail-closed (``extra="forbid"``, vetted capability names,
on_close tier restriction, sandboxed conditions) PLUS the tenant is pinned to the concrete
tenant id (never ``"*"``) so a tenant-authored playbook can only ever govern its own tenant.
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

from soctalk.response.models import ResponsePlaybook

# DB-row lifecycle. 'active' governs live (L1 dispatches from the DB); 'shadow' is
# audited-not-dispatched; 'draft' is WIP; 'retired' is a soft delete.
AUTHORED_STATUSES = frozenset({"draft", "shadow", "active"})
_SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,127}$")
_MAX_AUTHORED_BYTES = 64 * 1024


class ResponsePlaybookValidationError(ValueError):
    """An authored response playbook failed validation (author-facing message)."""


class ResponsePlaybookConflictError(Exception):
    """A concurrent create/edit collided on the revision number — retry."""


def validate_authored(raw: dict[str, Any]) -> ResponsePlaybook:
    """Validate an authored response playbook fail-closed. Returns the parsed
    ``ResponsePlaybook``. Raises ``ResponsePlaybookValidationError`` on any problem."""
    if not isinstance(raw, dict):
        raise ResponsePlaybookValidationError("response playbook must be a mapping")
    if len(json.dumps(raw, default=str)) > _MAX_AUTHORED_BYTES:
        raise ResponsePlaybookValidationError(
            f"definition exceeds {_MAX_AUTHORED_BYTES} bytes"
        )
    # The stored DEFINITION is always shadow (the safe default for a file rollout /
    # export); the DB ROW's status column carries the draft/shadow/active lifecycle
    # separately, and live dispatch keys on the row status, never on this field.
    # Without this, an exported shadow playbook would carry status:active and
    # activate on a file rollout (Codex ph2 incr3 finding 3).
    try:
        pb = ResponsePlaybook.model_validate({**raw, "status": "shadow"})
    except Exception as exc:  # noqa: BLE001 — surface pydantic errors as author feedback
        raise ResponsePlaybookValidationError(str(exc)) from exc
    if not _SLUG_RE.match(pb.id):
        raise ResponsePlaybookValidationError(
            "id must be a slug: lowercase letters, digits, hyphens "
            "(^[a-z0-9][a-z0-9-]{0,127}$)"
        )
    return pb


# --------------------------------------------------------------------------- store


async def _latest_revision(
    db: AsyncSession, *, tenant_id: UUID, response_playbook_id: str
) -> dict[str, Any] | None:
    row = (await db.execute(
        text(
            "SELECT revision, status, definition, created_by, created_at "
            "FROM authored_response_playbook_revisions "
            "WHERE tenant_id = :t AND response_playbook_id = :p "
            "ORDER BY revision DESC LIMIT 1"
        ),
        {"t": str(tenant_id), "p": response_playbook_id},
    )).mappings().first()
    return dict(row) if row else None


async def list_authored(db: AsyncSession, *, tenant_id: UUID) -> list[dict[str, Any]]:
    """Latest revision of each non-retired authored response playbook for the tenant."""
    rows = (await db.execute(
        text(
            """
            SELECT DISTINCT ON (response_playbook_id)
                   response_playbook_id, revision, status, definition,
                   created_by, created_at
            FROM authored_response_playbook_revisions
            WHERE tenant_id = :t
            ORDER BY response_playbook_id, revision DESC
            """
        ),
        {"t": str(tenant_id)},
    )).mappings().all()
    return [dict(r) for r in rows if r["status"] != "retired"]


async def get_authored(
    db: AsyncSession, *, tenant_id: UUID, response_playbook_id: str
) -> dict[str, Any] | None:
    latest = await _latest_revision(
        db, tenant_id=tenant_id, response_playbook_id=response_playbook_id
    )
    if latest is None or latest["status"] == "retired":
        return None
    return latest


async def _insert_revision(
    db: AsyncSession, *, tenant_id: UUID, response_playbook_id: str, revision: int,
    status: str, definition: dict[str, Any], created_by: UUID | None,
) -> None:
    await db.execute(
        text(
            "INSERT INTO authored_response_playbook_revisions "
            "(id, tenant_id, response_playbook_id, revision, status, definition, "
            " created_by) "
            "VALUES (:id, :t, :p, :rev, :st, CAST(:def AS JSONB), :by)"
        ),
        {"id": str(uuid4()), "t": str(tenant_id), "p": response_playbook_id,
         "rev": revision, "st": status, "def": _json(definition),
         "by": str(created_by) if created_by else None},
    )


async def upsert_authored(
    db: AsyncSession, *, tenant_id: UUID, definition: dict[str, Any],
    status: str = "shadow", created_by: UUID | None = None,
) -> dict[str, Any]:
    """Create or edit an authored response playbook (appends a revision). Validates
    fail-closed; pins the tenant to the concrete id. New edits land as draft/shadow —
    use ``set_authored_status`` to activate. Raises ResponsePlaybookValidationError."""
    if status not in ("draft", "shadow"):
        raise ResponsePlaybookValidationError("new/edited status must be 'draft' or 'shadow'")
    pb = validate_authored({**definition, "tenant": str(tenant_id)})
    latest = await _latest_revision(
        db, tenant_id=tenant_id, response_playbook_id=pb.id
    )
    revision = (latest["revision"] + 1) if latest else 1
    stored = pb.model_dump()
    try:
        await _insert_revision(
            db, tenant_id=tenant_id, response_playbook_id=pb.id, revision=revision,
            status=status, definition=stored, created_by=created_by,
        )
        await db.flush()  # surface a duplicate-revision race here, not at commit
    except IntegrityError as exc:
        raise ResponsePlaybookConflictError(
            "a concurrent edit created a newer revision — reload and retry"
        ) from exc
    return {"response_playbook_id": pb.id, "revision": revision, "status": status,
            "definition": stored}


async def retire_authored(
    db: AsyncSession, *, tenant_id: UUID, response_playbook_id: str,
    retired_by: UUID | None = None,
) -> bool:
    """Soft-delete: append a 'retired' revision keeping the definition for history."""
    latest = await _latest_revision(
        db, tenant_id=tenant_id, response_playbook_id=response_playbook_id
    )
    if latest is None or latest["status"] == "retired":
        return False
    await _insert_revision(
        db, tenant_id=tenant_id, response_playbook_id=response_playbook_id,
        revision=latest["revision"] + 1, status="retired",
        definition=dict(latest["definition"]), created_by=retired_by,
    )
    return True


async def set_authored_status(
    db: AsyncSession, *, tenant_id: UUID, response_playbook_id: str, status: str,
    created_by: UUID | None = None,
) -> dict[str, Any] | None:
    """Activate ('active') or deactivate ('shadow') by appending a status revision.
    Activation RE-VALIDATES the stored definition fail-closed (a row valid at author
    time can go invalid after a code change — e.g. a capability removed from the
    allowlist); deactivation never revalidates so a now-invalid playbook can always be
    turned OFF. Returns the new state, or None if not found / retired."""
    if status not in ("active", "shadow"):
        raise ResponsePlaybookValidationError("status must be 'active' or 'shadow'")
    latest = await _latest_revision(
        db, tenant_id=tenant_id, response_playbook_id=response_playbook_id
    )
    if latest is None or latest["status"] == "retired":
        return None
    # Pass the stored definition through WITHOUT coercing to dict: deactivation must
    # always succeed even for a malformed row (Codex ph2 incr3 finding 2), so a
    # now-invalid playbook can still be turned OFF. Activation revalidates fail-closed
    # (validate_authored raises on a non-mapping), so garbage can never be activated.
    definition = latest["definition"]
    if status == "active":
        validate_authored(definition)
    revision = latest["revision"] + 1
    try:
        await _insert_revision(
            db, tenant_id=tenant_id, response_playbook_id=response_playbook_id,
            revision=revision, status=status, definition=definition,
            created_by=created_by,
        )
        await db.flush()
    except IntegrityError as exc:
        raise ResponsePlaybookConflictError(
            "a concurrent edit collided — reload and retry"
        ) from exc
    return {"response_playbook_id": response_playbook_id, "revision": revision,
            "status": status, "definition": definition}


async def load_dispatchable(
    db: AsyncSession, *, tenant_id: UUID, status: str
) -> list[ResponsePlaybook]:
    """Authored playbooks of the given governing status ('active'|'shadow') as parsed,
    RE-VALIDATED ``ResponsePlaybook`` objects for the dispatcher. Fail-closed: a stored
    row that no longer validates is SKIPPED (never dispatched), not raised — one bad row
    must not stop the completion path. The dispatcher merges these with the file
    registry."""
    rows = (await db.execute(
        text(
            """
            SELECT DISTINCT ON (response_playbook_id)
                   response_playbook_id, status, definition
            FROM authored_response_playbook_revisions
            WHERE tenant_id = :t
            ORDER BY response_playbook_id, revision DESC
            """
        ),
        {"t": str(tenant_id)},
    )).mappings().all()
    out: list[ResponsePlaybook] = []
    for r in rows:
        if r["status"] != status:
            continue
        # Fully fail-closed per row (Codex ph2 incr3 finding 2): a malformed JSONB
        # scalar/array must skip, never raise, or one bad row aborts the whole
        # completion's response dispatch. Also reassert the tenant pin — a
        # tampered/imported row whose definition tenant != this tenant is skipped.
        try:
            definition = dict(r["definition"])
        except (TypeError, ValueError):
            continue
        if str(definition.get("tenant")) != str(tenant_id):
            continue
        try:
            out.append(validate_authored(definition))
        except ResponsePlaybookValidationError:
            continue
    return out


def to_yaml(definition: dict[str, Any]) -> str:
    """Export an authored definition as YAML (git / portability)."""
    return yaml.safe_dump(definition, sort_keys=True, default_flow_style=False)


def _json(obj: Any) -> str:
    return json.dumps(obj, separators=(",", ":"), sort_keys=True, default=str)
