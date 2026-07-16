"""Tenant co-managed-SOC operate surface: capability gating + cross-tenant isolation.

Two layers:
  * Guard gating (no DB) — the actual route guards attached to the review-decide, proposal,
    and chat endpoints admit a ``tenant_analyst`` and deny a ``customer_viewer``; high-blast
    proposal sign-off stays manager-tier on both audiences.
  * Cross-tenant isolation (Postgres) — a tenant operator can only resolve its OWN tenant's
    reviews; a foreign review_id fails closed as 404 (never discloses existence across tenants).
"""

from __future__ import annotations

import os
from types import SimpleNamespace
from uuid import uuid4

import pytest
from fastapi import HTTPException

os.environ.setdefault("SOCTALK_JWT_SIGNING_KEY", "test-signing-key-32-bytes-plaintext")

from soctalk.core.tenancy.models import Role, UserType  # noqa: E402


# --------------------------------------------------------------------------- #
# Layer 1 — guard gating (deterministic, no DB)
# --------------------------------------------------------------------------- #


class _FakeRequest:
    def __init__(self, identity):
        self.state = type("S", (), {"user_identity": identity})()


def _id(user_type, role, tenant_id="t1"):
    return {"user_type": user_type, "role": role, "tenant_id": tenant_id}


async def _status(guard, identity):
    """Return None if the guard admits the caller, else the HTTP status it raised."""
    try:
        await guard(_FakeRequest(identity))
        return None
    except HTTPException as e:
        return e.status_code


def _analyst():
    return _id(UserType.MSSP.value, Role.ANALYST.value, tenant_id=None)


def _tenant_analyst():
    return _id(UserType.TENANT.value, Role.TENANT_ANALYST.value)


def _customer_viewer():
    return _id(UserType.TENANT.value, Role.CUSTOMER_VIEWER.value)


@pytest.mark.asyncio
async def test_review_decide_guard_admits_both_operators_denies_viewer():
    from soctalk.core.api.legacy_stubs import _REVIEW_DECIDE_GUARD

    assert await _status(_REVIEW_DECIDE_GUARD, _analyst()) is None
    assert await _status(_REVIEW_DECIDE_GUARD, _tenant_analyst()) is None
    assert await _status(_REVIEW_DECIDE_GUARD, _customer_viewer()) == 403


@pytest.mark.asyncio
async def test_proposal_guard_admits_both_operators_denies_viewer():
    from soctalk.core.api.ir import _APPROVE_PROPOSAL_GUARD

    assert await _status(_APPROVE_PROPOSAL_GUARD, _analyst()) is None
    assert await _status(_APPROVE_PROPOSAL_GUARD, _tenant_analyst()) is None
    assert await _status(_APPROVE_PROPOSAL_GUARD, _customer_viewer()) == 403


@pytest.mark.asyncio
async def test_review_read_is_gated_off_read_only_viewer():
    # the review LIST/GET endpoints share the decide guard: a read-only customer_viewer cannot
    # even enumerate the operate queue (pending_reviews has no audience column to hide it otherwise)
    from soctalk.core.api.legacy_stubs import _REVIEW_ACCESS_GUARD

    assert await _status(_REVIEW_ACCESS_GUARD, _analyst()) is None
    assert await _status(_REVIEW_ACCESS_GUARD, _tenant_analyst()) is None
    assert await _status(_REVIEW_ACCESS_GUARD, _customer_viewer()) == 403


@pytest.mark.asyncio
async def test_chat_guards_gate_read_write_and_confirm():
    from soctalk.core.api.chat import _CHAT_CONFIRM_GUARD, _CHAT_GUARD

    # chat access (reads AND writes are gated — chat history can carry review-queue tool output,
    # so a read-only customer_viewer must not read it either): both operators yes, viewer no
    assert await _status(_CHAT_GUARD, _tenant_analyst()) is None
    assert await _status(_CHAT_GUARD, _analyst()) is None
    assert await _status(_CHAT_GUARD, _customer_viewer()) == 403
    # confirm = review-decide authority (NOT mere chat access): tenant_analyst yes, viewer no
    assert await _status(_CHAT_CONFIRM_GUARD, _tenant_analyst()) is None
    assert await _status(_CHAT_CONFIRM_GUARD, _customer_viewer()) == 403
    assert await _status(_CHAT_CONFIRM_GUARD, _analyst()) is None


def test_privileged_proposal_stays_manager_tier_on_both_audiences():
    from soctalk.core.api.ir import _may_approve_privileged

    # tenant: analyst may NOT sign off a WRITE_EXTERNAL action; manager may
    assert not _may_approve_privileged(
        SimpleNamespace(user_type=UserType.TENANT.value, role=Role.TENANT_ANALYST.value)
    )
    assert _may_approve_privileged(
        SimpleNamespace(user_type=UserType.TENANT.value, role=Role.TENANT_MANAGER.value)
    )
    # mssp: analyst may NOT; manager may
    assert not _may_approve_privileged(
        SimpleNamespace(user_type=UserType.MSSP.value, role=Role.ANALYST.value)
    )
    assert _may_approve_privileged(
        SimpleNamespace(user_type=UserType.MSSP.value, role=Role.MSSP_MANAGER.value)
    )


# --------------------------------------------------------------------------- #
# Layer 2 — cross-tenant isolation (Postgres; _resolve_pending_review opens its
# own role-based RLS session internally, so this is self-contained once the seed
# is committed).
# --------------------------------------------------------------------------- #

SKIP_INTEGRATION = os.getenv("SKIP_INTEGRATION", "0") == "1"


def _principal(tenant_id):
    return SimpleNamespace(
        role=Role.TENANT_ANALYST.value, tenant_id=tenant_id, current_tenant=None
    )


def _mssp_analyst_pinned(pin_tenant_id):
    # an MSSP analyst carries no home tenant_id; it works a tenant via an Open-SOC pin
    return SimpleNamespace(
        role=Role.ANALYST.value, tenant_id=None, current_tenant=pin_tenant_id
    )


@pytest.mark.integration
@pytest.mark.skipif(SKIP_INTEGRATION, reason="needs Postgres")
async def test_tenant_operator_resolves_only_its_own_reviews(mssp_session, seed_two_tenants):
    from sqlalchemy import text

    from soctalk.core.api.legacy_stubs import _resolve_pending_review

    a, b = seed_two_tenants
    inv_id, rev_id = uuid4(), uuid4()
    # seed one investigation + pending review in tenant A (BYPASSRLS seed), then COMMIT so the
    # fresh app-role session opened inside _resolve_pending_review can see it.
    await mssp_session.execute(
        text(
            "INSERT INTO investigations "
            "(id, tenant_id, short_id, title, severity, status, visibility, opened_at) "
            "VALUES (:id, :t, 'OP-1', 'operate test', 5, 'active', 'mssp_only', now())"
        ),
        {"id": str(inv_id), "t": str(a.tenant_id)},
    )
    await mssp_session.execute(
        text(
            "INSERT INTO pending_reviews "
            "(id, investigation_id, tenant_id, status, title, description, "
            " max_severity, alert_count, findings, enrichments, created_at) "
            "VALUES (:id, :inv, :t, 'pending', 'r', 'operate test', 'high', 1, "
            " '{}', '{}'::jsonb, now())"
        ),
        {"id": str(rev_id), "inv": str(inv_id), "t": str(a.tenant_id)},
    )
    await mssp_session.commit()

    try:
        # tenant_analyst of A resolves its own review
        resolved = await _resolve_pending_review(str(rev_id), _principal(a.tenant_id))
        assert resolved["id"] == str(rev_id)
        assert resolved["tenant_id"] == str(a.tenant_id)

        # tenant_analyst of B asking for A's review → 404, fail closed (no existence disclosure)
        with pytest.raises(HTTPException) as exc:
            await _resolve_pending_review(str(rev_id), _principal(b.tenant_id))
        assert exc.value.status_code == 404

        # #3 fix: a pinned MSSP analyst (no home tenant_id) resolves via its Open-SOC pin —
        # the review is scoped by the effective tenant (the pin), not identity.tenant_id.
        pinned_ok = await _resolve_pending_review(str(rev_id), _mssp_analyst_pinned(a.tenant_id))
        assert pinned_ok["id"] == str(rev_id)
        # …pinned to the WRONG tenant it still fails closed
        with pytest.raises(HTTPException) as exc2:
            await _resolve_pending_review(str(rev_id), _mssp_analyst_pinned(b.tenant_id))
        assert exc2.value.status_code == 404
    finally:
        await mssp_session.execute(
            text("DELETE FROM pending_reviews WHERE id = :id"), {"id": str(rev_id)}
        )
        await mssp_session.execute(
            text("DELETE FROM investigations WHERE id = :id"), {"id": str(inv_id)}
        )
        await mssp_session.commit()
