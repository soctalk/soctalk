"""MSSP governance API for authorization facts: analyst create / list / revoke."""

from __future__ import annotations

import os
from uuid import uuid4

import pytest
from fastapi import HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

os.environ.setdefault("SOCTALK_JWT_SIGNING_KEY", "test-signing-key-32-bytes-plaintext")

from soctalk.core.api.authorization import (  # noqa: E402
    FactCreateRequest,
    RevokeRequest,
    mssp_create_fact,
    mssp_list_facts,
    mssp_revoke_fact,
)

SKIP_INTEGRATION = os.getenv("SKIP_INTEGRATION", "0") == "1"
pytestmark = [pytest.mark.integration, pytest.mark.skipif(SKIP_INTEGRATION, reason="needs Postgres")]


def _req(session, user_id):
    from soctalk.core.tenancy.models import Role, UserType

    identity = {
        "user_id": str(user_id),
        "email": "analyst@mssp.example",
        "user_type": UserType.MSSP.value,
        "role": Role.MSSP_ADMIN.value,
        "tenant_id": None,
        "current_tenant": None,
    }

    class _R:
        class state:  # noqa: N801
            user_identity = identity
            db = session

    return _R()


_GRANT = {
    "kind": "grant", "id": "CHG-1", "track": "account", "grant_class": "change_ticket",
    "scope": {"subject": "svc-deploy", "target": "db-01", "action": "sudo-exec"},
    "valid_until": "2026-12-31T00:00:00Z",
}


async def test_create_list_revoke_as_analyst(mssp_session: AsyncSession, seed_two_tenants):
    a, _ = seed_two_tenants
    req = _req(mssp_session, a.admin_user_id)

    out = await mssp_create_fact(a.tenant_id, FactCreateRequest(fact=dict(_GRANT)), req)
    await mssp_session.commit()
    assert out["stored"] == "CHG-1"

    listed = await mssp_list_facts(a.tenant_id, req)
    assert len(listed["facts"]) == 1
    f = listed["facts"][0]
    # analyst-created facts are stamped analyst_asserted / trust 60, attributed to the user
    assert f["source_type"] == "analyst_asserted"
    assert f["trust"] == 60
    assert f["created_by"] == str(a.admin_user_id)

    rev = await mssp_revoke_fact(a.tenant_id, "CHG-1", RevokeRequest(reason="superseded"), req)
    await mssp_session.commit()
    assert rev["revoked"] == "CHG-1"
    assert (await mssp_list_facts(a.tenant_id, req))["facts"] == []


async def test_create_invalid_fact_is_422(mssp_session: AsyncSession, seed_two_tenants):
    a, _ = seed_two_tenants
    req = _req(mssp_session, a.admin_user_id)
    with pytest.raises(HTTPException) as exc:
        await mssp_create_fact(
            a.tenant_id, FactCreateRequest(fact={"kind": "prohibition", "id": "X", "track": "account"}), req
        )
    assert exc.value.status_code == 422


async def test_revoke_missing_is_404(mssp_session: AsyncSession, seed_two_tenants):
    a, _ = seed_two_tenants
    req = _req(mssp_session, a.admin_user_id)
    with pytest.raises(HTTPException) as exc:
        await mssp_revoke_fact(a.tenant_id, "nope", RevokeRequest(reason=None), req)
    assert exc.value.status_code == 404


def _tenant_req(session, tenant_id, user_id, role="tenant_manager"):
    from soctalk.core.tenancy.models import UserType

    identity = {
        "user_id": str(user_id), "email": f"{role}@acme.example",
        "user_type": UserType.TENANT.value, "role": role,
        "tenant_id": str(tenant_id), "current_tenant": None,
    }

    class _R:
        class state:  # noqa: N801
            user_identity = identity
            db = session

    return _R()


async def test_tenant_assert_is_pending_until_mssp_approves(
    mssp_session: AsyncSession, seed_two_tenants
):
    """End-to-end review gate: a tenant asserts a fact → it lands 'pending', server-stamped
    (tenant_asserted, trust 20, server-namespaced id) and INVISIBLE to the engine read, until an
    MSSP analyst approves it — then it becomes live."""
    from soctalk.core.api.authorization import (
        FactCreateRequest,
        ReviewRequest,
        mssp_review_fact,
        tenant_assert_fact,
    )
    from soctalk.core.ir.authorization_store import list_current_facts

    a, _ = seed_two_tenants
    treq = _tenant_req(mssp_session, a.tenant_id, a.admin_user_id)

    # tenant asserts (client id is ignored; server namespaces + stamps)
    out = await tenant_assert_fact(
        FactCreateRequest(fact={**_GRANT, "id": "CHG-1"}), treq
    )
    await mssp_session.commit()
    fid = out["stored"]
    assert out["review_status"] == "pending"
    assert fid.startswith("tenant:")  # server-namespaced — cannot collide with an existing fact

    # invisible to the engine while pending
    assert await list_current_facts(mssp_session, tenant_id=a.tenant_id) == []

    # MSSP analyst approves → now live to the engine
    mreq = _req(mssp_session, a.admin_user_id)
    res = await mssp_review_fact(a.tenant_id, fid, ReviewRequest(decision="approve"), mreq)
    await mssp_session.commit()
    assert res["status"] == "approved"
    live = await list_current_facts(mssp_session, tenant_id=a.tenant_id)
    assert [f.id for f in live] == [fid]

    # a second pending assertion that gets rejected never goes live
    out2 = await tenant_assert_fact(FactCreateRequest(fact={**_GRANT, "id": "CHG-2"}), treq)
    await mssp_session.commit()
    await mssp_review_fact(a.tenant_id, out2["stored"], ReviewRequest(decision="reject"), mreq)
    await mssp_session.commit()
    live_ids = {f.id for f in await list_current_facts(mssp_session, tenant_id=a.tenant_id)}
    assert out2["stored"] not in live_ids
