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
