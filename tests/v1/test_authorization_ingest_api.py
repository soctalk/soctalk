"""Authorization-fact ingest API: submit (all kinds), credential-stamped trust, list, revoke."""

from __future__ import annotations

import os
from uuid import uuid4

import pytest
from fastapi import HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

os.environ.setdefault("SOCTALK_JWT_SIGNING_KEY", "test-signing-key-32-bytes-plaintext")
os.environ.setdefault("SOCTALK_ADAPTER_SIGNING_KEY", "adapter-signing-key-32-bytes-plaintext")

from soctalk.core.api.authorization import (  # noqa: E402
    FactSubmission,
    RevokeRequest,
    list_facts,
    revoke,
    submit_facts,
)

SKIP_INTEGRATION = os.getenv("SKIP_INTEGRATION", "0") == "1"
pytestmark = [pytest.mark.integration, pytest.mark.skipif(SKIP_INTEGRATION, reason="needs Postgres")]


def _req(session, token: str):
    class _R:
        headers = {"Authorization": f"Bearer {token}"}

        class state:  # noqa: N801 — mimics request.state
            db = session

    return _R()


def _token(tenant_id) -> str:
    from soctalk.core.tenancy import auth

    return auth.mint_adapter_token(tenant_id)


def _fact_payloads() -> list[dict]:
    return [
        {
            "kind": "grant", "id": "CHG-991", "track": "account",
            "grant_class": "change_ticket",
            "scope": {"subject": "svc-deploy", "target": "db-01", "action": "sudo-exec",
                      "recurring_window": {"start": "01:00", "end": "04:00"}},
            "valid_until": "2026-07-31T00:00:00Z",
        },
        # "account created" — a FIM/IAM submitter asserting a new service account exists.
        {
            "kind": "entity_context", "id": "acct-svc-deploy", "track": "account",
            "entity_type": "account", "name": "svc-deploy",
            "account_type": "service", "owner_org": "team-x",
        },
        {
            "kind": "prohibition", "id": "POL-PCI", "track": "account",
            "forbid_action": "sudo-exec",
            "applies_to": {"data_class": ["pci"], "env": ["prod"]},
            "break_glass_exception": True,
        },
    ]


async def test_submit_stamps_trust_and_lists(mssp_session: AsyncSession, seed_two_tenants):
    a, _ = seed_two_tenants
    tok = _token(a.tenant_id)

    res = await submit_facts(
        FactSubmission(tenant_id=a.tenant_id, facts=_fact_payloads()), _req(mssp_session, tok)
    )
    await mssp_session.commit()
    assert set(res["stored"]) == {"CHG-991", "acct-svc-deploy", "POL-PCI"}
    assert res["errors"] == []

    listed = await list_facts(_req(mssp_session, tok), tenant_id=a.tenant_id)
    facts = {f["id"]: f for f in listed["facts"]}
    assert set(facts) == {"CHG-991", "acct-svc-deploy", "POL-PCI"}
    # trust is stamped from the credential, not the payload
    assert all(f["source_type"] == "system_asserted" and f["trust"] == 80 for f in facts.values())
    assert facts["CHG-991"]["provenance"]["api_caller"] == f"adapter:{a.tenant_id}"


async def test_invalid_fact_reported_not_fatal(mssp_session: AsyncSession, seed_two_tenants):
    a, _ = seed_two_tenants
    tok = _token(a.tenant_id)
    payloads = _fact_payloads() + [
        # account prohibition missing forbid_action -> schema-invalid
        {"kind": "prohibition", "id": "BAD", "track": "account"},
    ]
    res = await submit_facts(
        FactSubmission(tenant_id=a.tenant_id, facts=payloads), _req(mssp_session, tok)
    )
    await mssp_session.commit()
    assert set(res["stored"]) == {"CHG-991", "acct-svc-deploy", "POL-PCI"}
    assert [e["id"] for e in res["errors"]] == ["BAD"]


async def test_tenant_mismatch_is_forbidden(mssp_session: AsyncSession, seed_two_tenants):
    a, b = seed_two_tenants
    tok_b = _token(b.tenant_id)  # token for tenant B, submitting as tenant A
    with pytest.raises(HTTPException) as exc:
        await submit_facts(
            FactSubmission(tenant_id=a.tenant_id, facts=_fact_payloads()), _req(mssp_session, tok_b)
        )
    assert exc.value.status_code == 403


async def test_revoke_soft_deletes(mssp_session: AsyncSession, seed_two_tenants):
    a, _ = seed_two_tenants
    tok = _token(a.tenant_id)
    await submit_facts(
        FactSubmission(tenant_id=a.tenant_id, facts=_fact_payloads()), _req(mssp_session, tok)
    )
    await mssp_session.commit()

    out = await revoke("CHG-991", RevokeRequest(reason="ticket expired"), _req(mssp_session, tok))
    await mssp_session.commit()
    assert out["revoked"] == "CHG-991"

    listed = await list_facts(_req(mssp_session, tok), tenant_id=a.tenant_id)
    assert {f["id"] for f in listed["facts"]} == {"acct-svc-deploy", "POL-PCI"}

    with pytest.raises(HTTPException) as exc:
        await revoke("nope", RevokeRequest(reason=None), _req(mssp_session, tok))
    assert exc.value.status_code == 404
