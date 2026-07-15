"""Authored playbooks: DB-backed shadow/draft CRUD + export (#44 follow-on).

Round-trip against Postgres via the route handlers, fail-closed validation, and the role
gate (read = ANALYST+, write = admin-only).
"""

from __future__ import annotations

import os
from uuid import uuid4

import pytest
import yaml
from fastapi import HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

os.environ.setdefault("SOCTALK_JWT_SIGNING_KEY", "test-signing-key-32-bytes-plaintext")
os.environ.setdefault("SOCTALK_ADAPTER_SIGNING_KEY", "adapter-signing-key-32-bytes-plaintext")

from sqlalchemy import text  # noqa: E402

from soctalk.core.api.ir import (  # noqa: E402
    AuthoredPlaybookRequest,
    activate_authored_playbook_route,
    create_authored_playbook_route,
    deactivate_authored_playbook_route,
    export_authored_playbook_route,
    list_authored_playbooks_route,
    retire_authored_playbook_route,
    update_authored_playbook_route,
)
from soctalk.playbook.authoring import render_active_authored_values  # noqa: E402

SKIP_INTEGRATION = os.getenv("SKIP_INTEGRATION", "0") == "1"

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(SKIP_INTEGRATION, reason="needs Postgres"),
]


def _req(session):
    from soctalk.core.tenancy.models import Role, UserType

    identity = {
        "user_id": str(uuid4()), "email": "admin@mssp.example",
        "user_type": UserType.MSSP.value, "role": Role.MSSP_ADMIN.value,
        "tenant_id": None, "current_tenant": None,
    }

    class _R:
        class state:  # noqa: N801
            user_identity = identity
            db = session

    return _R()


def _valid(**over):
    d = {"id": "custom-pb", "priority": 70, "applies_to": {"rule_groups": ["custom_group"]}}
    d.update(over)
    return AuthoredPlaybookRequest(definition=d, status="shadow")


async def test_create_list_edit_export_retire(mssp_session: AsyncSession, seed_two_tenants):
    t, _ = seed_two_tenants
    req = _req(mssp_session)

    created = await create_authored_playbook_route(t.tenant_id, _valid(), req)
    await mssp_session.commit()
    assert created.playbook_id == "custom-pb"
    assert created.revision == 1
    assert created.status == "shadow"
    assert created.definition["status"] == "shadow"  # forced — authored is never active
    assert created.definition["tenant"] == str(t.tenant_id)  # forced concrete tenant, never "*"

    listed = await list_authored_playbooks_route(t.tenant_id, req)
    assert [p.playbook_id for p in listed] == ["custom-pb"]

    # edit → new revision
    edited = await update_authored_playbook_route(
        t.tenant_id, "custom-pb",
        _valid(applies_to={"rule_groups": ["custom_group", "other"]}), req,
    )
    await mssp_session.commit()
    assert edited.revision == 2
    assert "other" in edited.definition["applies_to"]["rule_groups"]

    # export → parseable YAML
    exported = await export_authored_playbook_route(t.tenant_id, "custom-pb", req)
    parsed = yaml.safe_load(exported["yaml"])
    assert parsed["id"] == "custom-pb" and parsed["status"] == "shadow"

    # retire → gone from list
    out = await retire_authored_playbook_route(t.tenant_id, "custom-pb", req)
    await mssp_session.commit()
    assert out["ok"] == "retired"
    assert await list_authored_playbooks_route(t.tenant_id, req) == []


async def test_duplicate_create_conflicts(mssp_session: AsyncSession, seed_two_tenants):
    t, _ = seed_two_tenants
    req = _req(mssp_session)
    await create_authored_playbook_route(t.tenant_id, _valid(id="dup-pb"), req)
    await mssp_session.commit()
    with pytest.raises(HTTPException) as ei:
        await create_authored_playbook_route(t.tenant_id, _valid(id="dup-pb"), req)
    assert ei.value.status_code == 409


@pytest.mark.parametrize(
    "bad",
    [
        {"deterministic_disposition": "close_operational"},  # built-in-only
        {"priority": 10},                                      # below floor
        {"id": "dual-use-privileged-exec"},                    # built-in collision
        {"required_steps": ["bogus_step"]},                    # unknown step
        {"legal_actions": {"triage": ["NOT_AN_ACTION"]}},      # unknown action
        {"decision_modules": ["made_up_module"]},              # unknown module
        {"legal_actions": {"triag": ["VERDICT"]}},             # unknown phase (typo)
        {"id": "Bad_Slug"},                                    # invalid slug charset
        {"applies_to": {"rule_groups": ["g"]}, "guardrails": [
            {"when": {"bogus_op": [1, 2]}, "effect": "override",
             "to": "escalate", "reason": "x"}]},               # bad condition
    ],
)
async def test_invalid_definitions_rejected(mssp_session, seed_two_tenants, bad):
    t, _ = seed_two_tenants
    payload = _valid(**{"id": "bad-pb", **bad})
    with pytest.raises(HTTPException) as ei:
        await create_authored_playbook_route(t.tenant_id, payload, _req(mssp_session))
    assert ei.value.status_code == 400


async def _reconcile_jobs(session, tenant_id):
    return (await session.execute(
        text("SELECT count(*) FROM provisioning_jobs WHERE tenant_id = :t "
             "AND kind = 'tenant.reconcile' AND status = 'pending'"),
        {"t": str(tenant_id)},
    )).scalar_one()


async def test_activate_deactivate_governs_and_reconciles(
    mssp_session: AsyncSession, seed_two_tenants
):
    t, _ = seed_two_tenants  # seeded tenants are ACTIVE → activation enqueues a reconcile
    req = _req(mssp_session)
    await create_authored_playbook_route(t.tenant_id, _valid(id="gov-pb"), req)
    await mssp_session.commit()

    # not active yet → not delivered
    assert await render_active_authored_values(mssp_session, tenant_id=t.tenant_id) == {}

    activated = await activate_authored_playbook_route(t.tenant_id, "gov-pb", req)
    await mssp_session.commit()
    assert activated.status == "active"
    assert await _reconcile_jobs(mssp_session, t.tenant_id) >= 1

    # now materialized for chart delivery, status forced active in the YAML
    rendered = await render_active_authored_values(mssp_session, tenant_id=t.tenant_id)
    assert set(rendered) == {"authored-gov-pb.yaml"}
    doc = yaml.safe_load(rendered["authored-gov-pb.yaml"])
    assert doc["id"] == "gov-pb" and doc["status"] == "active"
    assert doc["tenant"] == str(t.tenant_id)

    deactivated = await deactivate_authored_playbook_route(t.tenant_id, "gov-pb", req)
    await mssp_session.commit()
    assert deactivated.status == "shadow"
    assert await render_active_authored_values(mssp_session, tenant_id=t.tenant_id) == {}


async def test_edit_active_playbook_stays_active(
    mssp_session: AsyncSession, seed_two_tenants
):
    """Editing an active playbook must keep it governing (not silently drop to shadow) and
    re-roll — the Codex-flagged footgun."""
    t, _ = seed_two_tenants
    req = _req(mssp_session)
    await create_authored_playbook_route(t.tenant_id, _valid(id="edit-pb"), req)
    await activate_authored_playbook_route(t.tenant_id, "edit-pb", req)
    await mssp_session.commit()

    edited = await update_authored_playbook_route(
        t.tenant_id, "edit-pb",
        _valid(id="edit-pb", applies_to={"rule_groups": ["g", "extra"]}), req,
    )
    await mssp_session.commit()
    assert edited.status == "active"  # still governing
    rendered = await render_active_authored_values(mssp_session, tenant_id=t.tenant_id)
    assert "authored-edit-pb.yaml" in rendered
    doc = yaml.safe_load(rendered["authored-edit-pb.yaml"])
    assert "extra" in doc["applies_to"]["rule_groups"]  # the new definition governs


async def test_activate_unknown_returns_404(mssp_session: AsyncSession, seed_two_tenants):
    t, _ = seed_two_tenants
    with pytest.raises(HTTPException) as ei:
        await activate_authored_playbook_route(t.tenant_id, "ghost", _req(mssp_session))
    assert ei.value.status_code == 404


async def test_oversized_definition_rejected(mssp_session: AsyncSession, seed_two_tenants):
    t, _ = seed_two_tenants
    big = _valid(id="big-pb", applies_to={"rule_groups": ["x" * 70000]})
    with pytest.raises(HTTPException) as ei:
        await create_authored_playbook_route(t.tenant_id, big, _req(mssp_session))
    assert ei.value.status_code == 400


async def test_edit_id_mismatch_and_unknown(mssp_session: AsyncSession, seed_two_tenants):
    t, _ = seed_two_tenants
    req = _req(mssp_session)
    with pytest.raises(HTTPException) as ei:  # id in body != path
        await update_authored_playbook_route(t.tenant_id, "path-id", _valid(id="body-id"), req)
    assert ei.value.status_code == 400
    with pytest.raises(HTTPException) as ei2:  # editing a non-existent playbook
        await update_authored_playbook_route(t.tenant_id, "ghost", _valid(id="ghost"), req)
    assert ei2.value.status_code == 404


async def test_tenant_isolation(mssp_session: AsyncSession, seed_two_tenants):
    ta, tb = seed_two_tenants
    await create_authored_playbook_route(ta.tenant_id, _valid(id="a-only"), _req(mssp_session))
    await mssp_session.commit()
    assert await list_authored_playbooks_route(tb.tenant_id, _req(mssp_session)) == []


def test_authoring_role_gate():
    from fastapi.testclient import TestClient
    from starlette.middleware.base import BaseHTTPMiddleware

    from soctalk.core.api.app_v1 import create_app
    from soctalk.core.tenancy.models import Role, UserType

    class _NoopDB:
        def __init__(self, app):
            self.app = app

        async def __call__(self, scope, receive, send):
            if scope["type"] == "http":
                scope.setdefault("state", {})
                scope["state"]["db"] = None
            await self.app(scope, receive, send)

    def _app_as(identity):
        app = create_app(db_session_middleware=_NoopDB)

        class _Inject(BaseHTTPMiddleware):
            async def dispatch(self, request, call_next):
                request.state.user_identity = identity
                return await call_next(request)

        app.add_middleware(_Inject)
        return app

    tid = str(uuid4())
    analyst = {
        "user_id": str(uuid4()), "email": "a@mssp.example",
        "user_type": UserType.MSSP.value, "role": Role.ANALYST.value,
        "tenant_id": None, "current_tenant": None,
    }
    admin = {**analyst, "role": Role.MSSP_ADMIN.value, "email": "admin@mssp.example"}
    viewer = {
        "user_id": str(uuid4()), "email": "v@acme.example",
        "user_type": UserType.TENANT.value, "role": Role.CUSTOMER_VIEWER.value,
        "tenant_id": tid, "current_tenant": None,
    }
    url = f"/api/mssp/tenants/{tid}/playbooks"
    body = {"definition": {"id": "x", "priority": 70, "applies_to": {"rule_groups": ["g"]}}}

    ca = TestClient(_app_as(analyst), raise_server_exceptions=False)
    # analyst may READ (gate opens → 500 on the None db), but may NOT create (403)
    assert ca.get(url).status_code != 403
    assert ca.post(url, json=body).status_code == 403

    cadmin = TestClient(_app_as(admin), raise_server_exceptions=False)
    assert cadmin.post(url, json=body).status_code != 403  # gate opens for admin

    cv = TestClient(_app_as(viewer), raise_server_exceptions=False)
    assert cv.get(url).status_code == 403  # customer viewer can't even read
