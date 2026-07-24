"""MITRE contextualization endpoints (issue #71).

Covers the two bridge surfaces the evidence-rail UI consumes:

1. ``GET /api/investigations/{id}/alerts`` — member alerts with a
   per-alert union of the source events' ``mitre`` payloads (Wazuh rule
   metadata: flat ids/tactics/techniques arrays), deduped, first-seen
   order preserved.
2. ``GET /api/mitre/techniques/{attack_id}/alerts`` — the pivot. A
   parent technique id matches its sub-techniques; scope follows RLS
   (tenant-pinned sessions only see their tenant).

Runs the real app stack over httpx ASGI (same harness as
test_metrics_bridge_tenant_scope); skipped under SKIP_INTEGRATION=1.
"""

from __future__ import annotations

import json
import os
from uuid import UUID, uuid4

import httpx
import pytest
import pytest_asyncio
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

SKIP_INTEGRATION = os.getenv("SKIP_INTEGRATION", "0") == "1"

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        SKIP_INTEGRATION,
        reason="SKIP_INTEGRATION set; MITRE context tests need Postgres",
    ),
]

_PASSWORD = "mitre-context-pw-2026!"
_ORIGIN = "http://testserver"
_CSRF_HEADERS = {"Origin": _ORIGIN}

_MSSP_ADMIN_EMAIL = "admin-a@mssp-a.example"
_TENANT_VIEWER_EMAIL = "viewer-a@acme.example"


async def _reset_global_engines(*, close: bool) -> None:
    from soctalk.core.tenancy import db as tenancy_db

    for engine_attr, sm_attr in (
        ("_APP_ENGINE", "_APP_SM"),
        ("_MSSP_ENGINE", "_MSSP_SM"),
    ):
        engine = getattr(tenancy_db, engine_attr)
        if engine is not None:
            await engine.dispose(close=close)
        setattr(tenancy_db, engine_attr, None)
        setattr(tenancy_db, sm_attr, None)


@pytest_asyncio.fixture
async def api_client(monkeypatch):
    monkeypatch.setenv("SOCTALK_AUTH_MODE", "internal")
    monkeypatch.setenv("SOCTALK_PUBLIC_ORIGIN", _ORIGIN)
    monkeypatch.setenv("SOCTALK_AUTH_COOKIE_SECURE", "0")
    monkeypatch.setenv("SOCTALK_PROVISIONING_WORKER", "0")

    from soctalk.core.api.app_v1 import create_app

    await _reset_global_engines(close=False)

    app = create_app()
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url=_ORIGIN) as client:
        yield client

    await _reset_global_engines(close=True)


@pytest_asyncio.fixture
async def seeded(seed_two_tenants, mssp_session: AsyncSession):
    from soctalk.core.auth.models import PasswordCredential
    from soctalk.core.auth.passwords import hash_password

    tenant_a, tenant_b = seed_two_tenants

    for email in (_MSSP_ADMIN_EMAIL, _TENANT_VIEWER_EMAIL):
        user_id = (
            await mssp_session.execute(
                text("SELECT id FROM users WHERE email = :e"), {"e": email}
            )
        ).scalar_one()
        mssp_session.add(
            PasswordCredential(user_id=user_id, password_hash=hash_password(_PASSWORD))
        )
    await mssp_session.commit()
    return tenant_a, tenant_b


async def _login(client: httpx.AsyncClient, email: str) -> None:
    resp = await client.post(
        "/api/auth/login",
        json={"email": email, "password": _PASSWORD},
        headers=_CSRF_HEADERS,
    )
    assert resp.status_code == 200, f"login failed: {resp.status_code} {resp.text}"


async def _seed_investigation(db: AsyncSession, tenant_id: UUID, short_id: str) -> UUID:
    case_id = uuid4()
    await db.execute(
        text(
            "INSERT INTO investigations "
            "(id, tenant_id, short_id, title, severity, status, visibility, opened_at) "
            "VALUES (:id, :t, :sid, 'mitre context test', 10, 'active', "
            "'customer_safe', now())"
        ),
        {"id": str(case_id), "t": str(tenant_id), "sid": short_id},
    )
    return case_id


async def _seed_alert(
    db: AsyncSession,
    tenant_id: UUID,
    investigation_id: UUID | None,
    *,
    rule_id: str,
    description: str,
    mitre_events: list[dict],
    offset_seconds: int = 0,
) -> UUID:
    """One alert plus one source event per mitre payload."""
    alert_id = uuid4()
    await db.execute(
        text(
            "INSERT INTO alerts "
            "(id, tenant_id, source, rule_id, severity, signature, description, "
            " first_event_at, last_event_at, event_count, investigation_id, visibility) "
            "VALUES (:id, :t, 'wazuh', :rule, 10, :sig, :descr, "
            " now() + make_interval(secs => :off), now() + make_interval(secs => :off), "
            " :n, :inv, 'customer_safe')"
        ),
        {
            "id": str(alert_id),
            "t": str(tenant_id),
            "rule": rule_id,
            "sig": f"sig-{alert_id}",
            "descr": description,
            "off": offset_seconds,
            "n": max(1, len(mitre_events)),
            "inv": str(investigation_id) if investigation_id else None,
        },
    )
    for i, mitre in enumerate(mitre_events):
        await db.execute(
            text(
                "INSERT INTO alert_source_events "
                "(id, tenant_id, source, source_event_id, alert_id, mitre, "
                " ingested_at) "
                "VALUES (:id, :t, 'wazuh', :seid, :aid, cast(:m AS jsonb), "
                " now() + make_interval(secs => :off))"
            ),
            {
                "id": str(uuid4()),
                "t": str(tenant_id),
                "seid": f"ev-{alert_id}-{i}",
                "aid": str(alert_id),
                "m": json.dumps(mitre),
                "off": offset_seconds + i,
            },
        )
    return alert_id


_BRUTE = {
    "ids": ["T1110.001"],
    "tactics": ["Credential Access"],
    "techniques": ["Password Guessing"],
}
_LATERAL = {
    "ids": ["T1021", "T1110.001"],
    "tactics": ["Lateral Movement", "Credential Access"],
    "techniques": ["Remote Services", "Password Guessing"],
}


async def test_investigation_alerts_union_mitre(
    api_client: httpx.AsyncClient, seeded, mssp_session: AsyncSession
):
    tenant_a, _ = seeded
    inv = await _seed_investigation(mssp_session, tenant_a.tenant_id, "2026-7100")
    mapped = await _seed_alert(
        mssp_session,
        tenant_a.tenant_id,
        inv,
        rule_id="5712",
        description="sshd brute force",
        mitre_events=[_BRUTE, _LATERAL],
        offset_seconds=0,
    )
    plain = await _seed_alert(
        mssp_session,
        tenant_a.tenant_id,
        inv,
        rule_id="510",
        description="no mitre mapping",
        mitre_events=[{}],
        offset_seconds=5,
    )
    await mssp_session.commit()

    await _login(api_client, _MSSP_ADMIN_EMAIL)
    resp = await api_client.get(f"/api/investigations/{inv}/alerts")
    assert resp.status_code == 200, resp.text
    body = resp.json()

    assert [a["id"] for a in body["alerts"]] == [str(mapped), str(plain)]
    m = body["alerts"][0]["mitre"]
    # Union, deduped, first-seen order.
    assert m["ids"] == ["T1110.001", "T1021"]
    assert m["tactics"] == ["Credential Access", "Lateral Movement"]
    assert m["techniques"] == ["Password Guessing", "Remote Services"]
    assert body["alerts"][0]["severity"] == "high"
    assert body["alerts"][1]["mitre"] == {"ids": [], "tactics": [], "techniques": []}

    # Unknown investigation → 404.
    resp = await api_client.get(f"/api/investigations/{uuid4()}/alerts")
    assert resp.status_code == 404


async def test_technique_pivot_parent_match_and_validation(
    api_client: httpx.AsyncClient, seeded, mssp_session: AsyncSession
):
    tenant_a, tenant_b = seeded
    inv = await _seed_investigation(mssp_session, tenant_a.tenant_id, "2026-7101")
    alert_a = await _seed_alert(
        mssp_session,
        tenant_a.tenant_id,
        inv,
        rule_id="5712",
        description="tenant A brute force",
        mitre_events=[_BRUTE],
    )
    # Same technique in tenant B — must stay invisible to a tenant-A pin.
    await _seed_alert(
        mssp_session,
        tenant_b.tenant_id,
        None,
        rule_id="5712",
        description="tenant B brute force",
        mitre_events=[_BRUTE],
    )
    await mssp_session.commit()

    await _login(api_client, _MSSP_ADMIN_EMAIL)

    # Parent id matches the sub-technique; investigation attribution rides along.
    body = (await api_client.get("/api/mitre/techniques/T1110/alerts")).json()
    assert body["total"] == 2  # unpinned MSSP admin sees both tenants
    ids = {a["id"] for a in body["alerts"]}
    assert str(alert_a) in ids
    a_row = next(a for a in body["alerts"] if a["id"] == str(alert_a))
    assert a_row["investigation_id"] == str(inv)
    assert a_row["investigation_title"] == "mitre context test"

    # Exact sub-technique id also matches.
    body = (await api_client.get("/api/mitre/techniques/T1110.001/alerts")).json()
    assert body["total"] == 2

    # Server-side exclusion of the caller's own investigation: total and
    # page both drop tenant A's alert, leaving tenant B's uninvestigated one.
    body = (
        await api_client.get(
            f"/api/mitre/techniques/T1110/alerts?exclude_investigation_id={inv}"
        )
    ).json()
    assert body["total"] == 1
    assert all(a["investigation_id"] != str(inv) for a in body["alerts"])

    # A sibling technique doesn't.
    body = (await api_client.get("/api/mitre/techniques/T1566/alerts")).json()
    assert body["total"] == 0

    # Garbage ids are rejected before touching SQL.
    resp = await api_client.get("/api/mitre/techniques/DROP%20TABLE/alerts")
    assert resp.status_code == 422


async def test_technique_pivot_rls_scope(
    api_client: httpx.AsyncClient, seeded, mssp_session: AsyncSession
):
    tenant_a, tenant_b = seeded
    await _seed_alert(
        mssp_session,
        tenant_a.tenant_id,
        None,
        rule_id="5712",
        description="tenant A only",
        mitre_events=[_BRUTE],
    )
    await _seed_alert(
        mssp_session,
        tenant_b.tenant_id,
        None,
        rule_id="5712",
        description="tenant B only",
        mitre_events=[_BRUTE],
    )
    await mssp_session.commit()

    # Tenant-A viewer: RLS pins the session; tenant B's alert must not leak.
    await _login(api_client, _TENANT_VIEWER_EMAIL)
    body = (await api_client.get("/api/mitre/techniques/T1110.001/alerts")).json()
    assert body["total"] == 1
    assert body["alerts"][0]["description"] == "tenant A only"


async def test_endpoints_require_auth(api_client: httpx.AsyncClient, seeded):
    resp = await api_client.get(f"/api/investigations/{uuid4()}/alerts")
    assert resp.status_code == 401
    resp = await api_client.get("/api/mitre/techniques/T1110/alerts")
    assert resp.status_code == 401
