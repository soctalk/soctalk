"""Engagement deconfliction wired into ingest triage (#31), end-to-end (live Postgres).

A declared pentest/red-team window deconflicts in-scope attack-shaped alerts: they are
recorded in an auditable declared-test lane and skip the LLM run, but are NEVER closed/FP.
Out-of-scope tester activity is a contractual finding forced to a real look. The safety
ordering that makes this safe is asserted here:

  - deconfliction runs AFTER entity correlation (a live-incident alert must attach, not be
    deconflicted) and BEFORE reopen/memo/rules-close (a declared-test alert must not
    resurrect an auto-closed FP nor be closed by reference);
  - out-of-scope activity vetoes the auto-close paths (never suppressed);
  - deconfliction is fail-closed: it suppresses only alerts positively attributed to an
    in-scope tester source; a missing/unroled/out-of-scope source runs normal triage;
  - the flag defaults off (no behaviour change); tenant isolation holds.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from soctalk.core.ir.campaign import declare_engagement, deconflict
from soctalk.core.ir.policies import set_tenant_policy
from soctalk.core.ir.triage import triage_event

SKIP_INTEGRATION = os.getenv("SKIP_INTEGRATION", "0") == "1"

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(SKIP_INTEGRATION, reason="needs Postgres"),
]

# Anchor all timestamps (alert occurred_at + engagement windows) to real "now":
# correlation keys carry a wall-clock expiry (record_keys sets expires_at =
# occurred_at + window, and find_correlated_investigation filters
# `expires_at > now()` against the DB clock). A hardcoded past _NOW made the
# recorded keys expire once real time passed _NOW + window, silently breaking
# the correlation-wins assertions (a time-bomb: green when run near _NOW, red
# days later). A recent, relative anchor keeps windows consistent and keys live.
_NOW = datetime.now(UTC) - timedelta(minutes=1)
SCOPE_IP = "203.0.113.5"          # inside 203.0.113.0/24
OFF_SCOPE_IP = "198.51.100.7"     # outside the tester scope


def _ev(seid, *, rule_id="31101", host="web-01", src_ip=SCOPE_IP, severity=5,
        mitre_ids=None, iocs=None, ts=None):
    ents = [
        {"type": "host", "value": host, "role": "target"},
        {"type": "ip", "value": src_ip, "role": "src"},
    ]
    return dict(
        source="wazuh", rule_id=rule_id, severity=severity, asset_ids=[host],
        initial_iocs=iocs or [], source_event_id=seid, ts=ts or _NOW,
        description="GET /",
        evidence={
            "entities": ents,
            "mitre": {"ids": mitre_ids or []},
            "decoder": "web-accesslog", "template_hash": "th",
            "template_version": "1", "schema_version": 2,
        },
    )


async def _enable(session, tenant_id, *, deconf=True, correlation=False, auto_close=False):
    await set_tenant_policy(session, tenant_id, "engagement_deconfliction_enabled", deconf)
    await set_tenant_policy(session, tenant_id, "entity_correlation_enabled", correlation)
    await set_tenant_policy(session, tenant_id, "auto_close_enabled", auto_close)
    await session.commit()


async def _declare(session, tenant_id, *, hosts=("web-01", "web-02"),
                   techniques=("T1110",), starts=None, ends=None):
    return await declare_engagement(
        session, tenant_id=tenant_id, name="Q3 external pentest", kind="pentest",
        starts_at=starts or (_NOW - timedelta(hours=1)),
        ends_at=ends or (_NOW + timedelta(hours=1)),
        scope_source_ips=["203.0.113.0/24"], scope_hosts=list(hosts),
        scope_techniques=list(techniques),
    )


async def _scalar(session, sql, **p):
    return (await session.execute(text(sql), p)).scalar_one()


async def _obs(session, tenant_id):
    return (await session.execute(
        text("SELECT status, primary_engagement_id FROM engagement_observations "
             "WHERE tenant_id = :t"),
        {"t": str(tenant_id)},
    )).mappings().all()


# --------------------------------------------------------------------------- unit


async def test_declare_engagement_rejects_unsafe_scopes(mssp_session, seed_two_tenants):
    t, _ = seed_two_tenants
    common = dict(name="x", kind="pentest",
                  starts_at=_NOW, ends_at=_NOW + timedelta(hours=1))
    # all-empty scope would match every alert in its window
    with pytest.raises(ValueError):
        await declare_engagement(mssp_session, tenant_id=t.tenant_id,
                                 scope_source_ips=[], scope_hosts=[],
                                 scope_techniques=[], **common)
    # no bounded target axis
    with pytest.raises(ValueError):
        await declare_engagement(mssp_session, tenant_id=t.tenant_id,
                                 scope_source_ips=["203.0.113.0/24"], scope_hosts=[],
                                 scope_techniques=[], **common)
    # invalid ip / technique
    with pytest.raises(ValueError):
        await declare_engagement(mssp_session, tenant_id=t.tenant_id,
                                 scope_source_ips=["not-an-ip"], scope_hosts=["h"],
                                 scope_techniques=[], **common)
    with pytest.raises(ValueError):
        await declare_engagement(mssp_session, tenant_id=t.tenant_id,
                                 scope_source_ips=["203.0.113.0/24"], scope_hosts=[],
                                 scope_techniques=["brute-force"], **common)
    # ends before starts / window too long
    with pytest.raises(ValueError):
        await declare_engagement(mssp_session, tenant_id=t.tenant_id, name="x",
                                 kind="pentest", starts_at=_NOW, ends_at=_NOW,
                                 scope_source_ips=["203.0.113.0/24"], scope_hosts=["h"],
                                 scope_techniques=[])
    with pytest.raises(ValueError):
        await declare_engagement(mssp_session, tenant_id=t.tenant_id, name="x",
                                 kind="pentest", starts_at=_NOW,
                                 ends_at=_NOW + timedelta(days=365),
                                 scope_source_ips=["203.0.113.0/24"], scope_hosts=["h"],
                                 scope_techniques=[])


async def test_deconflict_skips_legacy_all_empty_engagement(mssp_session, seed_two_tenants):
    """A legacy all-empty-scope row must never match-all (declare now forbids it, but
    deconflict is defensive against pre-existing rows)."""
    t, _ = seed_two_tenants
    await mssp_session.execute(
        text("INSERT INTO engagements (id, tenant_id, name, kind, starts_at, ends_at) "
             "VALUES (gen_random_uuid(), :t, 'legacy', 'pentest', :s, :e)"),
        {"t": str(t.tenant_id), "s": _NOW - timedelta(hours=1), "e": _NOW + timedelta(hours=1)},
    )
    await mssp_session.commit()
    r = await deconflict(mssp_session, tenant_id=t.tenant_id, occurred_at=_NOW,
                         source_ips=[SCOPE_IP], hosts=["anything"], techniques=[])
    assert r is None


# --------------------------------------------------------------------- integration


async def test_in_scope_declared_test_lane(mssp_session: AsyncSession, seed_two_tenants):
    t, _ = seed_two_tenants
    await _enable(mssp_session, t.tenant_id)
    await _declare(mssp_session, t.tenant_id)

    r = await triage_event(mssp_session, tenant_id=t.tenant_id, **_ev("s1"))
    await mssp_session.commit()

    assert r["action"] == "declared_test"
    assert await _scalar(mssp_session, "SELECT status FROM alerts WHERE id = :a",
                         a=r["alert_id"]) == "deconflicted"
    # recorded in the lane, NEVER closed / no investigation created
    rows = await _obs(mssp_session, t.tenant_id)
    assert len(rows) == 1 and rows[0]["status"] == "declared_test"
    assert await _scalar(mssp_session,
                         "SELECT count(*) FROM investigations WHERE tenant_id = :t",
                         t=str(t.tenant_id)) == 0


async def test_missing_source_ip_fails_closed(mssp_session: AsyncSession, seed_two_tenants):
    """Fail-closed: an alert on an in-scope host whose source ip is absent/unroled is NOT
    attributable to the tester, so it must NOT be deconflicted — it runs normal triage."""
    t, _ = seed_two_tenants
    await _enable(mssp_session, t.tenant_id)
    await _declare(mssp_session, t.tenant_id)  # scope hosts web-01/02

    # in-scope host, but the ip entity carries no source role → no attributable source ip
    ev = _ev("nosrc")
    ev["evidence"]["entities"] = [{"type": "host", "value": "web-01", "role": "target"},
                                  {"type": "ip", "value": SCOPE_IP}]  # unroled
    r = await triage_event(mssp_session, tenant_id=t.tenant_id, **ev)
    await mssp_session.commit()

    assert r["action"] != "declared_test", r
    assert await _obs(mssp_session, t.tenant_id) == []


async def test_attacker_source_on_scoped_host_not_suppressed(
    mssp_session: AsyncSession, seed_two_tenants
):
    """An alert on an in-scope host from an OUT-OF-SCOPE (non-tester) source ip must not be
    suppressed as a declared test."""
    t, _ = seed_two_tenants
    await _enable(mssp_session, t.tenant_id)
    await _declare(mssp_session, t.tenant_id)

    r = await triage_event(
        mssp_session, tenant_id=t.tenant_id, **_ev("atk", host="web-01", src_ip=OFF_SCOPE_IP)
    )
    await mssp_session.commit()

    assert r["action"] != "declared_test", r


async def test_engagement_without_source_scope_never_deconflicts(
    mssp_session: AsyncSession, seed_two_tenants
):
    """A legacy/manual engagement with host scope but no tester source scope is source-blind
    and must never deconflict."""
    t, _ = seed_two_tenants
    await mssp_session.execute(
        text("INSERT INTO engagements "
             "(id, tenant_id, name, kind, starts_at, ends_at, scope_hosts) "
             "VALUES (gen_random_uuid(), :t, 'no-source', 'pentest', :s, :e, "
             " CAST('[\"web-01\"]' AS JSONB))"),
        {"t": str(t.tenant_id), "s": _NOW - timedelta(hours=1), "e": _NOW + timedelta(hours=1)},
    )
    await mssp_session.commit()
    r = await deconflict(mssp_session, tenant_id=t.tenant_id, occurred_at=_NOW,
                         source_ips=[SCOPE_IP], hosts=["web-01"], techniques=[])
    assert r is None


async def test_out_of_scope_forces_look_and_vetoes_autoclose(
    mssp_session: AsyncSession, seed_two_tenants
):
    """A low-severity alert that would high-conf-FP auto-close, but strays out of scope,
    must be promoted for a real look — never suppressed."""
    t, _ = seed_two_tenants
    await _enable(mssp_session, t.tenant_id, auto_close=True)
    await _declare(mssp_session, t.tenant_id)  # scope: web-01/02

    # in-window, in-scope source, but a host the tester wasn't authorized for
    r = await triage_event(
        mssp_session, tenant_id=t.tenant_id,
        **_ev("oos", host="db-01", severity=2),
    )
    await mssp_session.commit()

    assert r["action"] == "promoted", r  # NOT auto_closed
    rows = await _obs(mssp_session, t.tenant_id)
    assert len(rows) == 1 and rows[0]["status"] == "out_of_scope"


async def test_correlation_wins_over_deconfliction(
    mssp_session: AsyncSession, seed_two_tenants
):
    """A live incident sharing an entity must attach, not be deconflicted away."""
    t, _ = seed_two_tenants
    # 1) build a live incident (correlation on, deconfliction off): a promoted alert
    await _enable(mssp_session, t.tenant_id, deconf=False, correlation=True)
    r1 = await triage_event(
        mssp_session, tenant_id=t.tenant_id,
        **_ev("inc", rule_id="99001", host="web-01", severity=9),
    )
    await mssp_session.commit()
    assert r1["action"] == "promoted"

    # 2) now declare a window covering web-01 and turn deconfliction on
    await _enable(mssp_session, t.tenant_id, deconf=True, correlation=True)
    await _declare(mssp_session, t.tenant_id)

    # 3) a DIFFERENT-signature alert sharing the host entity → must correlate
    r2 = await triage_event(
        mssp_session, tenant_id=t.tenant_id,
        **_ev("share", rule_id="99002", host="web-01", severity=9),
    )
    await mssp_session.commit()
    assert r2["action"] == "correlated", r2
    assert r2["investigation_id"] == r1["investigation_id"]


async def test_declared_test_does_not_reopen_autoclosed_fp(
    mssp_session: AsyncSession, seed_two_tenants
):
    """Deconfliction runs before reopen: a declared-test alert must not resurrect an
    auto-closed FP that shares its rule/asset."""
    t, _ = seed_two_tenants
    # 1) auto-close an alert (deconf off) → an auto_closed_fp with a reopen signature
    await _enable(mssp_session, t.tenant_id, deconf=False, auto_close=True)
    r1 = await triage_event(
        mssp_session, tenant_id=t.tenant_id,
        **_ev("fp", host="web-01", severity=2),
    )
    await mssp_session.commit()
    assert r1["action"] == "auto_closed"
    closed_id = r1["investigation_id"]

    # 2) declare a window covering web-01, enable deconfliction
    await _enable(mssp_session, t.tenant_id, deconf=True, auto_close=True)
    await _declare(mssp_session, t.tenant_id)

    # 3) a matching in-scope alert during the reopen window → declared_test, NOT reopened
    r2 = await triage_event(
        mssp_session, tenant_id=t.tenant_id,
        **_ev("scan", host="web-01", severity=2, ts=_NOW + timedelta(minutes=10)),
    )
    await mssp_session.commit()
    assert r2["action"] == "declared_test", r2
    # the auto-closed investigation is still closed (not reactivated)
    assert await _scalar(mssp_session, "SELECT status FROM investigations WHERE id = :i",
                         i=closed_id) == "auto_closed_fp"


async def test_flag_off_is_no_op(mssp_session: AsyncSession, seed_two_tenants):
    t, _ = seed_two_tenants
    await _enable(mssp_session, t.tenant_id, deconf=False, auto_close=True)
    await _declare(mssp_session, t.tenant_id)

    r = await triage_event(mssp_session, tenant_id=t.tenant_id, **_ev("off", severity=2))
    await mssp_session.commit()

    assert r["action"] != "declared_test"
    assert await _obs(mssp_session, t.tenant_id) == []


async def test_tenant_isolation(mssp_session: AsyncSession, seed_two_tenants):
    """Tenant A's engagement cannot deconflict tenant B's identical alert."""
    ta, tb = seed_two_tenants
    await _enable(mssp_session, ta.tenant_id)
    await _enable(mssp_session, tb.tenant_id)
    await _declare(mssp_session, ta.tenant_id)  # only tenant A declares a window

    r = await triage_event(mssp_session, tenant_id=tb.tenant_id, **_ev("b1"))
    await mssp_session.commit()

    assert r["action"] != "declared_test"
    assert await _obs(mssp_session, tb.tenant_id) == []
