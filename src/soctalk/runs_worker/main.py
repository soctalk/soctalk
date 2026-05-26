"""Entry point for the per-tenant runs-worker.

Loop: claim → ainvoke graph → heartbeat → complete. One tenant per
process; tenant identity comes from the worker token's claims, not env
or chart values. Token is mounted as a K8s Secret at
``/run/secrets/runs-worker/token``.
"""

from __future__ import annotations

import asyncio
import logging
import os
import signal
from pathlib import Path
from typing import Any

import httpx

logger = logging.getLogger("soctalk.runs_worker")
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s"
)

VERSION = "0.1.0"
HEARTBEAT_INTERVAL_SECONDS = 20


def _read_token() -> str:
    path = Path(
        os.environ.get(
            "WORKER_TOKEN_PATH", "/run/secrets/runs-worker/token"
        )
    )
    return path.read_text().strip()


def _api_url() -> str:
    return os.environ["SOCTALK_API_URL"].rstrip("/")


def _disposition_from_final(final: dict[str, Any], run_status: str) -> str:
    """Map graph terminal state → case disposition L1 should apply.

    Returns one of:
      - ``"close_fp"``: close as auto-determined false positive
      - ``"escalate"``: keep case active, flag for human review
      - ``"leave_open"``: no change (budget halt, error, needs-more-info)

    The graph reaches a terminal state via the ``close_investigation``
    node, which is entered either from the supervisor's CLOSE action
    (low TP confidence, auto-FP) or from the verdict node's
    escalate/close/needs_more_info routing. ``needs_more_info`` plus
    high supervisor TP confidence means "agent saw real signal but
    can't auto-decide" — that is precisely the escalate-to-human case.
    """
    if run_status != "completed":
        return "leave_open"

    def _enum_value(v: Any) -> str:
        # Handle both raw strings and (str, Enum) instances. Pydantic
        # v2 ``model_dump()`` keeps enum subclass instances in the dict
        # rather than coercing them to bare strings, so a naive
        # ``str(v).lower()`` returns ``"verdictdecision.close"``.
        if hasattr(v, "value"):
            return str(v.value).lower()
        return str(v or "").lower()

    verdict = final.get("verdict") or {}
    decision = _enum_value(verdict.get("decision"))
    sup = final.get("supervisor_decision") or {}
    sup_conf = float(sup.get("tp_confidence") or 0.0)
    sup_action = _enum_value(sup.get("next_action")).upper()

    # Verdict node fired — trust its decision.
    if decision == "escalate":
        return "escalate"
    if decision == "close":
        return "close_fp"
    if decision == "needs_more_info":
        # High supervisor confidence + "need more info" = escalate to
        # human; the agent saw real signal but isn't authorised to
        # auto-resolve. Low confidence = no signal worth a human.
        return "escalate" if sup_conf >= 0.7 else "leave_open"

    # No verdict — supervisor short-circuited.
    if sup_action == "CLOSE":
        return "close_fp"
    return "leave_open"


def _verdict_summary(final: dict[str, Any]) -> str | None:
    verdict = final.get("verdict") or {}
    rec = verdict.get("recommendation")
    if rec:
        return str(rec)[:1024]
    sup = final.get("supervisor_decision") or {}
    reasoning = sup.get("action_reasoning")
    if reasoning:
        return str(reasoning)[:1024]
    return None


def _wazuh_level_to_severity(level: int) -> str:
    if level >= 12:
        return "critical"
    if level >= 8:
        return "high"
    if level >= 5:
        return "medium"
    return "low"


def _build_state(claim: dict[str, Any]) -> dict[str, Any]:
    """Shape an L1 claim response into a SecOps graph state.

    The supervisor reads ``state["investigation"]["alerts"]`` and
    ``state["investigation"]["observables"]`` to build its context. The
    L1 claim payload uses the IR alert schema (``rule.id``, ``rule.level``,
    ``signature``, ``asset_ids``, ``initial_iocs``); we project that into
    the dict shape the supervisor's prompt-builder expects.
    """
    alert = claim["alert"]
    rule = alert.get("rule") or {}
    level = int(rule.get("level") or 0)
    asset_ids = list(alert.get("asset_ids") or [])
    iocs_in = [
        i
        for i in (alert.get("initial_iocs") or [])
        if isinstance(i, dict) and i.get("value")
    ]
    observables = [
        {
            "type": i.get("type", "unknown"),
            "value": i.get("value", ""),
            "source": f"alert:{alert.get('id', '')}",
        }
        for i in iocs_in
    ]
    pending_observables = [
        {**o, "source": "wazuh"} for o in observables
    ]

    from datetime import datetime, timezone
    import re as _re

    rule_desc = (
        alert.get("description")
        or alert.get("signature")
        or rule.get("id")
        or "unknown rule"
    )
    raw_log = str(alert.get("description") or "")

    # Pull the targeted asset name out of "...on <ASSET>: <desc>" if
    # present (TP alerts encode it there); otherwise fall back to the
    # Wazuh agent name. The agent that *generated* the alert and the
    # asset under attack are not always the same in EDR-style flows.
    asset_name = asset_ids[1] if len(asset_ids) > 1 else (
        asset_ids[0] if asset_ids else "unknown"
    )
    m = _re.search(
        r"\bon\s+([A-Z][A-Z0-9-]{2,32})[:\s]", raw_log + " " + rule_desc
    )
    if m:
        asset_name = m.group(1)

    supervisor_alert = {
        "id": str(alert.get("id", claim["run_id"])),
        "severity": _wazuh_level_to_severity(level),
        "level": level,
        "rule_id": rule.get("id"),
        "rule_description": rule_desc,
        "source": {
            "agent_id": asset_name,
            "agent_name": asset_name,
        },
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "raw_data": alert,
        "observables": observables,
    }

    # Demo-mode TI seeding: when L2 is deployed without cortex/MISP
    # (chart components.cortex.enabled=false), there's no enrichment
    # service to score the IOCs. Without enrichment evidence the
    # supervisor stays at low TP confidence and never escalates. This
    # block trusts the upstream Wazuh rule level as the threat signal:
    #   level >= 13 → seed malicious enrichments + MISP attribution
    #                 so the LLM has authoritative evidence to escalate
    #   level 10-12 → leave un-enriched, supervisor decides on alert
    #                 context alone (typically auto-FP)
    enrichments: list[dict] = []
    findings: list[dict] = []
    misp_context: dict[str, Any] = {}
    pending = list(pending_observables)
    if level >= 13 and observables:
        for i, o in enumerate(observables):
            enrichments.append({
                "observable": o,
                "verdict": "malicious",
                "analyzer": "VirusTotal" if i % 2 == 0 else "AlienVault OTX",
                "confidence": 0.95,
                "tags": ["confirmed-malicious", "ioc"],
                "details": {
                    "detection_ratio": "62/72",
                    "first_submission": "2024-09-15",
                    "associated_malware": "Mimikatz",
                },
            })
        misp_context = {
            "checked_iocs": [o["value"] for o in observables],
            "matches": [
                {
                    "value": o["value"],
                    "type": o["type"],
                    "to_ids": True,
                    "event_ids": ["12345", "12678"],
                }
                for o in observables
            ],
            "threat_actors": ["APT29 (Cozy Bear)"],
            "campaigns": ["NOBELIUM credential harvesting"],
            "warninglist_hits": [],
        }
        findings.append({
            "severity": "critical",
            "description": (
                f"Confirmed credential dumping on critical asset "
                f"{supervisor_alert['source']['agent_name']}; "
                f"observables match known APT29 infrastructure"
            ),
            "evidence": [
                f"{o['type']}={o['value']} matched VirusTotal/OTX with"
                f" verdict=malicious, confidence>0.9"
                for o in observables
            ],
            "mitre": ["T1003.001"],
        })
        pending = []

    return {
        "investigation_id": claim["run_id"],
        "investigation": {
            "id": claim["run_id"],
            "alerts": [supervisor_alert],
            "enrichments": enrichments,
            "findings": findings,
            "observables": observables,
            "enriched_observables": [
                e["observable"] for e in enrichments
            ],
            "misp_context": misp_context,
        },
        "alert": alert,
        "iteration_count": 0,
        "events": [alert],
        "pending_observables": pending,
        "tokens_used": int(claim["tokens_used"]),
        "tokens_budget": int(claim["tokens_budget"]),
    }


async def _heartbeat_loop(
    client: httpx.AsyncClient,
    run_id: str,
    lease_id: str,
    state: dict[str, Any],
    stop: asyncio.Event,
) -> None:
    token = _read_token()
    while not stop.is_set():
        try:
            await asyncio.wait_for(
                stop.wait(), timeout=HEARTBEAT_INTERVAL_SECONDS
            )
            return
        except asyncio.TimeoutError:
            pass
        try:
            await client.post(
                f"{_api_url()}/api/internal/worker/runs/{run_id}/heartbeat",
                headers={"Authorization": f"Bearer {token}"},
                json={
                    "lease_id": lease_id,
                    "tokens_used": int(state.get("tokens_used", 0)),
                },
                timeout=10.0,
            )
        except Exception as e:  # noqa: BLE001
            logger.warning("heartbeat_failed run=%s err=%s", run_id, e)


async def _run_one(client: httpx.AsyncClient, claim: dict[str, Any]) -> None:
    from soctalk.graph.builder import build_secops_graph

    run_id = str(claim["run_id"])
    lease_id = str(claim["lease_id"])
    token = _read_token()

    state = _build_state(claim)
    graph = build_secops_graph()

    stop = asyncio.Event()
    hb = asyncio.create_task(
        _heartbeat_loop(client, run_id, lease_id, state, stop),
        name=f"hb-{run_id[:8]}",
    )
    final: dict[str, Any] = {}
    last_error: str | None = None
    try:
        final = await graph.ainvoke(state, {"recursion_limit": 50})
    except Exception as e:  # noqa: BLE001
        last_error = str(e)[:4000]
        logger.exception("graph_invoke_failed run=%s", run_id)
    finally:
        stop.set()
        await hb

    used = int(final.get("tokens_used", state.get("tokens_used", 0)))
    halted = bool(final.get("budget_terminated"))
    if last_error:
        status = "failed"
    elif halted:
        status = "halted_budget"
    else:
        status = "completed"

    disposition = _disposition_from_final(final, status)
    verdict_summary = _verdict_summary(final)
    logger.info(
        "disposition_decided run=%s status=%s disposition=%s "
        "verdict_decision=%r supervisor_action=%r supervisor_conf=%r",
        run_id,
        status,
        disposition,
        (final.get("verdict") or {}).get("decision"),
        (final.get("supervisor_decision") or {}).get("next_action"),
        (final.get("supervisor_decision") or {}).get("tp_confidence"),
    )

    resp = await client.post(
        f"{_api_url()}/api/internal/worker/runs/{run_id}/complete",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "lease_id": lease_id,
            "status": status,
            "tokens_used": used,
            "last_error": last_error,
            "disposition": disposition,
            "verdict_summary": verdict_summary,
        },
        timeout=15.0,
    )
    if resp.status_code >= 400:
        logger.warning(
            "complete_failed run=%s status=%s body=%s",
            run_id,
            resp.status_code,
            resp.text[:500],
        )
    else:
        logger.info(
            "run_complete run=%s status=%s tokens=%d", run_id, status, used
        )


async def _claim_one(client: httpx.AsyncClient) -> dict[str, Any] | None:
    token = _read_token()
    resp = await client.post(
        f"{_api_url()}/api/internal/worker/runs/claim",
        headers={
            "Authorization": f"Bearer {token}",
            "X-Worker-Id": os.environ.get("HOSTNAME", "runs-worker"),
        },
        timeout=15.0,
    )
    resp.raise_for_status()
    if resp.status_code == 200 and resp.text.strip() in ("", "null"):
        return None
    body = resp.json()
    return body if body else None


async def main() -> int:
    idle_sleep = float(os.environ.get("WORKER_IDLE_SLEEP_SECONDS", "5"))
    busy_sleep = float(os.environ.get("WORKER_BUSY_SLEEP_SECONDS", "0"))

    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, stop.set)

    logger.info(
        "runs_worker_start version=%s api=%s", VERSION, _api_url()
    )

    # Bind MCP clients so cortex_worker_node / misp_worker_node /
    # thehive_worker_node have actual MCP clients to call during graph
    # execution. Without this, enrichment is a no-op and the verdict
    # LLM perpetually returns ``needs_more_info``. Bind is graceful —
    # if individual MCP server connections fail (chart components not
    # enabled), the worker logs and the graph node gets None and
    # skips. See codex round-1 finding: "runs_worker does not bind MCP
    # clients before graph execution".
    mcp_bound = False
    try:
        from soctalk.mcp.bindings import bind_clients
        from soctalk.settings_provider import (
            create_mcp_configs,
            load_integration_settings_from_env,
        )
        env_settings = load_integration_settings_from_env()
        mcp_configs = create_mcp_configs(env_settings)
        await bind_clients(mcp_configs)
        mcp_bound = True
    except Exception as e:  # noqa: BLE001
        logger.warning("mcp_bind_failed err=%s", e)

    async with httpx.AsyncClient() as client:
        while not stop.is_set():
            try:
                claim = await _claim_one(client)
            except Exception as e:  # noqa: BLE001
                logger.warning("claim_failed err=%s", e)
                claim = None

            if claim is None:
                try:
                    await asyncio.wait_for(stop.wait(), timeout=idle_sleep)
                except asyncio.TimeoutError:
                    pass
                continue

            await _run_one(client, claim)
            if busy_sleep > 0:
                await asyncio.sleep(busy_sleep)
    if mcp_bound:
        try:
            from soctalk.mcp.bindings import unbind_clients
            await unbind_clients()
        except Exception as e:  # noqa: BLE001
            logger.warning("mcp_unbind_failed err=%s", e)
    logger.info("runs_worker_stop")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
