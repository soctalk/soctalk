"""The non-overridable safety floor on the auto-close path (issue #43).

Auto-close happens in two planes, and the floor must veto in both:

- the runs-worker maps a graph terminal state to a ``close_fp`` disposition
  (``runs_worker/main.py``) which ``complete_run()`` applies as ``auto_closed_fp`` —
  ``worker_close_vetoes`` below is the pure check for that plane;
- the IR ingest path applies memoized and rules auto-close after correlation
  (``core/ir/triage.py``) — that plane needs the DB (active-incident lookup), so its
  check lives in ``triage.py`` next to the close sites and shares this module's
  reason vocabulary.

The floor is enforced by the executor, is not expressible in a playbook, and always
applies — a playbook can only add stricter gates. Without this, a misconfigured or
malicious playbook becomes a detection-suppression channel.
"""

from __future__ import annotations

from typing import Any

from soctalk.authorization.render import has_malicious_signal, parse_authorization_context
from soctalk.playbook.guard import derive_authz_class

VETO_IOC = "ioc_present"
VETO_UNVERIFIED_IOC = "ioc_unverified"
VETO_ACTIVE_INCIDENT = "active_incident"
VETO_AUTHZ_CONTRADICTED = "authorization_contradicted"

# Audit action for floor vetoes on the API/IR planes (queried like other ir.* rows).
FLOOR_AUDIT_ACTION = "ir.playbook.close_floor_veto"


def worker_close_vetoes(final_state: dict[str, Any]) -> list[str]:
    """Floor reasons that forbid a ``close_fp`` disposition for this graph run.

    Pure over the graph's terminal state. Three vetoes:

    - IOC: a malicious enrichment verdict or a MISP IOC match — the exact signal the
      verdict prompt warns about (shared helper so prompt and floor can't disagree).
      Deliberately NOT raw un-enriched ``initial_iocs`` on a verdict-tier close: the
      reasoning model saw them listed in its prompt and judged them, and vetoing
      every close that carries an extracted indicator would escalate the entire
      benign-FP stream (the over-ruling-into-SOAR failure the issue warns against).
      Raw IOCs veto on the ingest plane, where closes happen with NO look.
    - unverified IOC: a close with NO verdict (the supervisor's router-tier CLOSE
      short-circuit) while IOC observables were never enriched. The router alone —
      cheapest model, no reasoning pass, no TI — must not be able to close over
      indicators nothing ever looked at.
    - contradicted authorization: the deterministic engine says records are present
      but do not cover. This backstops the in-graph verdict_guard for terminal
      states that never pass a verdict.
    - ``correlation.active_incident``: honored when a future claim payload carries
      it; today's claims don't, so the active-incident floor is enforced server-side
      in ``complete_run()`` and on the IR ingest plane.
    """
    vetoes: list[str] = []
    investigation = final_state.get("investigation") or {}
    if has_malicious_signal(investigation):
        vetoes.append(VETO_IOC)
    if not final_state.get("verdict") and _has_unenriched_observables(investigation):
        vetoes.append(VETO_UNVERIFIED_IOC)
    authz_class, _ = derive_authz_class(parse_authorization_context(investigation))
    if authz_class == "contradicted":
        vetoes.append(VETO_AUTHZ_CONTRADICTED)
    correlation = final_state.get("correlation") or {}
    if isinstance(correlation, dict) and correlation.get("active_incident"):
        vetoes.append(VETO_ACTIVE_INCIDENT)
    return vetoes


def _has_unenriched_observables(investigation: dict[str, Any]) -> bool:
    """Any IOC observable on the investigation that no enrichment ever covered.
    Observables originate from the alert's ``initial_iocs`` (and worker extraction),
    so an uncovered one is an indicator that was never checked against TI."""
    observables = investigation.get("observables") or []
    if not observables:
        return False
    enriched = {
        (e.get("observable") or {}).get("value")
        for e in investigation.get("enrichments") or []
        if isinstance(e, dict)
    }
    return any(
        isinstance(o, dict) and o.get("value") and o["value"] not in enriched
        for o in observables
    )


def apply_worker_floor(
    final_state: dict[str, Any], disposition: str | None
) -> tuple[str | None, list[str]]:
    """Terminal veto for the runs-worker plane: a ``close_fp`` with floor vetoes
    becomes ``escalate`` (never silently dropped — an analyst sees it). Any other
    disposition passes through untouched."""
    if disposition != "close_fp":
        return disposition, []
    vetoes = worker_close_vetoes(final_state)
    if vetoes:
        return "escalate", vetoes
    return disposition, []
