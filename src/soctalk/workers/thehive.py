"""TheHive worker node for incident response operations."""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any

import structlog

from soctalk.mcp.bindings import get_thehive_client
from soctalk.models.enums import Phase, InvestigationStatus, Severity
from soctalk.models.investigation import InvestigationRunState

logger = structlog.get_logger()


async def thehive_worker_node(
    state: dict[str, Any],
) -> dict[str, Any]:
    """TheHive worker node - handles incident response operations.

    This worker can:
    - Check for existing cases/alerts
    - Create new cases
    - Promote alerts to cases

    Args:
        state: Current graph state.

    Returns:
        Updated state dictionary.
    """
    logger.info("thehive_worker_started")

    client = get_thehive_client()
    investigation_data = state.get("investigation", {})

    # Reconstruct InvestigationRunState object
    investigation = InvestigationRunState(**investigation_data) if isinstance(investigation_data, dict) else investigation_data

    try:
        # Create the case in TheHive. ``thehive_case_id`` is TheHive's
        # external identifier — distinct from our ``investigation_id``
        # (the LangGraph aggregate). The bulk case→investigation rename
        # collapsed both to ``investigation_id``; restored here.
        thehive_case_id = await _create_case(client, investigation)

        if thehive_case_id:
            investigation.thehive_case_id = thehive_case_id
            investigation.status = InvestigationStatus.ESCALATED
            logger.info(
                "thehive_case_created",
                investigation_id=investigation.id,
                thehive_case_id=thehive_case_id,
            )
        else:
            logger.warning("case_creation_failed")
            state["last_error"] = "Failed to create TheHive case"

        state["investigation"] = investigation.model_dump()
        state["current_phase"] = Phase.CLOSED.value

    except Exception as e:
        logger.error("thehive_worker_error", error=str(e))
        state["last_error"] = f"TheHive worker error: {str(e)}"
        state["error_count"] = state.get("error_count", 0) + 1

    state["last_updated"] = datetime.now().isoformat()
    return state


async def _create_case(client: Any, investigation: InvestigationRunState) -> str | None:
    """Create a case in TheHive.

    Args:
        client: TheHive MCP client.
        investigation: InvestigationRunState to create case from.

    Returns:
        Case ID if created, None otherwise.
    """
    # Generate case data from investigation
    case_data = investigation.to_thehive_case_data()

    logger.info(
        "creating_thehive_case",
        title=case_data["title"],
        severity=case_data["severity"],
    )

    try:
        result = await client.call_tool(
            "create_thehive_case",
            {
                "title": case_data["title"],
                "description": case_data["description"],
                "severity": case_data["severity"],
                "tags": case_data["tags"],
                "tlp": case_data["tlp"],
                "pap": case_data["pap"],
            }
        )

        if result:
            # Try to extract case ID from result
            investigation_id = _extract_case_id(result)

            # If case was created successfully, add observables
            if investigation_id:
                await _add_observables_to_case(client, investigation_id, investigation)

            return investigation_id

        return None

    except Exception as e:
        logger.error("failed_to_create_case", error=str(e))
        raise


async def _add_observables_to_case(
    client: Any, investigation_id: str, investigation: InvestigationRunState
) -> None:
    """Add observables to a TheHive case.

    Args:
        client: TheHive MCP client.
        investigation_id: ID of the case to add observables to.
        investigation: InvestigationRunState containing observables.
    """
    from soctalk.models.enums import ObservableType, Verdict

    # Map soctalk observable types to TheHive data types
    type_mapping = {
        ObservableType.IP: "ip",
        ObservableType.DOMAIN: "domain",
        ObservableType.URL: "url",
        ObservableType.HASH_MD5: "hash",
        ObservableType.HASH_SHA1: "hash",
        ObservableType.HASH_SHA256: "hash",
        ObservableType.EMAIL: "mail",
        ObservableType.FILENAME: "filename",
        ObservableType.FQDN: "fqdn",
        ObservableType.USER: "other",
        ObservableType.PROCESS: "other",
        ObservableType.REGISTRY_KEY: "registry",
        ObservableType.UNKNOWN: "other",
    }

    # Track added observables to avoid duplicates
    added_values = set()

    for observable in investigation.observables:
        if observable.value in added_values:
            continue

        thehive_type = type_mapping.get(observable.type, "other")

        # Check if this observable has enrichment results
        enrichment = next(
            (e for e in investigation.enrichments if e.observable.value == observable.value),
            None
        )

        # Determine if it's an IOC based on enrichment verdict
        is_ioc = False
        message = observable.context or ""

        if enrichment:
            is_ioc = enrichment.verdict in (Verdict.MALICIOUS, Verdict.SUSPICIOUS)
            if enrichment.verdict == Verdict.MALICIOUS:
                message = f"[MALICIOUS] {message} - {enrichment.analyzer}: {enrichment.verdict.value}"
            elif enrichment.verdict == Verdict.SUSPICIOUS:
                message = f"[SUSPICIOUS] {message} - {enrichment.analyzer}: {enrichment.verdict.value}"

        # Build tags
        tags = list(observable.tags) if observable.tags else []
        tags.append(f"source:{observable.source}")
        if enrichment:
            tags.append(f"verdict:{enrichment.verdict.value}")
            tags.append(f"analyzer:{enrichment.analyzer}")

        try:
            await client.call_tool(
                "create_case_observable",
                {
                    "investigation_id": investigation_id,
                    "data_type": thehive_type,
                    "data": observable.value,
                    "message": message.strip() if message else None,
                    "ioc": is_ioc,
                    "sighted": True,
                    "tags": tags,
                }
            )
            added_values.add(observable.value)
            logger.debug(
                "observable_added_to_case",
                investigation_id=investigation_id,
                observable=observable.value,
                type=thehive_type,
            )
        except Exception as e:
            logger.warning(
                "failed_to_add_observable",
                investigation_id=investigation_id,
                observable=observable.value,
                error=str(e),
            )

    logger.info(
        "observables_added_to_case",
        investigation_id=investigation_id,
        count=len(added_values),
    )


def _extract_case_id(result: str) -> str | None:
    """Extract case ID from TheHive response.

    Args:
        result: Raw response from TheHive.

    Returns:
        Case ID or None.
    """
    import re

    # Try to parse as JSON first
    try:
        if result.strip().startswith("{"):
            parsed = json.loads(result)
            return parsed.get("_id") or parsed.get("id") or parsed.get("caseId")
    except json.JSONDecodeError:
        pass

    # Try regex patterns
    patterns = [
        r"Case ID:\s*([^\s\n]+)",
        r"_id[\"']?\s*:\s*[\"']?([^\"'\s,}]+)",
        r"case[_-]?id[\"']?\s*:\s*[\"']?([^\"'\s,}]+)",
        r"#(\d+)",  # Case number
    ]

    for pattern in patterns:
        match = re.search(pattern, result, re.IGNORECASE)
        if match:
            return match.group(1)

    # If result looks like a simple ID
    if result and len(result.strip()) < 50 and not " " in result.strip():
        return result.strip()

    return None
