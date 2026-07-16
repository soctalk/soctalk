"""Vetted response capabilities — the ONLY actions a response playbook can name.

A playbook references a capability by name and can reference nothing else;
resolution of an unknown name fails closed at author time (schema validation)
AND at execution time (the outbox handler). Phase 1 registers tier-0 only:
actions whose blast radius is a case annotation or an operator-configured
notification. Endpoint-impacting capabilities (block/disable/isolate) are
deliberately absent until the approval plane is proven (#49 phasing).

Capability classes reuse the ``core.ir`` taxonomy (``CapabilityClass``,
``ApprovalPolicy``). Tier-0 capabilities are explicitly AUTONOMOUS even where
the class default would gate them (``notify_webhook`` is ``write_external`` →
default ``typed_reason``): the override is justified because the target is an
operator-configured notification connector — SocTalk hands a signed envelope to
an endpoint the MSSP chose, it does not act on customer infrastructure. Any
future capability that mutates external state MUST NOT copy this override.
"""

from __future__ import annotations

import hashlib
import hmac
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any
from uuid import UUID, uuid4

import structlog
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from soctalk.core.ir.events import canonical_json
from soctalk.core.ir.models import CapabilityClass
from soctalk.core.ir.tools import ApprovalPolicy

logger = structlog.get_logger()

# HTTP timeout for the webhook connector. Short on purpose: the executor drains
# the outbox serially per claim and a slow endpoint must not stall the queue —
# retries with backoff are the outbox's job, not a long client timeout's.
_WEBHOOK_TIMEOUT_SECONDS = 10.0
_MAX_NOTE_BODY = 4096

SIGNATURE_HEADER = "X-SocTalk-Signature"
DELIVERY_HEADER = "X-SocTalk-Delivery"


def sign_webhook_body(secret: str, body: bytes) -> str:
    """``sha256=<hex hmac>`` over the exact request bytes — the receiver
    recomputes on the raw body, so the payload must be serialized once and
    signed as sent (no re-serialization between sign and post)."""
    digest = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return f"sha256={digest}"


# Handler contract: (db, tenant_id, payload) -> external_ref | None.
# ``payload`` is the outbox row's payload: {envelope, playbook, capability,
# params, delivery}. Raise to fail the action (the outbox retries per its
# max_attempts budget); return the remote reference for the audit chain.
Handler = Callable[[AsyncSession, UUID, dict[str, Any]], Awaitable[str | None]]


@dataclass(frozen=True)
class ResponseCapability:
    name: str
    capability_class: CapabilityClass
    approval: ApprovalPolicy
    description: str
    handler: Handler


async def _annotate_investigation(
    db: AsyncSession, tenant_id: UUID, payload: dict[str, Any]
) -> str | None:
    """Tier-0: write a system note on the investigation. Local DB write only."""
    envelope = payload.get("envelope") or {}
    params = payload.get("params") or {}
    playbook = payload.get("playbook") or {}
    investigation_id = envelope.get("investigation_id")
    if not investigation_id:
        raise ValueError("envelope missing investigation_id")
    body = str(params.get("body") or "").strip()
    if not body:
        # An empty annotation is an authoring bug — say what fired anyway so
        # the note still carries the audit value the playbook intended.
        body = "response playbook fired"
    suffix = (
        f"\n\n[response playbook {playbook.get('id')}@v{playbook.get('version')} "
        f"on {envelope.get('disposition')}]"
    )
    await db.execute(
        text(
            "INSERT INTO notes (id, tenant_id, investigation_id, author_kind, "
            "                   author_id, body, visibility) "
            "VALUES (:id, :t, :c, 'system', :a, :b, 'mssp_only')"
        ),
        {
            "id": str(uuid4()),
            "t": str(tenant_id),
            "c": str(investigation_id),
            "a": f"response:{playbook.get('id')}",
            "b": (body + suffix)[:_MAX_NOTE_BODY],
        },
    )
    return None


async def _notify_webhook(
    db: AsyncSession, tenant_id: UUID, payload: dict[str, Any]
) -> str | None:
    """Tier-0: POST the signed envelope to the tenant's configured webhook.

    This is the generic external-dispatch connector (#49): the envelope is the
    interop contract, the receiving SOAR/case-manager owns everything after the
    handoff. Config comes from tenant policy rows (``response_webhook_url``,
    optional ``response_webhook_secret``) — no URL in the playbook itself, so a
    playbook author can request a notification but never choose its target.
    """
    import httpx

    from soctalk.core.ir.policies import effective_policy

    policy = await effective_policy(db, tenant_id)
    url = str(policy.get("response_webhook_url") or "").strip()
    if not url.startswith(("https://", "http://")):
        raise ValueError(
            "response_webhook_url tenant policy is missing or not http(s) — "
            "configure the connector before activating a notify_webhook playbook"
        )
    body_obj = {
        "envelope": payload.get("envelope") or {},
        "playbook": payload.get("playbook") or {},
        "params": payload.get("params") or {},
    }
    body = canonical_json(body_obj).encode()
    headers = {
        "Content-Type": "application/json",
        DELIVERY_HEADER: str(payload.get("delivery") or ""),
    }
    secret = str(policy.get("response_webhook_secret") or "")
    if secret:
        headers[SIGNATURE_HEADER] = sign_webhook_body(secret, body)
    async with httpx.AsyncClient(timeout=_WEBHOOK_TIMEOUT_SECONDS) as client:
        resp = await client.post(url, content=body, headers=headers)
    if resp.status_code >= 400:
        raise RuntimeError(f"webhook returned HTTP {resp.status_code}")
    # The remote's request id (when offered) beats a bare status code as the
    # audit chain's external reference.
    remote_ref = resp.headers.get("X-Request-Id") or resp.headers.get("Request-Id")
    return remote_ref or f"http:{resp.status_code}"


RESPONSE_CAPABILITIES: dict[str, ResponseCapability] = {
    cap.name: cap
    for cap in (
        ResponseCapability(
            name="annotate_investigation",
            capability_class=CapabilityClass.WRITE_SANDBOX,
            approval=ApprovalPolicy.AUTONOMOUS,
            description="Write a system note on the investigation (local only).",
            handler=_annotate_investigation,
        ),
        ResponseCapability(
            name="notify_webhook",
            capability_class=CapabilityClass.WRITE_EXTERNAL,
            approval=ApprovalPolicy.AUTONOMOUS,
            description=(
                "POST the signed disposition envelope to the tenant's configured "
                "webhook connector (generic external SOAR handoff)."
            ),
            handler=_notify_webhook,
        ),
    )
}

# A close is the suppression-shaped direction (#43): response actions on
# on_close stay annotation/audit-only until outbox idempotency and the
# approval plane are proven in production (#49 non-negotiables).
ON_CLOSE_ALLOWED: frozenset[str] = frozenset({"annotate_investigation"})
