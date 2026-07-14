"""Render an investigation's authorization_context into prompt/report text.

The section presents evidence grouped under the four expectedness components BY NAME but never
prints computed component booleans — the LLM must reason from the records, not copy an answer
(and the golden eval would otherwise measure string-copying). Two invariants (§8 guardrails):

  - absence is first-class: a present-but-empty context renders an explicit "do not assume
    authorized" line, and a missing key renders NOTHING (existing prompts stay byte-identical);
  - authorization lowers suspicion, never overrides malicious signal: when the investigation
    carries malicious enrichments or MISP IOC matches, a fixed warning line is appended.
"""

from __future__ import annotations

from typing import Any

import structlog
from pydantic import ValidationError

from soctalk.models.authorization import (
    AuthorizationContext,
    AuthorizationFact,
    AuthorizationTrack,
    ChangeFreezeFact,
    EntityContextFact,
    GrantFact,
    ProhibitionFact,
)

logger = structlog.get_logger()

_GROUP_CAP = 8  # facts rendered per component group before an overflow line

MALICIOUS_SIGNAL_WARNING = (
    "⚠ Malicious indicators are present in this investigation — authorization evidence "
    "must NOT be used to close it. Escalate on the malicious signal."
)

NO_EVIDENCE_LINE = (
    "No authorization evidence available for this activity — do not assume it was authorized. "
    "Treat missing authorization evidence as grounds for escalation or human review, never as "
    "implicit approval."
)

AUTHORIZATION_RULES_LINE = (
    "Authorization evidence lowers suspicion ONLY when a single record fully covers the "
    "activity (right subject, target, action, time window, calendar validity, approvals). "
    "Never combine partial records. Expired, pending, not-yet-effective, unapproved-CAB, "
    "out-of-window, or frozen records do not cover. It never overrides malicious indicators."
)


def parse_authorization_context(investigation: dict[str, Any]) -> AuthorizationContext | None:
    """The investigation's authorization_context, or None when absent/invalid.

    Invalid payloads are dropped with a warning: bad evidence is NO evidence (fail safe) —
    it must never be rendered half-parsed into a prompt.
    """
    raw = investigation.get("authorization_context")
    if raw is None:
        return None
    if isinstance(raw, AuthorizationContext):
        return raw
    try:
        return AuthorizationContext.model_validate(raw)
    except ValidationError as exc:
        logger.warning("authorization_context_invalid", errors=exc.error_count())
        return None


def _verdict_value(enrichment: Any) -> str:
    """The enrichment verdict as a plain lowercase string, across the shapes that reach the
    prompt builders: plain dicts, typed EnrichmentResult models, str or Enum verdicts."""
    value = (
        enrichment.get("verdict")
        if isinstance(enrichment, dict)
        else getattr(enrichment, "verdict", None)
    )
    if value is None:
        return ""
    return str(getattr(value, "value", value)).lower()


def _has_malicious_signal(investigation: dict[str, Any]) -> bool:
    enrichments = investigation.get("enrichments", []) or []
    if any(_verdict_value(e) == "malicious" for e in enrichments):
        return True
    misp = investigation.get("misp_context") or {}
    return bool(isinstance(misp, dict) and misp.get("matches"))


def render_fact_line(fact: AuthorizationFact) -> str:
    tag = f"[{fact.source_type.value}, trust {fact.trust}]"
    s = fact.scope
    if isinstance(fact, GrantFact):
        parts = [f"{fact.grant_class.value} {fact.id}:"]
        if s.subject:
            parts.append(f"subject={s.subject}")
        if s.target:
            parts.append(f"target={s.target}")
        if s.action:
            parts.append(f"action={s.action}")
        if s.change_type:
            parts.append(f"change_type={s.change_type.value}")
        if s.recurring_window:
            parts.append(f"window={s.recurring_window.start}-{s.recurring_window.end}")
        # full ISO bounds: "effective from" is as decision-relevant as expiry (a
        # future-effective ticket must be visibly not-yet-effective to the reader)
        if fact.valid_from:
            parts.append(f"effective_from={fact.valid_from.isoformat()}")
        if fact.valid_until:
            parts.append(f"valid_until={fact.valid_until.isoformat()}")
        parts.append(f"status={fact.status.value}")
        if fact.cab_required:
            parts.append(f"CAB approved={fact.cab_approved}")
        if fact.emergency:
            parts.append("emergency")
        if fact.freeze_exception:
            parts.append("freeze-exception")
        if fact.seen_count is not None:
            parts.append(f"seen_count={fact.seen_count} ioc={bool(fact.ioc)}")
        return f"- {' '.join(parts)} {tag}"
    if isinstance(fact, ProhibitionFact):
        parts = [f"policy {fact.id}: priority={fact.priority.value}"]
        if fact.forbid_action:
            parts.append(f"forbids action={fact.forbid_action}")
        if fact.forbid_change_type is not None:
            parts.append(f"forbids change_types={','.join(fact.forbid_change_type) or 'none'}")
        if fact.forbid_account_type:
            parts.append(f"account_type={fact.forbid_account_type.value}")
        a = fact.applies_to
        scopes = []
        if a.env is not None:
            scopes.append(f"env={','.join(a.env) or '(none)'}")
        if a.criticality is not None:
            scopes.append(f"criticality={','.join(a.criticality) or '(none)'}")
        if a.data_class is not None:
            scopes.append(f"data_class={','.join(a.data_class) or '(none)'}")
        if a.config_class:
            scopes.append(f"config_class={','.join(a.config_class)}")
        if scopes:
            parts.append(f"applies_to({' '.join(scopes)})")
        if fact.waiver_present:
            parts.append("WAIVER on file")
        if fact.break_glass_exception:
            parts.append("break-glass exception allowed")
        return f"- {' '.join(parts)} {tag}"
    if isinstance(fact, ChangeFreezeFact):
        scope = (
            f"envs={','.join(fact.freeze_scope.envs)}"
            if fact.freeze_scope.envs
            else f"config_classes={','.join(fact.freeze_scope.config_classes)}"
        )
        window = f"{fact.start.isoformat()} → {fact.end.isoformat()}"
        exceptions = (
            f" exceptions={','.join(fact.allowed_exception_ids)}"
            if fact.allowed_exception_ids
            else ""
        )
        return f"- freeze {fact.id}: {scope} {window}{exceptions} {tag}"
    assert isinstance(fact, EntityContextFact)
    parts = [f"{fact.entity_type.value} {fact.name}:"]
    for attr in (
        "account_type", "environment", "criticality", "data_classification", "config_class",
        "owner_org", "compromise_status",
    ):
        value = getattr(fact, attr)
        if value is not None and value != "":
            parts.append(f"{attr}={value.value if hasattr(value, 'value') else value}")
    for flag in ("privileged", "on_call", "break_glass"):
        value = getattr(fact, flag)
        if value is not None:
            parts.append(f"{flag}={value}")
    if fact.linked_orgs:
        parts.append(f"linked_orgs={','.join(fact.linked_orgs)}")
    return f"- {' '.join(parts)} {tag}"


def _activity_line(ctx: AuthorizationContext) -> str:
    a = ctx.activity
    if a.track == AuthorizationTrack.ACCOUNT:
        detail = f"action={a.action} account={a.account} host={a.host}"
        if a.interactive:
            detail += " interactive=true"
    else:
        change = a.change_type.value if a.change_type else "?"
        detail = f"change={change} path={a.path}"
    return f"**Activity:** {detail} time={a.time.isoformat()} ({a.track.value} track)"


def _group(title: str, facts: list[AuthorizationFact]) -> list[str]:
    if not facts:
        return [f"**{title}:** none on record."]
    ordered = sorted(facts, key=lambda f: (-f.trust, f.id))
    lines = [f"**{title}:**"]
    lines.extend(render_fact_line(f) for f in ordered[:_GROUP_CAP])
    if len(ordered) > _GROUP_CAP:
        lines.append(f"- ... and {len(ordered) - _GROUP_CAP} more")
    return lines


def _section_body(ctx: AuthorizationContext, investigation: dict[str, Any]) -> list[str]:
    lines = [_activity_line(ctx)]
    if not ctx.facts:
        lines.append(NO_EVIDENCE_LINE)
    else:
        grants = [f for f in ctx.facts if isinstance(f, GrantFact)]
        freezes = [f for f in ctx.facts if isinstance(f, ChangeFreezeFact)]
        entities = [f for f in ctx.facts if isinstance(f, EntityContextFact)]
        prohibitions = [f for f in ctx.facts if isinstance(f, ProhibitionFact)]
        # the four expectedness components, by name, evidence only — never computed booleans
        lines.extend(_group("Sanction & scope evidence (grants)", list(grants)))
        lines.extend(_group("Freeze status", list(freezes)))
        lines.extend(_group("Actor & target genuineness (entity context)", list(entities)))
        lines.extend(_group("Policy constraints (prohibitions)", list(prohibitions)))
        lines.append(AUTHORIZATION_RULES_LINE)
    if ctx.note:
        lines.append(f"Note: {ctx.note}")
    if _has_malicious_signal(investigation):
        lines.append(MALICIOUS_SIGNAL_WARNING)
    return lines


def supervisor_authorization_lines(investigation: dict[str, Any]) -> list[str]:
    """Lines for _build_context_summary — [] when the investigation has no authorization key,
    so existing prompts are byte-identical (prompt-cache contract)."""
    ctx = parse_authorization_context(investigation)
    if ctx is None:
        return []
    return ["", "### Authorization Context", *_section_body(ctx, investigation)]


def verdict_authorization_detail(investigation: dict[str, Any]) -> str:
    """The {authorization_detail} template value for the verdict prompt — "" when absent so
    the template collapses cleanly."""
    ctx = parse_authorization_context(investigation)
    if ctx is None:
        return ""
    body = "\n".join(_section_body(ctx, investigation))
    return f"## Authorization Context\n\n{body}\n\n"


def to_authorization_case_lines(ctx: AuthorizationContext) -> list[str]:
    """Markdown block for escalated-case descriptions (TheHive). Unlike the prompts, this MAY
    state the deterministic engine components — it is an audit artifact, not model input."""
    from soctalk.authorization.engine import evaluate_authorization

    comps = evaluate_authorization(ctx.activity, ctx.facts, ctx.tenant)
    lines = ["## Authorization Context", "", _activity_line(ctx)]
    lines.append(
        "**Deterministic components:** "
        f"sanctioned_or_routine={comps.sanctioned_or_routine} in_scope={comps.in_scope} "
        f"actor_genuine={comps.actor_genuine} policy_allowed={comps.policy_allowed}"
    )
    for fact in sorted(ctx.facts, key=lambda f: (f.kind, -f.trust, f.id))[:10]:
        lines.append(render_fact_line(fact))
    if len(ctx.facts) > 10:
        lines.append(f"- ... and {len(ctx.facts) - 10} more facts")
    return lines
