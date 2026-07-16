"""Sandboxed condition language for triage policy guardrails (issue #44).

A deliberately tiny JSONLogic subset, implemented natively (no dependency, no
dynamic evaluation): a condition is a nested dict of ALLOWLISTED operators over
DECLARED state-contract fields, and nothing else. Sandboxing is by construction —
there is no attribute access, no call syntax, no string formatting, no way to name
anything outside ``STATE_CONTRACT``.

Author-time validation (``validate_condition``) fails closed: an unknown operator
or an undeclared field rejects the whole condition (and its triage policy file). At
eval time a missing value is ``None`` and comparisons with ``None`` are simply
falsy — a guardrail can only fire on evidence that is actually present.

The state contract (#43): the four expectedness components and the derived class,
the LLM draft verdict + confidence, trust-resolved asset attributes, and the
malicious-signal / active-incident flags. A condition may reference only these.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

# The documented read-only surface conditions may reference. Additions are
# deliberate API decisions — never reflect arbitrary state in.
STATE_CONTRACT: frozenset[str] = frozenset(
    {
        "authz.class",
        "authz.in_scope",
        "authz.sanctioned_or_routine",
        "authz.actor_genuine",
        "authz.policy_allowed",
        "verdict",
        "verdict_confidence",
        "asset.data_classification",
        "asset.environment",
        "asset.criticality",
        "enrichment.ioc",
        "correlation.active_incident",
    }
)

# Operator allowlist. ``var`` reads a contract field; everything else combines.
_COMPARISONS = {"==", "!=", "<", "<=", ">", ">="}
_LOGIC = {"and", "or", "!", "!!"}
_MEMBERSHIP = {"in"}
ALLOWED_OPERATORS: frozenset[str] = frozenset(
    {"var"} | _COMPARISONS | _LOGIC | _MEMBERSHIP
)

_MAX_DEPTH = 8
_MAX_NODES = 64
_MAX_LIST_LITERAL = 32


class ConditionError(ValueError):
    """A condition failed author-time validation."""


def _walk_validate(node: Any, depth: int, counter: list[int]) -> None:
    counter[0] += 1
    if counter[0] > _MAX_NODES:
        raise ConditionError(f"condition exceeds {_MAX_NODES} nodes")
    if depth > _MAX_DEPTH:
        raise ConditionError(f"condition exceeds depth {_MAX_DEPTH}")
    if isinstance(node, Mapping):
        if len(node) != 1:
            raise ConditionError(
                "each condition node must be a single {operator: args} mapping"
            )
        (op, args), = node.items()
        if op not in ALLOWED_OPERATORS:
            raise ConditionError(f"operator {op!r} is not allowed")
        if op == "var":
            if not isinstance(args, str):
                raise ConditionError("var takes a single dotted field name string")
            if args not in STATE_CONTRACT:
                raise ConditionError(
                    f"field {args!r} is not in the declared state contract"
                )
            return
        args_list = args if isinstance(args, list) else [args]
        if op in _COMPARISONS and len(args_list) != 2:
            raise ConditionError(f"{op} takes exactly 2 arguments")
        if op == "in" and len(args_list) != 2:
            raise ConditionError("in takes exactly 2 arguments")
        if op in ("!", "!!") and len(args_list) != 1:
            raise ConditionError(f"{op} takes exactly 1 argument")
        for a in args_list:
            _walk_validate(a, depth + 1, counter)
        return
    if isinstance(node, (str, int, float, bool)) or node is None:
        return
    if isinstance(node, list):
        # bare lists appear only as literal membership targets for ``in``
        if len(node) > _MAX_LIST_LITERAL:
            raise ConditionError(
                f"list literals are capped at {_MAX_LIST_LITERAL} entries"
            )
        for a in node:
            if not (isinstance(a, (str, int, float, bool)) or a is None):
                raise ConditionError("list literals may contain only scalars")
        return
    raise ConditionError(f"unsupported node type {type(node).__name__}")


def validate_condition(condition: Any) -> None:
    """Author-time validation: raises ConditionError unless the condition is a
    well-formed allowlisted-operator tree over declared contract fields."""
    if not isinstance(condition, Mapping):
        raise ConditionError("a condition must be a mapping at its root")
    _walk_validate(condition, 0, [0])


def _lookup(ctx: Mapping[str, Any], dotted: str) -> Any:
    node: Any = ctx
    for part in dotted.split("."):
        if not isinstance(node, Mapping):
            return None
        node = node.get(part)
    return node


def evaluate_condition(condition: Any, ctx: Mapping[str, Any]) -> bool:
    """Evaluate a VALIDATED condition against the contract context. Total: any
    unexpected shape at runtime evaluates falsy rather than raising — a guardrail
    must never take down the guard."""
    try:
        return bool(_eval(condition, ctx))
    except Exception:  # noqa: BLE001 — malformed-at-runtime = does not fire
        return False


def _eval(node: Any, ctx: Mapping[str, Any]) -> Any:
    if isinstance(node, Mapping):
        (op, args), = node.items()
        if op == "var":
            return _lookup(ctx, args)
        args_list = args if isinstance(args, list) else [args]
        vals = [_eval(a, ctx) for a in args_list]
        if op == "==":
            return vals[0] == vals[1]
        if op == "!=":
            return vals[0] != vals[1]
        if op in ("<", "<=", ">", ">="):
            a, b = vals
            if a is None or b is None:
                return False
            return {"<": a < b, "<=": a <= b, ">": a > b, ">=": a >= b}[op]
        if op == "and":
            return all(bool(v) for v in vals)
        if op == "or":
            return any(bool(v) for v in vals)
        if op == "!":
            return not bool(vals[0])
        if op == "!!":
            return bool(vals[0])
        if op == "in":
            container = vals[1]
            if isinstance(container, (list, tuple, set, str)):
                return vals[0] in container
            return False
        raise ValueError(f"operator {op!r} not allowed")  # unreachable post-validate
    return node
