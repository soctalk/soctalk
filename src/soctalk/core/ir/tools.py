"""Tool registry and capability taxonomy.

Tools are declared in code; policies decide whether each tool is
autonomous, analyst-gated, or needs a typed reason. See core-invariants §9.

Usage:

    from soctalk.core.ir.tools import tool, registry

    @tool(
        name="vt.reputation",
        capability=CapabilityClass.READ_EXTERNAL_SILENT,
        cost_tokens=500,
        cost_dollars=0.002,
    )
    async def vt_reputation(ioc: str) -> dict[str, Any]:
        ...
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Awaitable, Callable

from soctalk.core.ir.models import CapabilityClass


class ApprovalPolicy(str, Enum):
    AUTONOMOUS = "autonomous"
    ANALYST_APPROVE = "analyst_approve"
    TYPED_REASON = "typed_reason"
    ESCALATION_REQUIRED = "escalation_required"


# Default approval policy per capability class.
DEFAULT_APPROVAL: dict[CapabilityClass, ApprovalPolicy] = {
    CapabilityClass.READ_LOCAL: ApprovalPolicy.AUTONOMOUS,
    CapabilityClass.READ_EXTERNAL_SILENT: ApprovalPolicy.AUTONOMOUS,
    CapabilityClass.READ_EXTERNAL_ATTRIBUTED: ApprovalPolicy.ANALYST_APPROVE,
    CapabilityClass.WRITE_SANDBOX: ApprovalPolicy.ANALYST_APPROVE,
    CapabilityClass.WRITE_EXTERNAL: ApprovalPolicy.TYPED_REASON,
}


@dataclass
class ToolSpec:
    name: str
    capability: CapabilityClass
    description: str = ""
    cost_tokens: int = 0
    cost_dollars: float = 0.0
    cost_wall_ms: int = 0
    footprint: bool = False  # leaves a trace at the target
    handler: Callable[..., Awaitable[Any]] | None = None


class ToolRegistry:
    """Simple in-memory registry. Tools register at import time."""

    def __init__(self) -> None:
        self._tools: dict[str, ToolSpec] = {}

    def register(self, spec: ToolSpec) -> None:
        if spec.name in self._tools:
            raise ValueError(f"tool {spec.name!r} already registered")
        self._tools[spec.name] = spec

    def get(self, name: str) -> ToolSpec | None:
        return self._tools.get(name)

    def list(self) -> list[ToolSpec]:
        return list(self._tools.values())


registry = ToolRegistry()


def tool(
    *,
    name: str,
    capability: CapabilityClass,
    description: str = "",
    cost_tokens: int = 0,
    cost_dollars: float = 0.0,
    cost_wall_ms: int = 0,
    footprint: bool = False,
) -> Callable[[Callable[..., Awaitable[Any]]], Callable[..., Awaitable[Any]]]:
    """Decorator that registers an async function as a tool."""

    def _wrap(fn: Callable[..., Awaitable[Any]]) -> Callable[..., Awaitable[Any]]:
        spec = ToolSpec(
            name=name,
            capability=capability,
            description=description or (fn.__doc__ or "").strip(),
            cost_tokens=cost_tokens,
            cost_dollars=cost_dollars,
            cost_wall_ms=cost_wall_ms,
            footprint=footprint,
            handler=fn,
        )
        registry.register(spec)
        fn.__tool_spec__ = spec  # type: ignore[attr-defined]
        return fn

    return _wrap


def approval_policy_for(
    capability: CapabilityClass, overrides: dict[str, ApprovalPolicy] | None = None
) -> ApprovalPolicy:
    if overrides and capability.value in overrides:
        return overrides[capability.value]
    return DEFAULT_APPROVAL[capability]


# ---------------------------------------------------------------------------
# Built-in tool stubs (read_local and read_external_silent)
# The real implementations land when we wire the specific integrations.
# These stubs make sure the registry has something at boot.
# ---------------------------------------------------------------------------


@tool(
    name="investigation.list_iocs",
    capability=CapabilityClass.READ_LOCAL,
    description="List IOCs currently attached to an investigation.",
    cost_tokens=50,
)
async def _tool_list_iocs(investigation_id: str) -> dict[str, Any]:
    return {"not_implemented": True, "investigation_id": investigation_id}


@tool(
    name="investigation.list_assets",
    capability=CapabilityClass.READ_LOCAL,
    description="List assets currently linked to an investigation.",
    cost_tokens=50,
)
async def _tool_list_assets(investigation_id: str) -> dict[str, Any]:
    return {"not_implemented": True, "investigation_id": investigation_id}


__all__ = [
    "ApprovalPolicy",
    "CapabilityClass",
    "DEFAULT_APPROVAL",
    "ToolRegistry",
    "ToolSpec",
    "approval_policy_for",
    "registry",
    "tool",
]
