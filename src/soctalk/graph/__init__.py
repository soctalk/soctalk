"""LangGraph definition and nodes for SecOps agent.

Submodules are imported lazily: eager ``from .builder import ...`` here
created a cycle (builder → supervisor.node → soctalk.graph.budget →
this __init__ → builder) that broke any cold import reaching the
supervisor package first.
"""

from typing import Any

__all__ = [
    "human_review_node",
    "close_investigation_node",
    "build_secops_graph",
]


def __getattr__(name: str) -> Any:
    if name == "human_review_node":
        from soctalk.graph.hil import human_review_node

        return human_review_node
    if name == "close_investigation_node":
        from soctalk.graph.close import close_investigation_node

        return close_investigation_node
    if name == "build_secops_graph":
        from soctalk.graph.builder import build_secops_graph

        return build_secops_graph
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
