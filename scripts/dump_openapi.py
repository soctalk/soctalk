#!/usr/bin/env python
"""Generate the SocTalk OpenAPI schema straight from the FastAPI app.

This is the single source of truth for the REST API reference: the docs site
(soctalk-docs) renders the emitted ``openapi.json`` rather than hand-listing
endpoints, so the reference can never drift from the code.

On top of FastAPI's schema this enriches every operation with
``x-soctalk-auth`` — a human-readable auth label derived from the actual
``require_role`` / ``require_tenant_role`` guards on each route (which are plain
FastAPI dependencies, not OpenAPI security schemes, so they aren't in the raw
schema). Non-guarded routes fall back to a prefix-based label.

Usage:
    python scripts/dump_openapi.py [output.json]   # default: openapi.json
"""
from __future__ import annotations

import json
import sys

from soctalk.core.api.app_v1 import create_app


def _iter_call_tree(dependant):
    """Yield every callable in a route's dependency tree."""
    if getattr(dependant, "call", None) is not None:
        yield dependant.call
    for sub in getattr(dependant, "dependencies", []) or []:
        yield from _iter_call_tree(sub)


def _auth_label(path: str, dependant) -> str:
    """Best-effort, code-derived auth label for one route."""
    roles: tuple[str, ...] = ()
    scope: str | None = None
    for call in _iter_call_tree(dependant):
        r = getattr(call, "_soctalk_roles", None)
        if r:
            roles = r
            scope = getattr(call, "_soctalk_scope", None)
            break
    if roles:
        joined = " / ".join(roles)
        if scope == "tenant":
            return f"tenant session ({joined})"
        return f"session (roles: {joined})"
    # No role guard: classify by prefix.
    if path.startswith("/api/internal/adapter"):
        return "service JWT (adapter token)"
    if path.startswith("/api/internal/worker"):
        return "service JWT (worker token)"
    if path.startswith("/api/agent"):
        return "L2 agent install token (bearer)"
    if path.startswith("/api/public") or path.startswith("/health"):
        return "none (public)"
    if path.startswith("/api/auth"):
        return "session cookie (login) / none"
    if path.startswith("/api/tenant/"):
        return "tenant session"
    return "session cookie"


def build_spec() -> dict:
    app = create_app()
    spec = app.openapi()

    # Map (path, METHOD) -> route dependant so we can annotate each operation.
    from fastapi.routing import APIRoute

    by_key: dict[tuple[str, str], object] = {}
    for route in app.routes:
        if isinstance(route, APIRoute):
            for method in route.methods or ():
                by_key[(route.path, method.upper())] = route.dependant

    for path, item in spec.get("paths", {}).items():
        for method, op in item.items():
            if method.upper() not in {
                "GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD",
            }:
                continue
            dependant = by_key.get((path, method.upper()))
            if dependant is not None:
                op["x-soctalk-auth"] = _auth_label(path, dependant)
    return spec


def main() -> int:
    out = sys.argv[1] if len(sys.argv) > 1 else "openapi.json"
    spec = build_spec()
    with open(out, "w") as f:
        json.dump(spec, f, indent=2, sort_keys=True)
        f.write("\n")
    paths = spec.get("paths", {})
    ops = sum(
        1
        for item in paths.values()
        for m in item
        if m in ("get", "post", "put", "patch", "delete")
    )
    print(f"wrote {out}: {len(paths)} paths, {ops} operations", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
