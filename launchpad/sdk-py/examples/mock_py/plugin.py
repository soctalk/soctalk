#!/usr/bin/env python3
"""Example Python plugin — the mirror of launchpad-plugin-mock.

Wire this into launchpad's plugin dir alongside a plugin.yaml with
``executable: ./plugin.py`` and set the +x bit.
"""

from __future__ import annotations

import hashlib
import time

from launchpad_sdk import Plugin, Emitter, serve, Category, PluginError


REGISTRY: dict[str, dict] = {}


def _key(run_id: str, vm_key: str) -> str:
    return f"{run_id}/{vm_key}"


def _det_ip(run_id: str, vm_key: str) -> str:
    h = hashlib.sha1(_key(run_id, vm_key).encode()).digest()
    return f"10.{h[0] % 254 + 1}.{h[1]}.{h[2]}"


def initialize(params, emit: Emitter):
    return {"ready": True}


def plan(params, emit: Emitter):
    spec = params["spec"]
    return {
        "summary": f"mock-py: {spec.get('size_hint')} in {spec.get('region')}",
        "estimated_cost_usd": 0,
        "estimated_duration_sec": 1,
    }


def create(params, emit: Emitter):
    spec = params["spec"]
    k = _key(spec["run_id"], spec["vm_key"])
    if k in REGISTRY:
        emit.log("info", "idempotent hit", {"vm_id": REGISTRY[k]["vm_id"]})
        return REGISTRY[k]
    emit.progress("create", 25, "allocating VM")
    time.sleep(0.02)
    emit.progress("create", 75, "booting VM")
    time.sleep(0.02)
    vm_id = "mock-py-" + hashlib.sha1(k.encode()).hexdigest()[:8]
    res = {
        "vm_id": vm_id,
        "ipv4": _det_ip(spec["run_id"], spec["vm_key"]),
        "ssh_user": "ubuntu",
        "ssh_port": 22,
        "metadata": {"provider": "mock-py"},
    }
    REGISTRY[k] = res
    emit.progress("create", 100, "VM ready")
    return res


def wait_ready(params, emit: Emitter):
    return {"ready": True}


def destroy(params, emit: Emitter):
    k = _key(params["run_id"], params["vm_key"])
    if k not in REGISTRY:
        return {"destroyed": False}
    del REGISTRY[k]
    return {"destroyed": True}


def inspect(params, emit: Emitter):
    k = _key(params["run_id"], params["vm_key"])
    if k not in REGISTRY:
        return {"exists": False}
    r = REGISTRY[k]
    return {
        "exists": True,
        "vm_id": r["vm_id"],
        "state": "running",
        "ipv4": r["ipv4"],
        "ssh_user": r["ssh_user"],
    }


if __name__ == "__main__":
    serve(Plugin(
        name="mock-py",
        version="0.1.0",
        initialize=initialize,
        plan=plan,
        create=create,
        wait_ready=wait_ready,
        destroy=destroy,
        inspect=inspect,
    ))
