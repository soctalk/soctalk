"""Round-trip tests for the Python SDK Serve loop."""

from __future__ import annotations

import io
import json
import threading

from launchpad_sdk import Plugin, PluginError, Category, serve_io


def _run_serve_with_script(plugin: Plugin, script_lines: list[str]) -> list[dict]:
    """Feeds ``script_lines`` into a fresh ``serve_io``, returns emitted frames.

    Uses two BytesIO buffers so we don't need actual pipes / threads.
    """
    stdin = io.BytesIO()
    for line in script_lines:
        stdin.write(line.encode() + b"\n")
    stdin.seek(0)
    stdout = io.BytesIO()
    serve_io(plugin, stdin, stdout)
    return [json.loads(l) for l in stdout.getvalue().splitlines() if l.strip()]


def test_hello_first():
    """The plugin's first frame is always the hello notification."""

    def init(params, emit):
        return {"ready": True}

    frames = _run_serve_with_script(
        Plugin(name="test", version="0.1.0", initialize=init),
        [],  # EOF immediately.
    )
    assert frames[0]["method"] == "plugin.hello"
    assert frames[0]["params"]["protocol_version"] == "1"
    assert frames[0]["params"]["plugin_name"] == "test"


def test_initialize_roundtrip():
    """A plugin.initialize request produces an OK response."""

    def init(params, emit):
        assert params["run_id"] == "r1"
        return {"ready": True}

    req = json.dumps({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "plugin.initialize",
        "params": {"run_id": "r1", "config": {}, "log_level": "info"},
    })
    frames = _run_serve_with_script(
        Plugin(name="test", version="0.1.0", initialize=init),
        [req],
    )
    # frames[0] is hello, frames[1] is the response.
    resp = frames[1]
    assert resp["id"] == 1
    assert resp["result"]["ready"] is True
    assert "error" not in resp


def test_plugin_error_serialization():
    """PluginError raised from a handler surfaces as a categorized wire error."""

    def init(params, emit):
        raise PluginError(
            category=Category.AUTH,
            code="test.credentials.missing",
            message="TOKEN is unset",
            hint="set TOKEN",
        )

    req = json.dumps({
        "jsonrpc": "2.0",
        "id": 5,
        "method": "plugin.initialize",
        "params": {"run_id": "x", "config": {}, "log_level": "info"},
    })
    frames = _run_serve_with_script(
        Plugin(name="test", version="0.1.0", initialize=init),
        [req],
    )
    resp = frames[1]
    assert resp["id"] == 5
    assert resp["error"]["data"]["category"] == "auth"
    assert resp["error"]["data"]["app_code"] == "test.credentials.missing"
    assert "TOKEN" in resp["error"]["message"]
    assert resp["error"]["data"]["hint"] == "set TOKEN"


def test_progress_notifications_carry_op_id_and_vm_key():
    """Progress notifications emitted from a handler are correlated."""

    def init(params, emit):
        return {"ready": True}

    def create(params, emit):
        emit.progress("boot", 50, "booting")
        return {"vm_id": "vm-x", "ipv4": "10.0.0.1", "ssh_user": "root"}

    req_init = json.dumps({
        "jsonrpc": "2.0", "id": 1, "method": "plugin.initialize",
        "params": {"run_id": "r", "config": {}, "log_level": "info"},
    })
    req_create = json.dumps({
        "jsonrpc": "2.0", "id": 2, "method": "vm.create",
        "params": {"spec": {"run_id": "r", "vm_key": "vm-a"}},
    })
    frames = _run_serve_with_script(
        Plugin(name="test", version="0.1.0", initialize=init, create=create),
        [req_init, req_create],
    )
    # Progress notification should exist with op_id=2 + vm_key=vm-a.
    progresses = [f for f in frames if f.get("method") == "progress"]
    assert len(progresses) == 1, progresses
    assert progresses[0]["params"]["op_id"] == 2
    assert progresses[0]["params"]["vm_key"] == "vm-a"


def test_unknown_method_returns_method_not_found():
    """Requests for methods a plugin doesn't declare error out correctly."""

    def init(params, emit):
        return {"ready": True}

    req = json.dumps({
        "jsonrpc": "2.0", "id": 7, "method": "vm.plan", "params": {},
    })
    frames = _run_serve_with_script(
        Plugin(name="test", version="0.1.0", initialize=init),
        [req],
    )
    resp = [f for f in frames if f.get("id") == 7][0]
    assert resp["error"]["code"] == -32601
    assert resp["error"]["data"]["category"] == "validation"


def test_shutdown_ends_loop():
    """plugin.shutdown returns cleanly."""

    def init(params, emit):
        return {"ready": True}

    called = []

    def sd():
        called.append(True)

    req = json.dumps({"jsonrpc": "2.0", "id": 99, "method": "plugin.shutdown"})
    frames = _run_serve_with_script(
        Plugin(name="test", version="0.1.0", initialize=init, shutdown=sd),
        [req],
    )
    resp = [f for f in frames if f.get("id") == 99][0]
    assert "result" in resp
    assert called == [True]
