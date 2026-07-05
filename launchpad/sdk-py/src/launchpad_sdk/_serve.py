"""Serve loop — mirrors the Go SDK's ``Serve`` function."""

from __future__ import annotations

import io
import json
import sys
import threading
from dataclasses import dataclass, field
from typing import Any, BinaryIO, Callable, Optional

from ._protocol import (
    MAX_MESSAGE_BYTES,
    PROTOCOL_VERSION,
    Category,
    Method,
    ERR_INVALID_PARAMS,
    ERR_METHOD_NOT_FOUND,
    ERR_PLUGIN_INTERNAL,
)
from ._errors import PluginError


class Emitter:
    """Progress + log channel handed to long-running handlers.

    The SDK stitches the op_id (JSON-RPC request ID) automatically; callers
    only need to describe the step + percent + message.
    """

    def __init__(self, send_frame: Callable[[dict], None], op_id: Optional[int] = None, vm_key: str = ""):
        self._send = send_frame
        self._op_id = op_id
        self._vm_key = vm_key

    def progress(self, step: str, percent: float, message: str = "") -> None:
        params = {"step": step, "percent": percent, "message": message}
        if self._op_id is not None:
            params["op_id"] = self._op_id
        if self._vm_key:
            params["vm_key"] = self._vm_key
        self._send({"jsonrpc": "2.0", "method": Method.PROGRESS, "params": params})

    def log(self, level: str, message: str, fields: Optional[dict] = None) -> None:
        params = {"level": level, "message": message}
        if self._op_id is not None:
            params["op_id"] = self._op_id
        if self._vm_key:
            params["vm_key"] = self._vm_key
        if fields:
            params["fields"] = fields
        self._send({"jsonrpc": "2.0", "method": Method.LOG, "params": params})


@dataclass
class Plugin:
    """Declarative plugin configuration.

    Handlers receive params dicts (as sent by the launchpad) and return
    result dicts. They may raise ``PluginError`` for typed errors, or any
    other Exception which becomes an ``internal``-category error.
    """

    name: str
    version: str
    allowed_env_vars: list[str] = field(default_factory=list)
    config_schema: dict = field(default_factory=dict)

    initialize: Optional[Callable[[dict, Emitter], dict]] = None
    plan: Optional[Callable[[dict, Emitter], dict]] = None
    create: Optional[Callable[[dict, Emitter], dict]] = None
    wait_ready: Optional[Callable[[dict, Emitter], dict]] = None
    destroy: Optional[Callable[[dict, Emitter], dict]] = None
    inspect: Optional[Callable[[dict, Emitter], dict]] = None
    shutdown: Optional[Callable[[], None]] = None


def serve(plugin: Plugin) -> None:
    """Run the plugin's main loop against os.stdin / os.stdout."""
    serve_io(plugin, sys.stdin.buffer, sys.stdout.buffer)


def serve_io(plugin: Plugin, r: BinaryIO, w: BinaryIO) -> None:
    """Run the plugin's main loop against explicit binary streams (for tests)."""
    _validate(plugin)

    # Writes must be serialized; multiple handlers can emit notifications
    # concurrently (in future when we allow it) so use a mutex.
    write_lock = threading.Lock()

    def send(frame: dict) -> None:
        data = json.dumps(frame, separators=(",", ":")).encode("utf-8")
        if len(data) > MAX_MESSAGE_BYTES:
            raise RuntimeError(f"message {len(data)} bytes exceeds MAX_MESSAGE_BYTES ({MAX_MESSAGE_BYTES})")
        with write_lock:
            w.write(data + b"\n")
            w.flush()

    # Phase 1: emit hello.
    caps = []
    if plugin.plan:
        caps.append(Method.VM_PLAN)
    if plugin.create:
        caps.append(Method.VM_CREATE)
    if plugin.wait_ready:
        caps.append(Method.VM_WAIT_READY)
    if plugin.destroy:
        caps.append(Method.VM_DESTROY)
    if plugin.inspect:
        caps.append(Method.VM_INSPECT)
    send({
        "jsonrpc": "2.0",
        "method": Method.HELLO,
        "params": {
            "protocol_version": PROTOCOL_VERSION,
            "plugin_name": plugin.name,
            "plugin_version": plugin.version,
            "capabilities": caps,
            "config_schema": plugin.config_schema or None,
            "allowed_env_vars": plugin.allowed_env_vars or None,
        },
    })

    # Phase 2+: request/response loop.
    for line in _iter_lines(r):
        env = _parse_frame(line)
        if env is None:
            continue
        method = env.get("method", "")
        if not method:
            # Response frame — plugins don't originate requests in v1.
            continue
        _dispatch(plugin, env, send)
        if method == Method.SHUTDOWN:
            return


def _validate(plugin: Plugin) -> None:
    if not plugin.name:
        raise ValueError("plugin.name required")
    if not plugin.version:
        raise ValueError("plugin.version required")
    if plugin.initialize is None:
        raise ValueError("plugin.initialize required")


def _iter_lines(r: BinaryIO):
    """Line-delimited framing over a binary stream.

    Uses readline() when available (BufferedReader / BytesIO / stdin.buffer).
    That blocks until a full line arrives, which is what our JSON-RPC framing
    needs. Falls back to a manual chunk-based scanner for exotic streams.
    """
    if hasattr(r, "readline"):
        while True:
            line = r.readline(MAX_MESSAGE_BYTES + 1)
            if not line:
                return
            if len(line) > MAX_MESSAGE_BYTES:
                raise RuntimeError(f"line {len(line)} bytes exceeds MAX_MESSAGE_BYTES")
            # Strip the trailing newline (may be missing on the very last line).
            if line.endswith(b"\n"):
                line = line[:-1]
            yield line
        return

    buf = b""
    while True:
        chunk = r.read(4096)
        if not chunk:
            if buf:
                yield buf
            return
        buf += chunk
        while True:
            i = buf.find(b"\n")
            if i < 0:
                break
            line = buf[:i]
            buf = buf[i + 1 :]
            if len(line) > MAX_MESSAGE_BYTES:
                raise RuntimeError(f"line {len(line)} bytes exceeds MAX_MESSAGE_BYTES")
            yield line


def _parse_frame(line: bytes) -> Optional[dict]:
    line = line.strip()
    if not line:
        return None
    try:
        env = json.loads(line)
    except json.JSONDecodeError:
        return None
    if env.get("jsonrpc") != "2.0":
        return None
    return env


def _dispatch(plugin: Plugin, req: dict, send: Callable[[dict], None]) -> None:
    method = req.get("method", "")
    params = req.get("params") or {}
    req_id = req.get("id")

    def respond_ok(result: Any) -> None:
        if req_id is None:
            return
        send({"jsonrpc": "2.0", "id": req_id, "result": result})

    def respond_err(code: int, message: str, category: str, app_code: str, hint: str = "") -> None:
        if req_id is None:
            return
        send({
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {
                "code": code,
                "message": message,
                "data": {"category": category, "app_code": app_code, "hint": hint},
            },
        })

    emit = Emitter(send, op_id=req_id, vm_key=_extract_vm_key(method, params))

    def handle(handler: Optional[Callable], default_cap_msg: str) -> None:
        if handler is None:
            respond_err(ERR_METHOD_NOT_FOUND, default_cap_msg, Category.VALIDATION, "capability_not_supported")
            return
        try:
            result = handler(params, emit) if method != Method.SHUTDOWN else (handler() or {})
            respond_ok(result if result is not None else {})
        except PluginError as e:
            code_data = {
                "category": e.category,
                "app_code": e.code,
                "hint": e.hint,
                "docs_url": e.docs_url,
            }
            if e.retry:
                code_data["retry"] = e.retry
            if req_id is None:
                return
            send({"jsonrpc": "2.0", "id": req_id, "error": {
                "code": ERR_PLUGIN_INTERNAL, "message": e.message, "data": code_data,
            }})
        except Exception as e:  # pragma: no cover - safety net
            respond_err(ERR_PLUGIN_INTERNAL, str(e), Category.INTERNAL, "unhandled_exception")

    if method == Method.INITIALIZE:
        handle(plugin.initialize, "initialize not supported")
    elif method == Method.SHUTDOWN:
        handle(plugin.shutdown, "shutdown not supported")
    elif method == Method.VM_PLAN:
        handle(plugin.plan, "vm.plan not supported")
    elif method == Method.VM_CREATE:
        handle(plugin.create, "vm.create not supported")
    elif method == Method.VM_WAIT_READY:
        handle(plugin.wait_ready, "vm.wait_ready not supported")
    elif method == Method.VM_DESTROY:
        handle(plugin.destroy, "vm.destroy not supported")
    elif method == Method.VM_INSPECT:
        handle(plugin.inspect, "vm.inspect not supported")
    else:
        respond_err(ERR_METHOD_NOT_FOUND, f"unknown method: {method}", Category.VALIDATION, "method_not_found")


def _extract_vm_key(method: str, params: dict) -> str:
    if method in (Method.VM_PLAN, Method.VM_CREATE):
        spec = params.get("spec") or {}
        return str(spec.get("vm_key", ""))
    return str(params.get("vm_key", ""))
