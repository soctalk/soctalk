"""Protocol constants — must stay in lockstep with the Go SDK."""

from __future__ import annotations

PROTOCOL_VERSION = "1"
MAX_MESSAGE_BYTES = 4 * 1024 * 1024  # 4 MiB


class Method:
    HELLO = "plugin.hello"
    INITIALIZE = "plugin.initialize"
    SHUTDOWN = "plugin.shutdown"

    VM_PLAN = "vm.plan"
    VM_CREATE = "vm.create"
    VM_WAIT_READY = "vm.wait_ready"
    VM_DESTROY = "vm.destroy"
    VM_INSPECT = "vm.inspect"

    PROGRESS = "progress"
    LOG = "log"


class Category:
    """Stable error categories used by the launchpad UI."""

    AUTH = "auth"
    VALIDATION = "validation"
    QUOTA = "quota"
    RATE_LIMITED = "rate_limited"
    TIMEOUT = "timeout"
    CONFLICT = "conflict"
    NOT_FOUND = "not_found"
    PROVIDER_UNAVAILABLE = "provider_unavailable"
    CANCELLED = "cancelled"
    INTERNAL = "internal"


# JSON-RPC 2.0 error codes.
ERR_PARSE = -32700
ERR_INVALID_REQUEST = -32600
ERR_METHOD_NOT_FOUND = -32601
ERR_INVALID_PARAMS = -32602
ERR_INTERNAL = -32603
ERR_PLUGIN_INTERNAL = -32000
