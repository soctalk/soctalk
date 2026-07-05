"""SDK for writing SocTalk Launchpad plugins in Python.

Same wire protocol as the Go SDK: line-delimited JSON-RPC 2.0 on stdio.

Typical use:

    from launchpad_sdk import serve, Plugin, Emitter, PluginError, Category

    def initialize(params, emit):
        return {"ready": True}

    def create(spec, emit: Emitter):
        emit.progress("provisioning", 25, "requesting VM")
        # ... call provider API ...
        return {
            "vm_id": "vm-abc",
            "ipv4": "203.0.113.42",
            "ssh_user": "root",
            "ssh_port": 22,
        }

    serve(Plugin(
        name="myprovider",
        version="0.1.0",
        allowed_env_vars=["MYPROVIDER_TOKEN"],
        initialize=initialize,
        create=create,
    ))

Handlers can either return a dict-shaped result or raise ``PluginError`` with
a category + code so the launchpad can classify + display a hint.
"""

from ._protocol import PROTOCOL_VERSION, MAX_MESSAGE_BYTES, Category, Method
from ._errors import PluginError
from ._serve import Plugin, Emitter, serve, serve_io

__all__ = [
    "PROTOCOL_VERSION",
    "MAX_MESSAGE_BYTES",
    "Category",
    "Method",
    "Plugin",
    "Emitter",
    "PluginError",
    "serve",
    "serve_io",
]
