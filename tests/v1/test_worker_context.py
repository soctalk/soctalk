"""Worker context discipline tests: covers postgres-rls Test 3 + security-model §11.3.

These tests don't require Postgres; they exercise the decorator and
ContextVar primitives in-process.
"""

from __future__ import annotations

from uuid import uuid4

import pytest

from soctalk.core.tenancy.context import (
    MissingTenantContext,
    get_current_tenant,
    set_current_tenant,
)
from soctalk.core.tenancy.decorators import tenant_scoped_worker


async def test_worker_raises_when_tenant_missing():
    """postgres-rls Test 3: worker without tenant_id in payload must raise."""

    @tenant_scoped_worker
    async def hostile_worker(state):
        # intentionally does NOT propagate tenant_id
        return state

    with pytest.raises(MissingTenantContext):
        await hostile_worker({})


async def test_worker_sets_context_from_dict_state():
    """Worker with tenant_id in state sets the ContextVar for the call."""
    tid = uuid4()
    captured = {}

    @tenant_scoped_worker
    async def worker(state):
        captured["seen"] = get_current_tenant()
        return state

    await worker({"tenant_id": tid})
    assert captured["seen"] == tid


async def test_worker_resets_context_on_exit():
    """After the worker returns, ContextVar is reset."""
    tid = uuid4()
    token = set_current_tenant(None)
    try:
        @tenant_scoped_worker
        async def worker(state):
            return state

        await worker({"tenant_id": tid})
        assert get_current_tenant() is None
    finally:
        from soctalk.core.tenancy.context import _current_tenant_id  # noqa

        _current_tenant_id.reset(token)


async def test_worker_accepts_attr_style_state():
    """Worker handles state objects exposing tenant_id as attribute."""
    tid = uuid4()

    class State:
        def __init__(self, tenant_id):
            self.tenant_id = tenant_id

    captured = {}

    @tenant_scoped_worker
    async def worker(state):
        captured["seen"] = get_current_tenant()
        return state

    await worker(State(tid))
    assert captured["seen"] == tid


def test_sync_worker_decorator_also_enforces():
    """Sync workers get the same protection."""

    @tenant_scoped_worker
    def sync_worker(state):
        return state

    with pytest.raises(MissingTenantContext):
        sync_worker({})

    tid = uuid4()
    assert sync_worker({"tenant_id": tid})["tenant_id"] == tid
