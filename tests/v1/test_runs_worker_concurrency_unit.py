"""Runs-worker run-concurrency (issue #61).

The worker was strictly serial: one process held one in-flight inference at a
time, so a shared vLLM/SGLang backend's continuous batch could never fill from a
single worker. ``WORKER_RUN_CONCURRENCY`` now runs N ``_worker_loop`` copies
concurrently. These tests pin the invariants the Codex adversarial review called
out: no double-processing, a single run's failure never breaks its loop, the
completion POST tolerates lost responses / reclaim (409) without crashing, and
the per-client MCP lock serializes concurrent tool callers.
"""

from __future__ import annotations

import asyncio

import pytest

from soctalk.runs_worker.main import _post_complete, _worker_loop


class _FakeResponse:
    def __init__(self, status_code: int, text: str = "") -> None:
        self.status_code = status_code
        self.text = text


class _FakeClient:
    """Minimal stand-in for httpx.AsyncClient exercised by the worker loop."""

    def __init__(self, complete_result=None) -> None:
        self.complete_calls: list[str] = []
        self._complete_result = complete_result or []
        self._complete_idx = 0

    async def post(self, url: str, **kwargs):  # noqa: ANN003
        if url.endswith("/complete"):
            self.complete_calls.append(url)
            if self._complete_idx < len(self._complete_result):
                item = self._complete_result[self._complete_idx]
                self._complete_idx += 1
                if isinstance(item, Exception):
                    raise item
                return item
            return _FakeResponse(200)
        raise AssertionError(f"unexpected POST {url}")


@pytest.fixture(autouse=True)
def _worker_env(monkeypatch):
    monkeypatch.setenv("SOCTALK_API_URL", "http://api.test")
    monkeypatch.setenv("WORKER_TOKEN_PATH", "/dev/null")
    monkeypatch.setattr("soctalk.runs_worker.main._read_token", lambda: "tok")


async def _drive_loops(monkeypatch, *, concurrency, total_runs, run_impl):
    """Run N _worker_loops against a shared in-memory claim queue and return the
    order/identity of runs each loop processed."""
    queue = asyncio.Queue()
    for i in range(total_runs):
        queue.put_nowait({"run_id": f"run-{i}", "lease_id": f"lease-{i}"})

    claimed: list[str] = []
    processed: list[str] = []
    inflight = 0
    max_inflight = 0
    lock = asyncio.Lock()
    stop = asyncio.Event()

    async def fake_claim(_client):
        if queue.empty():
            # Nothing left to claim; signal drain once no run is still in flight
            # (a failed run never reaches ``processed``, so gate on inflight).
            if inflight == 0:
                stop.set()
            return None
        claim = queue.get_nowait()
        claimed.append(str(claim["run_id"]))
        return claim

    async def fake_run_one(_client, claim):
        nonlocal inflight, max_inflight
        async with lock:
            inflight += 1
            max_inflight = max(max_inflight, inflight)
        try:
            await run_impl(claim)
            processed.append(str(claim["run_id"]))
        finally:
            async with lock:
                inflight -= 1

    monkeypatch.setattr("soctalk.runs_worker.main._claim_one", fake_claim)
    monkeypatch.setattr("soctalk.runs_worker.main._run_one", fake_run_one)

    client = _FakeClient()
    loops = [
        asyncio.create_task(_worker_loop(client, stop, 0.01, 0.0, slot))
        for slot in range(concurrency)
    ]
    await asyncio.wait_for(asyncio.gather(*loops), timeout=5.0)
    return claimed, processed, max_inflight


@pytest.mark.asyncio
async def test_no_double_processing_across_loops(monkeypatch):
    async def run_impl(_claim):
        await asyncio.sleep(0.005)

    claimed, processed, _ = await _drive_loops(
        monkeypatch, concurrency=4, total_runs=20, run_impl=run_impl
    )
    # Every run processed exactly once; SKIP LOCKED semantics are simulated by the
    # single-consumer queue, so a run can be claimed by only one loop.
    assert sorted(processed) == sorted(f"run-{i}" for i in range(20))
    assert len(processed) == len(set(processed)) == 20
    assert sorted(claimed) == sorted(processed)


@pytest.mark.asyncio
async def test_concurrency_is_actually_realized(monkeypatch):
    # With slow runs and 4 loops, at least 2 must be in flight simultaneously —
    # proves N loops overlap (what fills a vLLM continuous batch).
    async def run_impl(_claim):
        await asyncio.sleep(0.05)

    _, processed, max_inflight = await _drive_loops(
        monkeypatch, concurrency=4, total_runs=8, run_impl=run_impl
    )
    assert len(processed) == 8
    assert max_inflight >= 2


@pytest.mark.asyncio
async def test_run_failure_does_not_break_the_loop(monkeypatch):
    # One run raises; its loop must keep pulling and the batch still drains.
    async def run_impl(claim):
        if claim["run_id"] == "run-3":
            raise RuntimeError("boom in graph")
        await asyncio.sleep(0.001)

    _, processed, _ = await _drive_loops(
        monkeypatch, concurrency=2, total_runs=10, run_impl=run_impl
    )
    # run-3 raised (not appended to processed), every other run completed.
    assert "run-3" not in processed
    assert sorted(processed) == sorted(f"run-{i}" for i in range(10) if i != 3)


@pytest.mark.asyncio
async def test_post_complete_treats_409_as_benign(monkeypatch):
    # A 409 means the worker no longer owns the active run (lease reclaimed or a
    # prior lost-response commit). It must return, not raise.
    client = _FakeClient(complete_result=[_FakeResponse(409, "lease expired")])
    await _post_complete(client, "run-x", {"status": "completed", "tokens_used": 1})
    assert len(client.complete_calls) == 1  # no retry storm on a definitive 409


async def _noop_sleep(*_a, **_k):
    return None


@pytest.mark.asyncio
async def test_post_complete_retries_transport_error_then_succeeds(monkeypatch):
    monkeypatch.setattr("soctalk.runs_worker.main.asyncio.sleep", _noop_sleep)
    client = _FakeClient(
        complete_result=[ConnectionError("reset"), _FakeResponse(200)]
    )
    # Must not raise; retries past the transient transport error.
    await _post_complete(client, "run-y", {"status": "completed", "tokens_used": 2})
    assert len(client.complete_calls) == 2


@pytest.mark.asyncio
async def test_post_complete_gives_up_quietly_after_retries(monkeypatch):
    monkeypatch.setenv("WORKER_COMPLETE_ATTEMPTS", "2")
    monkeypatch.setattr("soctalk.runs_worker.main.asyncio.sleep", _noop_sleep)
    client = _FakeClient(
        complete_result=[ConnectionError("x"), ConnectionError("y")]
    )
    # Exhausts retries without raising; lease expiry requeues if uncommitted.
    await _post_complete(client, "run-z", {"status": "completed", "tokens_used": 3})
    assert len(client.complete_calls) == 2


@pytest.mark.asyncio
async def test_mcp_client_serializes_concurrent_tool_calls(monkeypatch):
    # The per-client asyncio.Lock must prevent two coroutines from interleaving
    # on the single stdio session — the concurrency hazard Codex confirmed.
    from soctalk.config import MCPServerConfig
    from soctalk.mcp.client import MCPClient

    client = MCPClient(
        MCPServerConfig(name="cortex", path="/nonexistent", env_vars={})
    )
    client._tools = {"analyze": {"name": "analyze"}}

    inside = 0
    max_inside = 0

    class _Session:
        async def call_tool(self, name, args):  # noqa: ANN001
            nonlocal inside, max_inside
            inside += 1
            max_inside = max(max_inside, inside)
            await asyncio.sleep(0.01)
            inside -= 1

            class _R:
                isError = False  # noqa: N815 — mirrors the MCP SDK result attr
                content: list = []  # noqa: RUF012

            return _R()

    client._session = _Session()
    client._connected = True

    await asyncio.gather(*(client.call_tool("analyze", {}) for _ in range(5)))
    assert max_inside == 1  # lock held: never two callers in the session at once
