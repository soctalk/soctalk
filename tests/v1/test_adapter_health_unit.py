"""The adapter's heartbeat ``health`` must follow the ingest loop.

It used to be hard-coded ``"ok"``: an adapter whose every indexer poll
failed (bad credentials, TLS, an unreachable indexer) heartbeated green, so
the MSSP dashboard showed a healthy tenant receiving nothing. Health is now
computed from the poll loop: consecutive failures, time since the last
completed poll, checkpoint load/save, and whether the ingest task is still
alive. A quiet tenant (polls succeed, nothing new) stays ``ok``.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta

import pytest

import soctalk_adapter.main as m

NOW = datetime(2026, 11, 2, 12, 0, 0, tzinfo=UTC)


@pytest.fixture
def state(monkeypatch):
    s = m._State()
    s.ingest_phase = "polling"
    s.ingest_phase_since = NOW - timedelta(hours=1)
    s.ingest_interval = 15.0
    s.checkpoint_loaded = True
    s.last_poll_ok = NOW - timedelta(seconds=10)
    monkeypatch.setattr(m, "_state", s)
    return s


def test_recent_successful_poll_is_ok(state):
    assert m._compute_health(NOW) == ("ok", [])


def test_ingest_disabled_is_ok_regardless(state):
    state.ingest_phase = "disabled"
    state.last_poll_ok = None
    state.consecutive_poll_failures = 99
    assert m._compute_health(NOW) == ("ok", [])


@pytest.mark.parametrize("n", [1, m.POLL_FAILING_THRESHOLD - 1])
def test_few_poll_failures_are_degraded(state, n):
    state.consecutive_poll_failures = n
    assert m._compute_health(NOW) == ("degraded", ["poll_failing"])


def test_repeated_poll_failures_are_failing(state):
    state.consecutive_poll_failures = m.POLL_FAILING_THRESHOLD
    assert m._compute_health(NOW) == ("failing", ["poll_failing"])


def test_no_completed_poll_within_stale_window_is_failing(state):
    state.last_poll_ok = NOW - timedelta(seconds=m.POLL_STALE_MIN_SECONDS + 1)
    assert m._compute_health(NOW) == ("failing", ["poll_stale"])


def test_stale_window_scales_with_a_long_interval(state):
    state.ingest_interval = 300.0
    state.last_poll_ok = NOW - timedelta(seconds=600)
    assert m._compute_health(NOW) == ("ok", [])
    state.last_poll_ok = NOW - timedelta(seconds=901)
    assert m._compute_health(NOW)[0] == "failing"


def test_starting_is_ok_until_it_takes_too_long(state):
    state.ingest_phase = "starting"
    state.checkpoint_loaded = False
    state.last_poll_ok = None
    state.ingest_phase_since = NOW - timedelta(seconds=5)
    assert m._compute_health(NOW) == ("ok", [])
    state.ingest_phase_since = NOW - timedelta(seconds=m.POLL_STALE_MIN_SECONDS + 1)
    assert m._compute_health(NOW) == ("failing", ["poll_stale"])


def test_never_polled_since_entering_polling_goes_stale(state):
    state.last_poll_ok = None
    state.ingest_phase_since = NOW - timedelta(seconds=m.POLL_STALE_MIN_SECONDS + 1)
    assert m._compute_health(NOW) == ("failing", ["poll_stale"])


def test_stopped_ingest_task_is_failing(state):
    state.ingest_phase = "stopped"
    assert m._compute_health(NOW) == ("failing", ["ingest_stopped"])


def test_checkpoint_never_loaded_is_degraded(state):
    state.checkpoint_loaded = False
    assert m._compute_health(NOW) == ("degraded", ["checkpoint_not_loaded"])


def test_checkpoint_save_failing_is_degraded(state):
    state.checkpoint_save_failing = True
    assert m._compute_health(NOW) == ("degraded", ["checkpoint_save_failing"])


def test_failing_reports_degraded_reasons_too(state):
    state.consecutive_poll_failures = m.POLL_FAILING_THRESHOLD
    state.checkpoint_save_failing = True
    assert m._compute_health(NOW) == (
        "failing", ["poll_failing", "checkpoint_save_failing"],
    )


# --- poll-cycle bookkeeping ------------------------------------------------


@pytest.fixture
def cycle(monkeypatch, state):
    state.last_poll_ok = None
    monkeypatch.setattr(m, "_read_token", lambda: "tok")
    outcomes: list = []

    async def fake_ingest_once(*_a, **_kw):
        o = outcomes.pop(0)
        if isinstance(o, Exception):
            raise o
        return o

    monkeypatch.setattr(m, "_ingest_once", fake_ingest_once)

    async def run():
        return await m._poll_cycle(None, None, "http://l1", "tenant-1", 100)

    return state, outcomes, run


async def test_failed_polls_accumulate_and_a_success_resets(cycle):
    state, outcomes, run = cycle
    outcomes += [RuntimeError("indexer 401")] * m.POLL_FAILING_THRESHOLD
    for _ in range(m.POLL_FAILING_THRESHOLD):
        assert await run() is None
    assert state.consecutive_poll_failures == m.POLL_FAILING_THRESHOLD
    assert state.last_ingest_error == "indexer 401"
    assert m._compute_health()[0] == "failing"

    outcomes.append(m._PollResult())  # empty but successful poll
    assert await run() == m._PollResult()
    assert state.consecutive_poll_failures == 0
    assert state.last_ingest_error is None
    assert state.last_poll_ok is not None
    assert m._compute_health() == ("ok", [])


async def test_token_read_error_is_a_failed_poll_not_a_crash(cycle, monkeypatch):
    state, _outcomes, run = cycle

    def boom():
        raise FileNotFoundError("token")

    monkeypatch.setattr(m, "_read_token", boom)
    assert await run() is None
    assert state.consecutive_poll_failures == 1


async def test_checkpoint_save_failure_and_recovery_are_tracked(state):
    class _Api:
        def __init__(self, fail):
            self.fail = fail

        async def put(self, *_a, **_kw):
            if self.fail:
                raise RuntimeError("api down")

            class _R:
                def raise_for_status(self): ...

            return _R()

    await m._save_checkpoint(_Api(True), "http://l1", "t", "tok", "ts", "id")
    assert state.checkpoint_save_failing is True
    await m._save_checkpoint(_Api(False), "http://l1", "t", "tok", "ts", "id")
    assert state.checkpoint_save_failing is False


# --- ingest task liveness ---------------------------------------------------


async def test_ingest_task_dying_marks_stopped(state):
    async def die():
        raise FileNotFoundError("no token")

    t = asyncio.create_task(die())
    with pytest.raises(FileNotFoundError):
        await t
    m._on_ingest_task_done(t)
    assert state.ingest_phase == "stopped"
    assert "no token" in state.last_ingest_error
    assert m._compute_health()[0] == "failing"


async def test_cancelled_or_disabled_ingest_task_is_not_stopped(state):
    t = asyncio.create_task(asyncio.sleep(10))
    t.cancel()
    with pytest.raises(asyncio.CancelledError):
        await t
    m._on_ingest_task_done(t)
    assert state.ingest_phase == "polling"

    state.ingest_phase = "disabled"
    done = asyncio.create_task(asyncio.sleep(0))
    await done
    m._on_ingest_task_done(done)
    assert state.ingest_phase == "disabled"


# --- heartbeat payload --------------------------------------------------------


async def test_heartbeat_sends_computed_health_and_reasons(state, monkeypatch):
    monkeypatch.setenv("SOCTALK_API_URL", "http://l1")
    monkeypatch.setenv("SOCTALK_TENANT_ID", "tenant-1")
    monkeypatch.setattr(m, "_read_token", lambda: "tok")
    state.last_poll_ok = datetime.now(UTC)
    state.consecutive_poll_failures = m.POLL_FAILING_THRESHOLD
    sent: list[dict] = []

    class _Client:
        async def post(self, _url, **kw):
            sent.append(kw["json"])

            class _R:
                def raise_for_status(self): ...

            return _R()

    await m._heartbeat_once(_Client())
    body = sent[0]
    assert body["health"] == "failing"
    assert body["metrics"]["health_reasons"] == ["poll_failing"]
    assert body["metrics"]["consecutive_poll_failures"] == m.POLL_FAILING_THRESHOLD
    assert body["metrics"]["ingest_phase"] == "polling"
    assert body["metrics"]["last_poll_ok_at"] == state.last_poll_ok.isoformat()


async def test_ready_reports_health_without_gating(state):
    state.ingest_phase = "stopped"
    body = await m.ready()
    assert body["ok"] is True
    assert body["health"] == "failing"
    assert body["health_reasons"] == ["ingest_stopped"]


# --- checkpoint recovery ----------------------------------------------------
# A transient checkpoint failure must not leave a quiet tenant "degraded"
# forever: the save used to be retried only when the cursor moved, and a
# startup load that exhausted its retries was never recovered.


class _RecordingApi:
    def __init__(self, fail: bool = False):
        self.fail = fail
        self.puts: list[dict] = []

    async def put(self, _url, **kw):
        if self.fail:
            raise RuntimeError("api down")
        self.puts.append(kw["json"])

        class _R:
            def raise_for_status(self): ...

        return _R()


@pytest.fixture
def quiet_cycle(monkeypatch, state):
    """A poll that succeeds but finds nothing new (a quiet tenant)."""
    monkeypatch.setattr(m, "_read_token", lambda: "tok")
    state.last_alert_ts = "2026-11-02T10:00:00.000Z"
    state.last_alert_id = "wz-1"

    async def empty(*_a, **_kw):
        return m._PollResult()

    monkeypatch.setattr(m, "_ingest_once", empty)

    async def run(api):
        return await m._poll_cycle(api, None, "http://l1", "tenant-1", 100)

    return state, run


async def test_a_failed_save_is_retried_on_the_next_quiet_poll(quiet_cycle):
    state, run = quiet_cycle
    state.checkpoint_save_failing = True
    api = _RecordingApi()
    await run(api)
    assert [p["cursor_ts"] for p in api.puts] == ["2026-11-02T10:00:00.000Z"]
    assert state.checkpoint_save_failing is False
    assert m._compute_health() == ("ok", [])


async def test_a_startup_load_that_never_succeeded_recovers_after_a_save(quiet_cycle):
    state, run = quiet_cycle
    state.checkpoint_loaded = False
    assert m._compute_health(NOW) == ("degraded", ["checkpoint_not_loaded"])
    api = _RecordingApi()
    await run(api)
    assert len(api.puts) == 1
    assert m._compute_health() == ("ok", [])


async def test_recovery_save_failing_keeps_the_reason(quiet_cycle):
    state, run = quiet_cycle
    state.checkpoint_loaded = False
    await run(_RecordingApi(fail=True))
    health, reasons = m._compute_health()
    assert health == "degraded"
    assert set(reasons) == {"checkpoint_not_loaded", "checkpoint_save_failing"}


async def test_no_checkpoint_writes_on_quiet_polls_when_in_sync(quiet_cycle):
    state, run = quiet_cycle
    api = _RecordingApi()
    for _ in range(3):
        await run(api)
    assert api.puts == []
