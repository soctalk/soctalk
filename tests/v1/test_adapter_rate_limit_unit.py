"""The adapter's per-tenant rate limiter must not lose alerts.

Before this change the limiter truncated a batch to the bucket's capacity
and the keyset cursor still advanced past the discarded tail, so a fresh
100-event page against the default 60/min, burst-30 bucket forwarded 30
and permanently skipped 70. That is load shedding applied to durable SIEM
history. The default is now ``defer``: the cursor advances only through
what was forwarded, the tail is re-read next poll, and the loop re-polls
as soon as the bucket can admit another batch. ``shed`` keeps the old
behaviour, explicitly.

These tests drive ``_ingest_once`` with an in-memory indexer that honours
``search_after`` the way OpenSearch does, a fake clock on the bucket, and a
recording control-plane client, so delivery is proven event by event.
"""

from __future__ import annotations

import pytest

import soctalk_adapter.main as m

TS = "2026-01-31T10:00:00.000Z"


def _hits(n: int, ts: str = TS) -> list[dict]:
    """``n`` indexer hits sharing one timestamp (the livelock-prone shape),
    with zero-padded ids so string order matches numeric order."""
    return [
        {
            "_id": f"doc-{i:04d}",
            "_source": {
                "id": f"wz-{i:04d}",
                "@timestamp": ts,
                "rule": {"id": "5710", "level": 10, "description": "test alert", "groups": ["t"]},
                "agent": {"id": "001", "name": "host-01"},
                "data": {"srcip": "203.0.113.9"},
                "decoder": {"name": "json"},
                "full_log": f"event {i}",
            },
        }
        for i in range(1, n + 1)
    ]


class _FakeIndexer:
    """Serves pages from ``hits`` honouring the adapter's keyset query."""

    def __init__(self, hits: list[dict]):
        self.hits = hits
        self.queries: list[dict] = []

    async def post(self, url, **kw):
        body = kw["json"]
        self.queries.append(body)
        after = body.get("search_after")
        rows = self.hits
        if after:
            ts, eid = after
            rows = [h for h in rows if (h["_source"]["@timestamp"], h["_source"]["id"]) > (ts, eid)]
        page = rows[: body["size"]]

        class _Resp:
            def raise_for_status(self): ...

            def json(self):
                return {"hits": {"hits": page}}

        return _Resp()


class _FakeApi:
    """Records forwarded batches and checkpoint PUTs; can be told to fail."""

    def __init__(self, fail_post: bool = False):
        self.batches: list[list[dict]] = []
        self.checkpoints: list[tuple[str, str | None]] = []
        self.fail_post = fail_post

    async def post(self, url, **kw):
        if self.fail_post:
            raise RuntimeError("control plane down")
        self.batches.append(kw["json"]["events"])

        class _Resp:
            def raise_for_status(self): ...

            def json(self):
                return {"action_counts": {"duplicate": 0}}

        return _Resp()

    async def put(self, url, **kw):
        body = kw["json"]
        self.checkpoints.append((body["cursor_ts"], body["cursor_event_id"]))

        class _Resp:
            def raise_for_status(self): ...

        return _Resp()


class _Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


@pytest.fixture
def adapter(monkeypatch):
    """Fresh adapter state + a 60/min burst-30 bucket on a fake clock."""
    monkeypatch.delenv("SOCTALK_ADAPTER_RATE_LIMIT_MODE", raising=False)
    monkeypatch.delenv("SOCTALK_ADAPTER_EXCLUDE_MANAGER_AGENT", raising=False)
    clock = _Clock()
    bucket = m._TokenBucket(rate_per_sec=1.0, burst=30, clock=clock)
    monkeypatch.setattr(m, "_rate_limiter", bucket)
    monkeypatch.setattr(m, "_state", m._State())
    return clock, bucket


def _forwarded_ids(api: _FakeApi) -> list[str]:
    return [e["source_event_id"] for batch in api.batches for e in batch]


async def _poll(api, indexer, size=100):
    return await m._ingest_once(api, indexer, "http://l1", "tenant-1", "tok", size)


async def test_defer_forwards_capacity_and_holds_cursor_at_last_forwarded(adapter):
    clock, _ = adapter
    api, indexer = _FakeApi(), _FakeIndexer(_hits(100))

    r = await _poll(api, indexer)

    assert (r.queried, r.forwarded, r.deferred, r.dropped) == (100, 30, 70, 0)
    assert _forwarded_ids(api) == [f"wz-{i:04d}" for i in range(1, 31)]
    # Cursor = last FORWARDED event, not the last of the page.
    assert (m._state.last_alert_ts, m._state.last_alert_id) == (TS, "wz-0030")
    assert api.checkpoints[-1] == (TS, "wz-0030")
    assert m._state.alerts_dropped_rate_limit == 0
    assert m._state.alerts_deferred_rate_limit == 70


async def test_defer_eventually_delivers_every_event_once_in_order(adapter):
    """Drain a 100-event backlog through the bucket: every event arrives
    exactly once, in order, across successive polls as tokens refill."""
    clock, _ = adapter
    api, indexer = _FakeApi(), _FakeIndexer(_hits(100))

    for _ in range(10):
        r = await _poll(api, indexer)
        if r.queried == 0:
            break
        clock.t += 30  # refill 30 tokens between polls
    ids = _forwarded_ids(api)
    assert ids == [f"wz-{i:04d}" for i in range(1, 101)]
    assert m._state.alerts_forwarded == 100
    assert m._state.alerts_dropped_rate_limit == 0
    # Each re-read page started exactly after the last forwarded event.
    assert indexer.queries[1]["search_after"] == [TS, "wz-0030"]
    assert indexer.queries[2]["search_after"] == [TS, "wz-0060"]


async def test_defer_with_empty_bucket_forwards_nothing_and_keeps_cursor(adapter):
    clock, bucket = adapter
    bucket.take(30)  # drain
    api, indexer = _FakeApi(), _FakeIndexer(_hits(5))

    r = await _poll(api, indexer)

    assert (r.forwarded, r.deferred, r.advanced) == (0, 5, False)
    assert api.batches == [] and api.checkpoints == []
    assert m._state.last_alert_id is None


async def test_shed_mode_keeps_legacy_behaviour_explicitly(adapter, monkeypatch):
    monkeypatch.setenv("SOCTALK_ADAPTER_RATE_LIMIT_MODE", "shed")
    api, indexer = _FakeApi(), _FakeIndexer(_hits(100))

    r = await _poll(api, indexer)

    assert (r.forwarded, r.deferred, r.dropped) == (30, 0, 70)
    # Cursor jumps past the discarded tail: the next poll finds nothing.
    assert m._state.last_alert_id == "wz-0100"
    assert m._state.alerts_dropped_rate_limit == 70
    r2 = await _poll(api, indexer)
    assert r2.queried == 0


@pytest.mark.parametrize("raw", ["", "SHED ", "drop", "Defer"])
def test_rate_limit_mode_parsing(monkeypatch, raw):
    monkeypatch.setenv("SOCTALK_ADAPTER_RATE_LIMIT_MODE", raw)
    expected = "shed" if raw.strip().lower() == "shed" else "defer"
    assert m._rate_limit_mode() == expected


async def test_failed_post_leaves_cursor_for_a_whole_retry(adapter):
    api, indexer = _FakeApi(fail_post=True), _FakeIndexer(_hits(10))

    with pytest.raises(RuntimeError):
        await _poll(api, indexer)

    assert m._state.last_alert_id is None
    assert api.checkpoints == []
    assert m._state.alerts_forwarded == 0


async def test_hits_without_source_id_do_not_block_the_cursor(adapter):
    hits = _hits(3)
    hits[1]["_source"].pop("id")
    hits[1].pop("_id")  # neither id → _hit_to_event returns None
    api, indexer = _FakeApi(), _FakeIndexer(hits)

    r = await _poll(api, indexer)

    assert r.forwarded == 2
    assert m._state.last_alert_id == "wz-0003"


def test_next_sleep_repolls_early_only_when_deferring(adapter):
    clock, bucket = adapter
    assert m._next_sleep(None, 15.0) == 15.0
    assert m._next_sleep(m._PollResult(forwarded=30), 15.0) == 15.0
    bucket.take(30)  # empty; 1 token/s
    # 70 deferred, burst 30 → wait for 30 tokens = 30 s, capped at the interval.
    assert m._next_sleep(m._PollResult(deferred=70), 15.0) == 15.0
    assert m._next_sleep(m._PollResult(deferred=70), 60.0) == pytest.approx(30.0)
    clock.t += 10
    assert m._next_sleep(m._PollResult(deferred=5), 60.0) == 0.0


def test_token_bucket_seconds_until():
    clock = _Clock()
    b = m._TokenBucket(rate_per_sec=2.0, burst=10, clock=clock)
    assert b.seconds_until(10) == 0.0
    b.take(10)
    assert b.seconds_until(4) == pytest.approx(2.0)
    assert b.seconds_until(100) == pytest.approx(5.0)  # capped at burst
    clock.t += 1
    assert b.seconds_until(4) == pytest.approx(1.0)
    disabled = m._TokenBucket(rate_per_sec=0, burst=10, clock=clock)
    assert disabled.take(500) == (500, 0) and disabled.seconds_until(500) == 0.0
