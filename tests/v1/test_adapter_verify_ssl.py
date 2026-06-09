"""Adapter TLS-verification env-var wiring tests.

The per-tenant adapter must resolve ``WAZUH_INDEXER_VERIFY_SSL`` into the
``verify`` flag of the httpx client it uses to query the Wazuh indexer,
replacing the previously hard-coded ``verify=False``. The mapping is
fail-safe: anything we don't recognise leaves verification ON.

  unset / 'true' / '1'   -> verify=True   (no warning)
  'false' / '0'          -> verify=False
  anything else          -> verify=True   (with a warning)

No DB, no kube, no helm — pure function + a fake httpx client.
"""

from __future__ import annotations

import logging

import pytest

from soctalk_adapter import main


@pytest.fixture(autouse=True)
def _clear_verify_env(monkeypatch):
    """Start every test from a clean slate so the ambient environment
    can't leak a ``WAZUH_INDEXER_VERIFY_SSL`` value into the "unset" cases."""
    monkeypatch.delenv("WAZUH_INDEXER_VERIFY_SSL", raising=False)
    yield


def _warnings(caplog) -> list[logging.LogRecord]:
    return [r for r in caplog.records if r.levelno >= logging.WARNING]


# ---------------------------------------------------------------------------
# _wazuh_indexer_verify_ssl: env-var -> bool mapping
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("true", True),
        ("True", True),
        ("TRUE", True),
        ("1", True),
        (" true ", True),  # surrounding whitespace ignored
        ("false", False),
        ("False", False),
        ("FALSE", False),
        ("0", False),
        (" 0 ", False),
    ],
)
def test_recognised_values_map_without_warning(monkeypatch, caplog, raw, expected):
    monkeypatch.setenv("WAZUH_INDEXER_VERIFY_SSL", raw)
    with caplog.at_level(logging.WARNING, logger="soctalk.adapter"):
        result = main._wazuh_indexer_verify_ssl()
    assert result is expected
    assert not _warnings(caplog), f"recognised value {raw!r} should not warn"


def test_defaults_to_true_when_unset(monkeypatch, caplog):
    monkeypatch.delenv("WAZUH_INDEXER_VERIFY_SSL", raising=False)
    with caplog.at_level(logging.WARNING, logger="soctalk.adapter"):
        result = main._wazuh_indexer_verify_ssl()
    assert result is True
    assert not _warnings(caplog), "unset default must be silent"


@pytest.mark.parametrize("raw", ["maybe", "yes", "no", "verify", "2", "tru e", "off"])
def test_malformed_falls_back_to_true_with_warning(monkeypatch, caplog, raw):
    """Fail-safe: an unrecognised value never silently disables TLS
    verification — it logs a warning and resolves to ``True``."""
    monkeypatch.setenv("WAZUH_INDEXER_VERIFY_SSL", raw)
    with caplog.at_level(logging.WARNING, logger="soctalk.adapter"):
        result = main._wazuh_indexer_verify_ssl()
    assert result is True
    warns = _warnings(caplog)
    assert warns, f"malformed value {raw!r} must emit a warning"
    assert any("WAZUH_INDEXER_VERIFY_SSL" in r.getMessage() for r in warns)


# ---------------------------------------------------------------------------
# _ingest_loop: the Wazuh httpx client honours the resolved verify value
# ---------------------------------------------------------------------------


class _BreakLoop(BaseException):
    """Raised from the fake client to break out of _ingest_loop's
    ``while True``. Subclasses BaseException (not Exception) so the loop's
    ``except Exception`` doesn't swallow it — the coroutine exits on the
    first iteration instead of spinning forever."""


def _install_recording_client(monkeypatch) -> list[dict]:
    """Replace httpx.AsyncClient with a recorder that captures each
    constructor's kwargs and aborts the loop on the first POST."""
    created: list[dict] = []

    class _RecordingClient:
        def __init__(self, *args, **kwargs):
            created.append(kwargs)

        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return False

        async def post(self, *args, **kwargs):
            raise _BreakLoop

    monkeypatch.setattr(main.httpx, "AsyncClient", _RecordingClient)
    return created


@pytest.mark.parametrize("raw,expected_verify", [("true", True), ("false", False)])
async def test_ingest_loop_uses_resolved_verify(monkeypatch, raw, expected_verify):
    monkeypatch.setenv("WAZUH_INDEXER_VERIFY_SSL", raw)
    monkeypatch.setenv("SOCTALK_API_URL", "http://l1.local")
    monkeypatch.setenv("SOCTALK_TENANT_ID", "tenant-xyz")
    monkeypatch.setenv("SOCTALK_INGEST_DISABLED", "0")
    monkeypatch.setattr(main, "_read_token", lambda: "tok")
    created = _install_recording_client(monkeypatch)

    with pytest.raises(_BreakLoop):
        await main._ingest_loop()

    # Exactly one client — the Wazuh indexer client — is constructed with an
    # explicit ``verify=``; the L1 api client uses httpx's default. That one
    # must carry the resolved value, not a hard-coded False.
    verify_kwargs = [kw["verify"] for kw in created if "verify" in kw]
    assert verify_kwargs == [expected_verify]
