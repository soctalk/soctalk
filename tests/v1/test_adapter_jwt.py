"""Adapter token verification tests."""

from __future__ import annotations

import os
from uuid import uuid4

import pytest

os.environ.setdefault(
    "SOCTALK_JWT_SIGNING_KEY", "session-key-for-test-only-32-bytes-ok"
)
os.environ.setdefault(
    "SOCTALK_ADAPTER_SIGNING_KEY", "adapter-key-for-test-only-32-bytes"
)

from soctalk.core.tenancy import auth


@pytest.fixture(autouse=True)
def _reset_keys():
    auth.reset_jwt_signing_key_cache()
    auth.reset_adapter_signing_key_cache()
    yield
    auth.reset_jwt_signing_key_cache()
    auth.reset_adapter_signing_key_cache()


def test_mint_and_verify_adapter_token_roundtrip():
    tid = uuid4()
    token = auth.mint_adapter_token(tid)
    identity = auth.verify_adapter_token(token)
    assert identity is not None
    assert identity.user_type == "adapter"
    assert identity.tenant_id == tid
    assert identity.role == "adapter"


def test_adapter_token_rejects_session_jwt():
    """A token signed with the session key must be rejected by the adapter
    verifier."""
    tid = uuid4()
    user_token = auth.mint_session_token(
        auth.UserIdentity(
            user_id=uuid4(),
            email="x@example.com",
            user_type="tenant",
            role="customer_viewer",
            tenant_id=tid,
        )
    )
    assert auth.verify_adapter_token(user_token) is None


def test_session_verify_rejects_adapter_token():
    """Reverse direction: adapter token must not be accepted by session verifier."""
    tid = uuid4()
    adapter_token = auth.mint_adapter_token(tid)
    assert auth.verify_session_token(adapter_token) is None


def test_adapter_token_rejects_tamper():
    token = auth.mint_adapter_token(uuid4())
    payload_hex, sig = token.split(".", 1)
    tampered = f"{payload_hex}.{('0' if sig[0] != '0' else '1')}{sig[1:]}"
    assert auth.verify_adapter_token(tampered) is None


def test_adapter_token_rejects_expired(monkeypatch):
    tid = uuid4()
    import time

    fixed_now = [1_000_000]
    monkeypatch.setattr(auth.time, "time", lambda: fixed_now[0])
    token = auth.mint_adapter_token(tid, ttl_seconds=60)
    # Advance time past expiry.
    fixed_now[0] += 3600
    assert auth.verify_adapter_token(token) is None


def test_adapter_token_missing_claims_rejected():
    # Forge a "valid-signed but missing tenant_id" token manually.
    import hashlib
    import hmac
    import json
    import time as time_mod

    claims = {
        "iss": "soctalk",
        "sub": "adapter",
        "user_type": "adapter",
        "scope": "adapter",
        "iat": int(time_mod.time()),
        "exp": int(time_mod.time()) + 3600,
        # missing tenant_id
    }
    payload = json.dumps(claims, separators=(",", ":")).encode()
    sig = hmac.new(auth._adapter_signing_key(), payload, hashlib.sha256).hexdigest()
    token = f"{payload.hex()}.{sig}"
    assert auth.verify_adapter_token(token) is None
