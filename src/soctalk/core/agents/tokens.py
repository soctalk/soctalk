"""Bootstrap / runtime token minting + verification for L2 agents.

Design mirrors soctalk-cloud's L0→L1 scheme:

- Tokens are opaque random strings (``secrets.token_urlsafe(32)``).
- Plaintext is returned to the caller ONCE — shown to the MSSP admin
  (bootstrap) or held in-memory by the agent (runtime). We never
  persist plaintext.
- Argon2id hashes are stored. Verifying scans the small active-token
  set and verifies each candidate; good enough at MVP volumes, trivial
  to add a prefix index later if scale demands.
"""

from __future__ import annotations

import secrets

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError


_hasher = PasswordHasher(
    # Looser cost than user passwords: tokens are already high-entropy,
    # we only need collision resistance + a slow-enough verify.
    time_cost=2,
    memory_cost=32 * 1024,  # 32 MB
    parallelism=2,
)


def mint_token() -> str:
    """~43 char URL-safe random string (32 bytes of entropy)."""
    return secrets.token_urlsafe(32)


def hash_token(plain: str) -> str:
    return _hasher.hash(plain)


def verify_token(stored_hash: str, plain: str) -> bool:
    try:
        _hasher.verify(stored_hash, plain)
        return True
    except VerifyMismatchError:
        return False
