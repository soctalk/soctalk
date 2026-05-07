"""Password hashing and policy.

argon2id via ``argon2-cffi``. Parameters match P1-1 §5 (OWASP 2025
baseline). The hash string embeds all parameters, so tuning is
backwards-compatible via transparent rehash on verify.
"""

from __future__ import annotations

import secrets

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError


MIN_PASSWORD_LENGTH = 12
MAX_PASSWORD_LENGTH = 4096

# argon2id parameters, owasp 2025 baseline. Do not tune downward.
_HASHER = PasswordHasher(
    time_cost=3,
    memory_cost=65_536,
    parallelism=4,
    hash_len=32,
    salt_len=16,
)


class PasswordPolicyError(ValueError):
    """The candidate password does not meet policy (length, etc.)."""


def validate_password(candidate: str) -> None:
    if len(candidate) < MIN_PASSWORD_LENGTH:
        raise PasswordPolicyError(
            f"Password must be at least {MIN_PASSWORD_LENGTH} characters."
        )
    if len(candidate) > MAX_PASSWORD_LENGTH:
        raise PasswordPolicyError(
            f"Password must be at most {MAX_PASSWORD_LENGTH} characters."
        )


def hash_password(plain: str) -> str:
    """Argon2id-hash a cleartext password. Caller must have already
    called :func:`validate_password`."""

    return _HASHER.hash(plain)


def verify_password(plain: str, stored_hash: str) -> tuple[bool, str | None]:
    """Verify a cleartext password against a stored hash.

    Returns ``(matched, maybe_new_hash)``. If the hash was produced under
    an older parameter set, ``maybe_new_hash`` is a rehash under the
    current parameters; callers should write it back transparently.
    """

    try:
        _HASHER.verify(stored_hash, plain)
    except (VerifyMismatchError, InvalidHashError):
        return (False, None)
    if _HASHER.check_needs_rehash(stored_hash):
        return (True, _HASHER.hash(plain))
    return (True, None)


def generate_admin_reset_password() -> str:
    """Produce a strong random password for the admin-reset flow.

    The generated string is shown once to the admin and never stored in
    cleartext. Format is URL-safe base64 of 24 random bytes → 32 chars.
    """

    return secrets.token_urlsafe(24)
