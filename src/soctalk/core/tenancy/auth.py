"""Ingress-handoff authentication for SocTalk V1.

``docs/v1/00-decisions.md`` D-06 (three-layer access
model) and ``docs/v1/P0-1-security-model.md`` §§6.1–6.2 (token claims).

Pattern:

1. An ingress-level OIDC proxy (OAuth2-Proxy / Keycloak / Dex) authenticates
   the user and attaches trusted headers to upstream requests:

     - ``X-Forwarded-User``
     - ``X-Forwarded-Email``
     - ``X-Forwarded-Groups``

2. SocTalk accepts these only from ``trustedProxyCIDRs`` (chart value). Any
   request bearing these headers from an untrusted peer is rejected.

3. SocTalk looks up the ``User`` row by email; ``User.role`` and
   ``User.tenant_id`` determine scope. A short-lived internal JWT is minted
   for the request (HMAC-signed with the install's JWT signing key) and
   placed in ``request.state.user_identity``.

V1.5+ additions:

- Per-customer OIDC federation: customer-viewer users can authenticate
  against the customer's own IdP (different OAuth2-Proxy per tenant).
- Native OIDC / SAML in SocTalk (no proxy).
- Token revocation list for fast logout.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
from dataclasses import asdict, dataclass
from ipaddress import ip_address, ip_network
from typing import Any
from uuid import UUID

import structlog
from fastapi import HTTPException, Request, Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from soctalk.core.tenancy.models import Role, User, UserType

logger = structlog.get_logger()


INGRESS_USER_HEADER = "X-Forwarded-User"
INGRESS_EMAIL_HEADER = "X-Forwarded-Email"
INGRESS_GROUPS_HEADER = "X-Forwarded-Groups"

SESSION_COOKIE_NAME = "soctalk_session"
SESSION_TTL_SECONDS = 3600  # 1h; refresh on activity
IMPERSONATION_TTL_SECONDS = 1800  # 30min


# ----------------------------------------------------------------------------
# Identity
# ----------------------------------------------------------------------------


@dataclass(frozen=True)
class UserIdentity:
    """The identity resolved for a request.

    Shape mirrors the JWT claims; dict form is attached to ``request.state``.
    """

    user_id: UUID
    email: str
    user_type: str  # UserType enum value
    role: str  # Role enum value
    tenant_id: UUID | None = None
    # Set when an MSSP-side user is impersonating a tenant.
    current_tenant: UUID | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "user_id": str(self.user_id),
            "email": self.email,
            "user_type": self.user_type,
            "role": self.role,
            "tenant_id": str(self.tenant_id) if self.tenant_id else None,
            "current_tenant": (
                str(self.current_tenant) if self.current_tenant else None
            ),
        }


# ----------------------------------------------------------------------------
# Trusted-proxy check
# ----------------------------------------------------------------------------


def _peer_is_trusted(peer_ip: str | None, trusted_cidrs: list[str]) -> bool:
    if peer_ip is None:
        return False
    try:
        peer = ip_address(peer_ip)
    except ValueError:
        return False
    for cidr in trusted_cidrs:
        try:
            if peer in ip_network(cidr, strict=False):
                return True
        except ValueError:
            continue
    return False


def _trusted_cidrs_from_env() -> list[str]:
    raw = os.getenv("OIDC_TRUSTED_PROXY_CIDRS", "10.0.0.0/8,172.16.0.0/12")
    return [c.strip() for c in raw.split(",") if c.strip()]


# ----------------------------------------------------------------------------
# User lookup
# ----------------------------------------------------------------------------


async def _lookup_user_by_email(session: AsyncSession, email: str) -> User | None:
    result = await session.execute(select(User).where(User.email == email))
    return result.scalar_one_or_none()


async def _lookup_user_for_auth(
    email: str,
    request_session: AsyncSession | None,
) -> User | None:
    """Resolve login identity, including tenant-scoped users.

    Tenant users are hidden from the app-role session until a tenant context is
    set. At ingress login time that context is not known yet, so this named path
    uses the MSSP DB role to find the user row and then hands regular request
    handling back to the app-role session plus RLS.
    """
    try:
        from soctalk.core.tenancy.db import get_mssp_sessionmaker

        sm = get_mssp_sessionmaker()
        async with sm() as mssp_session:
            return await _lookup_user_by_email(mssp_session, email)
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "mssp_auth_lookup_failed",
            error=str(exc),
        )
        if request_session is not None:
            return await _lookup_user_by_email(request_session, email)
        return None


# ----------------------------------------------------------------------------
# JWT (HMAC-signed; SSO identity lives outside)
# ----------------------------------------------------------------------------


_CACHED_JWT_KEY: bytes | None = None
_CACHED_JWT_SOURCE: str | None = None  # "file" | "env" | "ephemeral"


def _jwt_signing_key() -> bytes:
    """Load the install's JWT signing key: cached for the life of the process.

    Precedence:
    1. File at ``JWT_SIGNING_KEY_PATH`` (Secret volume. Helm default
       ``/run/secrets/soctalk/jwt-key``).
    2. ``SOCTALK_JWT_SIGNING_KEY`` env var (dev / tests).
    3. Ephemeral random 32 bytes (tests that don't configure a key).

    V1 uses HMAC for simplicity (single-pod API). V1.5 moves to asymmetric
    (RSA/Ed25519) for multi-pod. Key rotation is manual V1.

    The ephemeral fallback is cached for the process lifetime so mint/verify
    pairs remain valid during local test runs.
    """
    global _CACHED_JWT_KEY, _CACHED_JWT_SOURCE
    if _CACHED_JWT_KEY is not None:
        return _CACHED_JWT_KEY

    secret_path = os.getenv("JWT_SIGNING_KEY_PATH", "/run/secrets/soctalk/jwt-key")
    if os.path.isfile(secret_path):
        with open(secret_path, "rb") as fh:
            key = fh.read().strip()
        _CACHED_JWT_KEY = key
        _CACHED_JWT_SOURCE = "file"
        return key

    env_key = os.getenv("SOCTALK_JWT_SIGNING_KEY")
    if env_key:
        _CACHED_JWT_KEY = env_key.encode("utf-8")
        _CACHED_JWT_SOURCE = "env"
        return _CACHED_JWT_KEY

    logger.warning(
        "no_jwt_signing_key_configured",
        msg="using ephemeral key; tokens invalidate on restart",
    )
    _CACHED_JWT_KEY = os.urandom(32)
    _CACHED_JWT_SOURCE = "ephemeral"
    return _CACHED_JWT_KEY


def reset_jwt_signing_key_cache() -> None:
    """Test helper; discards the cached key so subsequent calls re-resolve."""
    global _CACHED_JWT_KEY, _CACHED_JWT_SOURCE
    _CACHED_JWT_KEY = None
    _CACHED_JWT_SOURCE = None


# ---------------------------------------------------------------------------
# Adapter JWTs use a separate signing key from user session JWTs.
#
# Only SocTalk system pods should have the adapter signing key. Tenant adapter
# pods receive a tenant-bound token minted by SocTalk during provisioning.
# ---------------------------------------------------------------------------


_CACHED_ADAPTER_KEY: bytes | None = None


def _adapter_signing_key() -> bytes:
    """Load the adapter JWT signing key (distinct from session-JWT key)."""
    global _CACHED_ADAPTER_KEY
    if _CACHED_ADAPTER_KEY is not None:
        return _CACHED_ADAPTER_KEY

    secret_path = os.getenv(
        "ADAPTER_SIGNING_KEY_PATH", "/run/secrets/adapter/signing_key"
    )
    if os.path.isfile(secret_path):
        with open(secret_path, "rb") as fh:
            _CACHED_ADAPTER_KEY = fh.read().strip()
        return _CACHED_ADAPTER_KEY

    env_key = os.getenv("SOCTALK_ADAPTER_SIGNING_KEY")
    if env_key:
        _CACHED_ADAPTER_KEY = env_key.encode("utf-8")
        return _CACHED_ADAPTER_KEY

    logger.warning(
        "no_adapter_signing_key_configured",
        msg="using ephemeral key; adapter tokens invalidate on restart",
    )
    _CACHED_ADAPTER_KEY = os.urandom(32)
    return _CACHED_ADAPTER_KEY


def reset_adapter_signing_key_cache() -> None:
    global _CACHED_ADAPTER_KEY
    _CACHED_ADAPTER_KEY = None


def mint_adapter_token(
    tenant_id: UUID, *, ttl_seconds: int = 7 * 24 * 3600
) -> str:
    """Mint a tenant-bound adapter token signed with the adapter key."""
    now = int(time.time())
    claims = {
        "iss": "soctalk",
        "sub": "adapter",
        "user_type": "adapter",
        "tenant_id": str(tenant_id),
        "scope": "adapter",
        "iat": now,
        "exp": now + ttl_seconds,
    }
    payload = json.dumps(claims, separators=(",", ":")).encode("utf-8")
    sig = hmac.new(_adapter_signing_key(), payload, hashlib.sha256).hexdigest()
    return f"{payload.hex()}.{sig}"


def verify_adapter_token(token: str) -> UserIdentity | None:
    """Verify an adapter JWT.

    Returns a :class:`UserIdentity` with ``user_type='adapter'`` on success,
    or None on any failure (bad signature, expired, malformed).
    """
    try:
        payload_hex, sig = token.split(".", 1)
        payload = bytes.fromhex(payload_hex)
    except ValueError:
        return None
    expected = hmac.new(_adapter_signing_key(), payload, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, expected):
        return None
    try:
        claims: dict[str, Any] = json.loads(payload.decode("utf-8"))
    except ValueError:
        return None
    if claims.get("exp", 0) < int(time.time()):
        return None
    if claims.get("user_type") != "adapter" or claims.get("scope") != "adapter":
        return None
    try:
        tid = UUID(claims["tenant_id"])
    except (KeyError, ValueError):
        return None
    return UserIdentity(
        user_id=UUID("00000000-0000-0000-0000-000000000000"),
        email="adapter",
        user_type="adapter",
        role="adapter",
        tenant_id=tid,
    )


def mint_worker_token(
    tenant_id: UUID, *, ttl_seconds: int = 30 * 24 * 3600
) -> str:
    """Mint a tenant-bound runs-worker token signed with the adapter key."""
    now = int(time.time())
    claims = {
        "iss": "soctalk",
        "sub": "runs-worker",
        "user_type": "worker",
        "tenant_id": str(tenant_id),
        "scope": "runs",
        "iat": now,
        "exp": now + ttl_seconds,
    }
    payload = json.dumps(claims, separators=(",", ":")).encode("utf-8")
    sig = hmac.new(_adapter_signing_key(), payload, hashlib.sha256).hexdigest()
    return f"{payload.hex()}.{sig}"


def verify_worker_token(token: str) -> UserIdentity | None:
    """Verify a runs-worker token. Returns identity with ``user_type='worker'``."""
    try:
        payload_hex, sig = token.split(".", 1)
        payload = bytes.fromhex(payload_hex)
    except ValueError:
        return None
    expected = hmac.new(_adapter_signing_key(), payload, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, expected):
        return None
    try:
        claims: dict[str, Any] = json.loads(payload.decode("utf-8"))
    except ValueError:
        return None
    if claims.get("exp", 0) < int(time.time()):
        return None
    if claims.get("user_type") != "worker" or claims.get("scope") != "runs":
        return None
    try:
        tid = UUID(claims["tenant_id"])
    except (KeyError, ValueError):
        return None
    return UserIdentity(
        user_id=UUID("00000000-0000-0000-0000-000000000000"),
        email="runs-worker",
        user_type="worker",
        role="worker",
        tenant_id=tid,
    )


def mint_session_token(identity: UserIdentity, ttl: int = SESSION_TTL_SECONDS) -> str:
    now = int(time.time())
    claims = {
        "iss": "soctalk",
        "sub": str(identity.user_id),
        "email": identity.email,
        "user_type": identity.user_type,
        "role": identity.role,
        "tenant_id": str(identity.tenant_id) if identity.tenant_id else None,
        "current_tenant": (
            str(identity.current_tenant) if identity.current_tenant else None
        ),
        "iat": now,
        "exp": now + ttl,
    }
    payload = json.dumps(claims, separators=(",", ":")).encode("utf-8")
    sig = hmac.new(_jwt_signing_key(), payload, hashlib.sha256).hexdigest()
    return f"{payload.hex()}.{sig}"


def verify_session_token(token: str) -> UserIdentity | None:
    try:
        payload_hex, sig = token.split(".", 1)
        payload = bytes.fromhex(payload_hex)
    except ValueError:
        return None
    expected = hmac.new(_jwt_signing_key(), payload, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, expected):
        return None
    claims: dict[str, Any] = json.loads(payload.decode("utf-8"))
    if claims.get("exp", 0) < int(time.time()):
        return None
    try:
        return UserIdentity(
            user_id=UUID(claims["sub"]),
            email=claims["email"],
            user_type=claims["user_type"],
            role=claims["role"],
            tenant_id=UUID(claims["tenant_id"]) if claims.get("tenant_id") else None,
            current_tenant=(
                UUID(claims["current_tenant"])
                if claims.get("current_tenant")
                else None
            ),
        )
    except (KeyError, ValueError):
        return None


def mint_impersonation_token(
    mssp_user: UserIdentity, tenant_id: UUID
) -> str:
    """Mint a short-lived token for an MSSP-side user to act as a tenant."""
    if mssp_user.role not in {Role.MSSP_ADMIN.value, Role.PLATFORM_ADMIN.value, Role.ANALYST.value}:
        raise HTTPException(403, "role not allowed to impersonate")
    impersonating = UserIdentity(
        user_id=mssp_user.user_id,
        email=mssp_user.email,
        user_type=mssp_user.user_type,
        role=mssp_user.role,
        tenant_id=mssp_user.tenant_id,
        current_tenant=tenant_id,
    )
    return mint_session_token(impersonating, ttl=IMPERSONATION_TTL_SECONDS)


# ----------------------------------------------------------------------------
# Middleware
# ----------------------------------------------------------------------------


async def ingress_handoff_middleware(request: Request, call_next):
    """Resolve identity from ingress trusted headers OR from session cookie.

    Flow:
    1. If ``Authorization: Bearer <token>`` or session cookie present → verify
       and attach identity.
    2. Else if ingress headers present AND peer is a trusted proxy → look up
       user, mint session token, set cookie, attach identity.
    3. Else no identity (request proceeds unauthenticated; endpoint decorators
       enforce).
    """
    identity = _identity_from_cookie_or_bearer(request)

    if identity is None and _peer_is_trusted(
        request.client.host if request.client else None,
        _trusted_cidrs_from_env(),
    ):
        email = request.headers.get(INGRESS_EMAIL_HEADER)
        if email:
            session = _resolve_db_session(request)
            if session is not None:
                user = await _lookup_user_for_auth(email, session)
                if user and user.active:
                    identity = UserIdentity(
                        user_id=user.id,
                        email=user.email,
                        user_type=user.user_type,
                        role=user.role,
                        tenant_id=user.tenant_id,
                    )
                    # Mint a session token + set cookie so subsequent requests
                    # skip the lookup.
                    token = mint_session_token(identity)
                    request.state._set_session_cookie = token  # Response set by handler

    if identity is not None:
        request.state.user_identity = identity.as_dict()

        # Stamp RLS session vars so policies see audience + tenant on
        # this request. The internal-session middleware does the same;
        # without it, proxy-mode handlers run with empty
        # ``app.current_*`` and RLS policies block tenant data lookups.
        from soctalk.core.tenancy.context import set_request_db_context
        from soctalk.core.tenancy.models import UserType as _UserType

        db = _resolve_db_session(request)
        if db is not None:
            audience = (
                "customer"
                if identity.user_type == _UserType.TENANT.value
                else "mssp"
            )
            await set_request_db_context(
                db,
                tenant_id=identity.current_tenant or identity.tenant_id,
                audience=audience,
                user_role=identity.role,
            )

    response: Response = await call_next(request)
    # Apply session cookie if minted this request.
    token_to_set = getattr(request.state, "_set_session_cookie", None)
    if token_to_set:
        response.set_cookie(
            SESSION_COOKIE_NAME,
            token_to_set,
            max_age=SESSION_TTL_SECONDS,
            httponly=True,
            samesite="lax",
            secure=os.getenv("SOCTALK_INSECURE_COOKIE", "false").lower() != "true",
        )
    return response


def _identity_from_cookie_or_bearer(request: Request) -> UserIdentity | None:
    # Bearer header wins over cookie.
    auth = request.headers.get("Authorization", "")
    if auth.lower().startswith("bearer "):
        return verify_session_token(auth.split(" ", 1)[1].strip())
    cookie = request.cookies.get(SESSION_COOKIE_NAME)
    if cookie:
        return verify_session_token(cookie)
    return None


def _resolve_db_session(request: Request) -> AsyncSession | None:
    """Look up the DB session attached by the app's session middleware.

    Implementations differ; this helper makes the dependency loose. Returns
    None if no session is attached (caller must handle by deferring lookup).
    """
    return getattr(request.state, "db", None)


# ----------------------------------------------------------------------------
# Public helpers for routes
# ----------------------------------------------------------------------------


def current_identity(request: Request) -> UserIdentity:
    identity_dict = getattr(request.state, "user_identity", None)
    if identity_dict is None:
        raise HTTPException(401, "not authenticated")
    return UserIdentity(
        user_id=UUID(identity_dict["user_id"]),
        email=identity_dict["email"],
        user_type=identity_dict["user_type"],
        role=identity_dict["role"],
        tenant_id=(
            UUID(identity_dict["tenant_id"])
            if identity_dict.get("tenant_id")
            else None
        ),
        current_tenant=(
            UUID(identity_dict["current_tenant"])
            if identity_dict.get("current_tenant")
            else None
        ),
    )


def resolve_request_tenant(request: Request) -> UUID | None:
    """Resolve the tenant id a request should operate on.

    Priority:
    1. ``current_tenant`` claim (MSSP user impersonating).
    2. ``tenant_id`` claim (tenant user).
    3. None (install-scoped / system paths).
    """
    identity = current_identity(request)
    return identity.current_tenant or identity.tenant_id


__all__ = [
    "INGRESS_EMAIL_HEADER",
    "INGRESS_GROUPS_HEADER",
    "INGRESS_USER_HEADER",
    "SESSION_COOKIE_NAME",
    "UserIdentity",
    "current_identity",
    "ingress_handoff_middleware",
    "mint_adapter_token",
    "mint_impersonation_token",
    "mint_session_token",
    "mint_worker_token",
    "reset_adapter_signing_key_cache",
    "reset_jwt_signing_key_cache",
    "resolve_request_tenant",
    "verify_adapter_token",
    "verify_session_token",
    "verify_worker_token",
]
