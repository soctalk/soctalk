"""Auth-mode configuration.

The install picks one of ``internal | proxy`` via ``SOCTALK_AUTH_MODE``.
"""

from __future__ import annotations

import os
from enum import Enum


class AuthMode(str, Enum):
    INTERNAL = "internal"
    PROXY = "proxy"


def get_auth_mode() -> AuthMode:
    raw = (os.getenv("SOCTALK_AUTH_MODE") or AuthMode.INTERNAL.value).strip().lower()
    try:
        return AuthMode(raw)
    except ValueError:
        raise RuntimeError(
            f"Invalid SOCTALK_AUTH_MODE={raw!r}; "
            f"expected one of {[m.value for m in AuthMode]}"
        )


def public_origin() -> str | None:
    """First (canonical) first-party origin for CSRF validation.

    Kept for backward compatibility. New code should use
    :func:`public_origins` and :func:`origin_is_trusted` so slug-driven
    tenant subdomains (e.g. ``http://acme.soctalk.ai`` alongside
    ``http://labz.soctalk.ai``) are accepted.
    """

    origins = public_origins()
    return origins[0] if origins else None


def public_origins() -> list[str]:
    """Allowed first-party origins for CSRF validation.

    Sources, in order:

    1. ``SOCTALK_PUBLIC_ORIGIN`` — comma-separated list of explicit
       origins (``http://labz.soctalk.ai,http://acme.soctalk.ai``).
       Required as the canonical entry; the first non-empty value is
       what :func:`public_origin` returns.
    2. ``SOCTALK_PUBLIC_ORIGIN_BASE`` — base domain (e.g.
       ``soctalk.ai``). When set, any ``<sub>.<base>`` over the same
       scheme as origin #1 is also accepted, which lets tenant slug
       hosts like ``acme.soctalk.ai`` clear CSRF without enumerating
       each tenant in the chart values. The wildcard is host-only;
       scheme + port still must match the canonical origin.

    Returns empty list when nothing is configured — callers should
    treat that as "reject" (the existing fail-closed default).
    """

    raw = (os.getenv("SOCTALK_PUBLIC_ORIGIN") or "").strip()
    explicit = [p.strip() for p in raw.split(",") if p.strip()] if raw else []
    return explicit


def public_origin_wildcard_base() -> str | None:
    """Optional ``<base>`` for accepting ``<sub>.<base>`` CSRF origins."""
    value = os.getenv("SOCTALK_PUBLIC_ORIGIN_BASE")
    return value.strip().lstrip(".") if value else None


def origin_is_trusted(origin: str) -> bool:
    """Whether ``origin`` (scheme://host[:port]) is a trusted first-party
    origin per :func:`public_origins` plus an optional wildcard base.
    """

    if not origin:
        return False
    allowed = public_origins()
    if origin in allowed:
        return True
    base = public_origin_wildcard_base()
    if not base or not allowed:
        return False
    # Use the canonical origin's scheme + port as the wildcard template.
    from urllib.parse import urlparse

    canonical = urlparse(allowed[0])
    parsed = urlparse(origin)
    if parsed.scheme != canonical.scheme:
        return False
    if parsed.port != canonical.port:
        return False
    host = (parsed.hostname or "").lower()
    base_l = base.lower()
    # Only ``<sub>.<base>`` is trusted, NOT the apex ``<base>`` itself.
    # The wildcard ingress (``*.soctalk.ai``) routes subdomains; the
    # apex may host an unrelated app that would otherwise inherit the
    # session cookie and pass CSRF on a same-site cookie attach.
    # Operators who want the apex trusted must add it to
    # SOCTALK_PUBLIC_ORIGIN explicitly.
    return host != base_l and host.endswith("." + base_l)
