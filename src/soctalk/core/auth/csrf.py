"""CSRF protection for state-changing first-party requests.

Strategy per P1-1 §6: SameSite=Lax on the session cookie blocks cross-site
POST at the browser layer. In addition, any state-changing request must
carry an ``Origin`` (or fallback ``Referer``) matching the configured
public origin.
"""

from __future__ import annotations

from urllib.parse import urlparse

from fastapi import Request

from soctalk.core.auth.config import origin_is_trusted, public_origin
from soctalk.core.tenancy.auth import SESSION_COOKIE_NAME


STATE_CHANGING_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})


def _origin_of(url: str) -> str:
    parsed = urlparse(url)
    if not parsed.scheme or not parsed.hostname:
        return ""
    origin = f"{parsed.scheme}://{parsed.hostname}"
    if parsed.port:
        origin = f"{origin}:{parsed.port}"
    return origin


def request_origin_is_trusted(request: Request) -> bool:
    """Check whether the request carries an Origin/Referer that matches
    the configured first-party origin.

    Returns True for non-state-changing methods (nothing to check) and for
    requests whose Origin or Referer matches ``SOCTALK_PUBLIC_ORIGIN``.
    Returns False otherwise.
    """

    if request.method.upper() not in STATE_CHANGING_METHODS:
        return True

    # CSRF is a cookie-auth concern. Requests that don't carry the session
    # cookie (e.g., adapter pods authenticated via bearer token) are not
    # subject to cookie auto-attachment and therefore don't need Origin
    # validation. The login endpoint is also exempt by this rule, which is
    # the well-established browser behaviour (login-CSRF is a different,
    # lower-severity concern).
    if SESSION_COOKIE_NAME not in request.cookies:
        return True

    # Without any configured origin we cannot validate, so we reject.
    # Operators must set SOCTALK_PUBLIC_ORIGIN (and optionally
    # SOCTALK_PUBLIC_ORIGIN_BASE for slug-wildcard support).
    if public_origin() is None:
        return False

    origin_header = request.headers.get("Origin")
    if origin_header:
        return origin_is_trusted(origin_header)

    referer_header = request.headers.get("Referer")
    if referer_header:
        return origin_is_trusted(_origin_of(referer_header))

    return False
