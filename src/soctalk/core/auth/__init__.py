"""Internal authentication subsystem.

Authoritative spec: ``docs/multi-tenant/P1-1-internal-auth.md``.

Provides a self-contained login path (email + password + DB-backed session
cookie) alongside the V1 ingress-handoff flow. Mode is selected per install
by the ``SOCTALK_AUTH_MODE`` env var.

The subsystem produces the same ``UserIdentity`` shape consumed by the rest
of the app (see ``src/soctalk/core/tenancy/auth.py:67``), so authz
(decorators, RLS context helpers) is unchanged.
"""

from __future__ import annotations

from soctalk.core.auth.models import PasswordCredential, Session

__all__ = ["PasswordCredential", "Session"]
