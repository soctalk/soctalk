"""V1 observability helpers.

- :mod:`~soctalk.core.observability.metrics`. Prometheus exporter with
  per-tenant labels.
- :mod:`~soctalk.core.observability.audit`: convenience helpers for writing
  AuditLog rows without boilerplate.
"""

from soctalk.core.observability.metrics import (  # noqa: F401
    metrics_router,
    tenant_events_ingested,
    tenant_investigations_opened,
    tenant_llm_tokens_used,
    tenant_pending_reviews,
)

__all__ = [
    "metrics_router",
    "tenant_events_ingested",
    "tenant_investigations_opened",
    "tenant_llm_tokens_used",
    "tenant_pending_reviews",
]
