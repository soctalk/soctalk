"""Shared adapter⇄control-plane wire schema (issue #17).

This package is deliberately dependency-light (pydantic only, which the
adapter image already carries via fastapi) and is included in BOTH
distribution surfaces:

- the control-plane wheel (``[tool.hatch.build.targets.wheel]`` packages)
- the adapter image (``Dockerfile.adapter`` copies it next to
  ``soctalk_adapter``)

so the two ends of ``POST /api/internal/adapter/events`` validate against
the same artifact instead of drifting copies.

Versioning: the batch envelope carries ``schema_version`` (missing = 1).
Evolution is additive-only — new optional fields, never renames or type
changes. A consumer receiving a higher version than it supports processes
the batch best-effort (unknown fields ignored) and logs a warning.
"""

from soctalk_wire.events import (
    SCHEMA_VERSION,
    AdapterEvent,
    IngestBatch,
    IngestedIOC,
    WireEntity,
)
from soctalk_wire.redaction import REDACTION_VERSION, redact_text
from soctalk_wire.template import TEMPLATE_VERSION, template_hash

__all__ = [
    "SCHEMA_VERSION",
    "AdapterEvent",
    "IngestBatch",
    "IngestedIOC",
    "WireEntity",
    "REDACTION_VERSION",
    "redact_text",
    "TEMPLATE_VERSION",
    "template_hash",
]
