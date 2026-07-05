"""Typed plugin errors."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class PluginError(Exception):
    """Raised by handlers to signal a typed error to the launchpad.

    Attributes:
        category: One of the ``launchpad_sdk.Category`` values.
        code: Namespaced string owned by the plugin (e.g. ``"hetzner.credentials.missing"``).
        message: Human-readable message. Rendered in the TUI's error card.
        hint: Actionable hint (e.g. ``"set HCLOUD_TOKEN"``).
        docs_url: Optional link to plugin docs.
        retry: Optional retry hint. Format matches the wire protocol:
               ``{"mode": "never"|"immediate"|"backoff"|"manual", "after_ms": N, "max_attempts": N}``.
    """

    category: str
    code: str
    message: str
    hint: str = ""
    docs_url: str = ""
    retry: Optional[dict] = field(default=None)

    def __str__(self) -> str:  # pragma: no cover
        return f"[{self.category}/{self.code}] {self.message}"
