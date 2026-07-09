"""Normalized log-template identity (issue #17 fix 4).

Masks the variable spans of a log line so repeated log *shapes* hash to
the same value, letting the control plane cluster known templates and
flag novel ones (spend enrichment on novelty, not volume). The hash is
kept OUT of the coalescing signature so alert grouping never changes.

``TEMPLATE_VERSION`` versions the masking rules so hashes stay comparable
across adapter upgrades: a hash is only meaningful alongside its version.
"""

from __future__ import annotations

import hashlib
import re

TEMPLATE_VERSION = "1"

# Order: most specific first so a timestamp isn't half-eaten by the
# number rule, etc.
_MASKS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\b\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b"), "<TS>"),
    (re.compile(r"\b(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}\b"), "<MAC>"),
    (re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"), "<IP>"),
    (re.compile(r"\b[a-fA-F0-9]{32,64}\b"), "<HASH>"),
    (re.compile(r"/[^\s]+"), "<PATH>"),
    (re.compile(r"\b\d+\b"), "<N>"),
    (re.compile(r"\bhttps?://\S+\b"), "<URL>"),
]


def template_hash(text: str | None) -> str | None:
    """Return a stable hex hash of the masked log shape, or None."""
    if not text:
        return None
    masked = text
    for pattern, repl in _MASKS:
        masked = pattern.sub(repl, masked)
    masked = re.sub(r"\s+", " ", masked).strip()
    digest = hashlib.sha256(masked.encode("utf-8")).hexdigest()
    return digest[:32]
