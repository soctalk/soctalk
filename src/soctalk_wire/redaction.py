"""Adapter-side secret redaction (issue #17 fix 9).

Runs on the adapter, AFTER IOC extraction and BEFORE anything leaves the
tenant boundary, over every outbound text path (description, title,
raw.*, full_log). Secrets are replaced with typed markers like
``<REDACTED:password>`` so downstream can tell a withheld value from an
absent one.

``REDACTION_VERSION`` bumps whenever the rule set changes, so persisted
evidence records which rules were applied.

Design constraints:
- Must NOT eat the IOCs/entities the extractor needs — those are pulled
  from raw text before this runs, and the patterns here target
  credential shapes, not bare IPs/hashes/domains.
- Markers must be stable text (no random ids) so they don't perturb the
  coalescing signature or reopen matching (which key on asset_ids /
  IOC fingerprints, never on free text — but keep markers deterministic
  regardless).
"""

from __future__ import annotations

import re

REDACTION_VERSION = "1"

# (compiled pattern, marker-label). Order matters: more specific first.
_RULES: list[tuple[re.Pattern[str], str]] = [
    # PEM private key blocks
    (re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----.*?-----END (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----", re.DOTALL), "private_key"),
    # JWTs (three base64url segments)
    (re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b"), "jwt"),
    # AWS access key id / secret
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "aws_key"),
    (re.compile(r"(?i)\baws_secret_access_key\s*[=:]\s*\S+"), "aws_secret"),
    # Bearer / Authorization headers
    (re.compile(r"(?i)\b(?:authorization|bearer)\s*[=:]?\s*[A-Za-z0-9._~+/=-]{12,}"), "auth_token"),
    # Credentials in URLs: scheme://user:pass@host
    (re.compile(r"\b([a-z][a-z0-9+.-]*://[^\s:/@]+):[^\s:/@]+@"), "url_credential"),
    # key=value / key: value secrets (password, passwd, pwd, secret, token, apikey, api_key)
    (re.compile(r"(?i)\b(pass(?:word|wd)?|pwd|secret|token|api[_-]?key)\b\s*[=:]\s*\S+"), "credential"),
    # Payment card numbers (13-19 digits, optionally separated) — Luhn-checked below
    (re.compile(r"\b(?:\d[ -]?){13,19}\b"), "pan_candidate"),
]

_MARKER = "<REDACTED:{label}>"


def _luhn_ok(number: str) -> bool:
    digits = [int(c) for c in number if c.isdigit()]
    if not (13 <= len(digits) <= 19):
        return False
    checksum = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


def redact_text(text: str | None) -> str | None:
    """Replace detected secrets with typed markers. Idempotent-ish: a
    marker contains no secret-shaped substring, so re-running is a no-op."""
    if not text:
        return text
    out = text
    for pattern, label in _RULES:
        if label == "pan_candidate":
            def _sub_pan(m: re.Match[str]) -> str:
                return _MARKER.format(label="pan") if _luhn_ok(m.group(0)) else m.group(0)
            out = pattern.sub(_sub_pan, out)
        elif label == "url_credential":
            # Preserve the scheme://user@ prefix, drop only the password.
            out = pattern.sub(lambda m: f"{m.group(1)}:{_MARKER.format(label='url_credential')}@", out)
        else:
            out = pattern.sub(_MARKER.format(label=label), out)
    return out
