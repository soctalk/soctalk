"""Doc-contract tests for the ``provided`` tenant profile.

Feature: ``tenant.profile.provided.docs``.

These are pure-filesystem assertions — no DB, no network — so they run in any
environment. They pin the *stable anchors* the acceptance criteria enumerate
(filenames, headings, the ``tenant-external-siem-creds`` Secret + its five
keys, the ``PATCH /api/mssp/tenants/{id}/external-siem`` route) rather than
exact prose, so the docs can be reworded without breaking the gate.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

DOCS = Path(__file__).resolve().parents[2] / "docs" / "multi-tenant"

FIVE_KEYS = (
    "INDEXER_USERNAME",
    "INDEXER_PASSWORD",
    "WAZUH_API_USERNAME",
    "WAZUH_API_PASSWORD",
    "WAZUH_API_TOKEN",
)

PATCH_ROUTE = "PATCH /api/mssp/tenants/{id}/external-siem"


def _read(rel: str) -> str:
    path = DOCS / rel
    assert path.is_file(), f"expected doc file is missing: {path}"
    return path.read_text(encoding="utf-8")


def _has_table(text: str) -> bool:
    """True when ``text`` contains at least one markdown table row."""
    return re.search(r"^\s*\|.*\|.*\|", text, re.MULTILINE) is not None


def _section(text: str, heading_token: str) -> str:
    """Return the slice of ``text`` from the heading containing ``heading_token``
    up to the next same-or-higher-level heading (best-effort)."""
    lines = text.splitlines()
    start = None
    for i, line in enumerate(lines):
        if line.lstrip().startswith("#") and heading_token.lower() in line.lower():
            start = i
            break
    assert start is not None, f"no heading containing {heading_token!r}"
    level = len(lines[start]) - len(lines[start].lstrip("#").lstrip(" "))
    out = [lines[start]]
    for line in lines[start + 1 :]:
        if line.lstrip().startswith("#"):
            this_level = len(line) - len(line.lstrip("#").lstrip(" "))
            if this_level <= level:
                break
        out.append(line)
    return "\n".join(out)


# --- Acceptance 1: provided-profile.md ------------------------------------


def test_provided_profile_doc_exists_and_covers_all_sections() -> None:
    text = _read("provided-profile.md")
    low = text.lower()

    # (1) when to choose 'provided'
    assert "when to choose" in low and "provided" in low
    # (2) what SocTalk deploys vs not — as a table
    assert _has_table(text)
    assert "deploy" in low
    # (3) dual credential model: indexer HTTP-Basic vs API HTTP-Basic + token
    assert "dual credential" in low
    assert low.count("basic") >= 2  # indexer basic + API basic
    assert "indexer" in low and "token" in low
    # (4) credential lifecycle: onboard -> Secret -> PATCH -> adapter restart
    assert "onboard" in low
    assert "tenant-external-siem-creds" in text
    assert PATCH_ROUTE in text
    assert "adapter" in low and "restart" in low
    # (5) connectivity prerequisites: adapter FQDN egress AND control-plane egress
    assert "fqdn" in low
    assert "control-plane egress" in low
    assert "chat" in low and "manager" in low
    # (6) failure modes: auth failure + network unreachable, and how surfaced
    assert "failure mode" in low
    assert "authentication" in low or "auth failure" in low
    assert "unreachable" in low


# --- Acceptance 2: secret-placement.md inventory row ----------------------


def test_secret_placement_inventory_row_for_external_siem_creds() -> None:
    text = _read("secret-placement.md")
    inventory = _section(text, "Secret inventory")

    assert "tenant-external-siem-creds" in inventory
    assert "tenant-<slug>" in inventory
    for key in FIVE_KEYS:
        assert key in inventory, f"five-key list missing {key} in Secret inventory"
    low = inventory.lower()
    assert "adapter" in low  # indexer keys consumed by the adapter
    assert "chat resolver" in low  # API keys consumed by the chat resolver
    assert PATCH_ROUTE in inventory  # rotation route


# --- Acceptance 3: wazuh-profiles.md comparison table ---------------------


def test_wazuh_profiles_doc_enumerates_three_profiles_with_table() -> None:
    text = _read("wazuh-profiles.md")
    low = text.lower()

    assert _has_table(text)
    for profile in ("poc", "persistent", "provided"):
        assert profile in low, f"wazuh-profiles.md does not enumerate {profile}"
    # Comparison dimensions required by the acceptance criteria.
    assert "wazuh deploy" in low
    assert "indexer url" in low
    assert "api url" in low
    assert "agent ingress" in low
    assert "resource quota" in low
    assert "decommission" in low


# --- Acceptance 4: README.md Documents table links ------------------------


def test_readme_documents_table_links_new_docs() -> None:
    text = _read("README.md")
    documents = _section(text, "Documents")
    assert "](provided-profile.md)" in documents
    assert "](wazuh-profiles.md)" in documents


# --- Acceptance 5: install guide provided-SIEM variant --------------------


def test_install_guide_has_provided_siem_variant() -> None:
    text = _read("install/README.md")
    onboard = _section(text, "Onboard first customer")

    assert "Variant — provided-SIEM tenant" in onboard
    low = onboard.lower()
    assert "external siem" in low  # the conditional wizard step
    # indexer + API fields the operator must supply.
    assert "indexer_url" in onboard and "api_url" in onboard


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-q"]))
