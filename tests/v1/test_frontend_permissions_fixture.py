"""Drift guard: the frontend spec fixture mirrors ROLE_PERMISSIONS.

frontend/tests/helpers.ts hard-codes the mssp_admin capability set so hermetic
Playwright specs can mint a permissions-bearing /auth/me identity. That list
silently rots when a capability is added or renamed server-side — and a stale
fixture makes UI specs pass against permissions no real deployment grants
(or hide nav/panels a real admin would see). Flagged in the #52 test-fix
review; this test fails the build on any asymmetric difference.
"""

from __future__ import annotations

import re
from pathlib import Path

from soctalk.core.tenancy.permissions import ROLE_PERMISSIONS

HELPERS_TS = Path(__file__).resolve().parents[2] / "frontend" / "tests" / "helpers.ts"


def test_frontend_mssp_admin_fixture_matches_role_permissions() -> None:
    source = HELPERS_TS.read_text(encoding="utf-8")
    block = re.search(r"MSSP_ADMIN_PERMISSIONS = \[(.*?)\]", source, re.S)
    assert block, "MSSP_ADMIN_PERMISSIONS not found in frontend/tests/helpers.ts"
    fixture = set(re.findall(r"'([a-z_]+)'", block.group(1)))

    server = {perm.value for perm in ROLE_PERMISSIONS["mssp_admin"]}

    missing = server - fixture
    extra = fixture - server
    assert not missing and not extra, (
        "frontend/tests/helpers.ts MSSP_ADMIN_PERMISSIONS drifted from "
        f"ROLE_PERMISSIONS['mssp_admin']: missing={sorted(missing)} "
        f"extra={sorted(extra)} — update the fixture."
    )
