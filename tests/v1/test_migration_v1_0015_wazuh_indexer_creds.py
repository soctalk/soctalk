"""Reversibility test for v1_0015_wazuh_indexer_credentials.

Boots a synchronous SQLAlchemy engine against the test Postgres
(``DATABASE_URL_ADMIN``), upgrades to head, downgrades to v1_0015's
parent revision (pinned explicitly — a head-relative ``-1`` would break
every time a newer migration lands on top, as v1_0016 did), then upgrades
again. The two new indexer-credential columns on ``integration_configs``
must toggle present/absent accordingly, while the v1_0012-owned
API-credential columns survive the downgrade untouched.

Marked ``@pytest.mark.integration`` since it needs Postgres.
"""

from __future__ import annotations

import os
import pathlib

import pytest


SKIP_INTEGRATION = os.getenv("SKIP_INTEGRATION", "0") == "1"

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        SKIP_INTEGRATION,
        reason="SKIP_INTEGRATION set; migration reversibility test needs Postgres",
    ),
]

# Columns OWNED by v1_0015 (added on upgrade, dropped on downgrade).
_NEW_COLUMNS = {
    "wazuh_indexer_username",
    "wazuh_indexer_password_plain",
}

# v1_0015's parent in the migration chain — the downgrade target that
# unwinds v1_0015 itself regardless of how many revisions sit above it.
_PARENT_REVISION = "v1_0012_integration_external_wazuh"

# v1_0012-owned API columns that must survive this revision's downgrade.
_SURVIVES = {
    "wazuh_username",
    "wazuh_password_plain",
    "wazuh_api_token_plain",
    "wazuh_api_url",
}


def _admin_sync_url() -> str:
    url = os.getenv(
        "DATABASE_URL_ADMIN",
        "postgresql+asyncpg://soctalk_admin:soctalk_admin@localhost:5432/soctalk",
    )
    return url.replace("+asyncpg", "+psycopg2")


def _alembic_config():
    from alembic.config import Config

    repo_root = pathlib.Path(__file__).resolve().parents[2]
    cfg = Config(str(repo_root / "alembic.ini"))
    cfg.set_main_option("script_location", str(repo_root / "alembic"))
    cfg.set_main_option("sqlalchemy.url", _admin_sync_url())
    return cfg


def _column_names(engine, table: str) -> set[str]:
    from sqlalchemy import inspect

    inspector = inspect(engine)
    return {col["name"] for col in inspector.get_columns(table)}


def test_v1_0015_wazuh_indexer_creds_is_reversible():
    """upgrade -> downgrade to v1_0015's parent -> upgrade round-trips,
    toggling exactly the two indexer-credential columns while leaving the
    API columns intact.
    """
    from alembic import command
    from sqlalchemy import create_engine

    cfg = _alembic_config()
    engine = create_engine(_admin_sync_url(), future=True)

    try:
        command.upgrade(cfg, "head")

        cols_at_head = _column_names(engine, "integration_configs")
        assert _NEW_COLUMNS.issubset(cols_at_head), (
            "v1_0015 should have added the indexer-credential columns at head, "
            f"got: {sorted(cols_at_head)}"
        )
        assert _SURVIVES.issubset(cols_at_head)

        command.downgrade(cfg, _PARENT_REVISION)

        cols_after_down = _column_names(engine, "integration_configs")
        assert not (_NEW_COLUMNS & cols_after_down), (
            "downgrade to the parent revision should have dropped the "
            "indexer-credential columns, "
            f"still present: {sorted(_NEW_COLUMNS & cols_after_down)}"
        )
        # The API credential columns (owned by v1_0012) must survive.
        assert _SURVIVES.issubset(cols_after_down)

        command.upgrade(cfg, "head")
        assert _NEW_COLUMNS.issubset(_column_names(engine, "integration_configs"))
    finally:
        engine.dispose()
