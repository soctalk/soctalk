"""Reversibility test for v1_0012_integration_external_wazuh.

Acceptance criterion #2 for ``tenant.profile.provided.model``:

    alembic upgrade head followed by alembic downgrade -1 on the new
    revision is reversible in tests/v1/test_provisioning_controller.py
    (or a dedicated migration test) without raising.

This is a dedicated migration test. It boots a synchronous SQLAlchemy
engine against the test Postgres (``DATABASE_URL_ADMIN``), runs
``alembic upgrade head`` to ensure we're at the tip, then
``alembic downgrade -1`` to roll back exactly the new revision, then
``alembic upgrade head`` again. Each step must succeed without raising
and must leave the five new columns present (after upgrade) or absent
(after downgrade) on ``integration_configs``.

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


_NEW_COLUMNS = {
    "wazuh_username",
    "wazuh_password_plain",
    "wazuh_api_token_plain",
    "wazuh_indexer_url",
    "wazuh_api_url",
}


def _admin_sync_url() -> str:
    """Sync (psycopg2) DSN built from the admin async URL fixture default."""
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


def _profile_check_constraint_def(engine) -> str:
    """Return the current ``CHECK`` clause body of ``ck_tenants_profile``.

    This is the implementation-agnostic way to verify which profile values
    the DB will accept. We can't easily INSERT a tenants row from this
    test (the ``soctalk_admin`` role is DDL-only and lacks DML privileges
    on ``organizations``), so we inspect ``pg_constraint`` directly.
    """
    from sqlalchemy import text

    with engine.connect() as conn:
        row = conn.execute(
            text(
                "SELECT pg_get_constraintdef(oid) FROM pg_constraint "
                "WHERE conname = 'ck_tenants_profile' "
                "AND conrelid = 'tenants'::regclass"
            )
        ).first()
    assert row is not None, "ck_tenants_profile constraint not found on tenants"
    return row[0]


def test_v1_0012_external_wazuh_is_reversible():
    """upgrade → downgrade -1 → upgrade is round-trippable without raising,
    the five new columns toggle on/off accordingly, and the
    ``ck_tenants_profile`` CHECK constraint admits ``'provided'`` only
    while v1_0012 is applied.
    """
    from alembic import command
    from sqlalchemy import create_engine

    from sqlalchemy import text

    cfg = _alembic_config()
    engine = create_engine(_admin_sync_url(), future=True)

    try:
        # Make sure we're at head before the test (some other test may
        # have left us mid-stream).
        command.upgrade(cfg, "head")

        # Other tests in this session may have inserted tenant rows whose
        # ``profile`` value would violate the *narrower* pre-v1_0012
        # CHECK constraint we're about to (temporarily) restore during
        # downgrade. TRUNCATE every tenant-scoped table CASCADE so the
        # downgrade DDL can re-add the old constraint without
        # ``CheckViolation``. The admin role has TRUNCATE privilege.
        with engine.begin() as conn:
            conn.execute(
                text(
                    "TRUNCATE tenants, organizations RESTART IDENTITY CASCADE"
                )
            )

        cols_at_head = _column_names(engine, "integration_configs")
        assert _NEW_COLUMNS.issubset(cols_at_head), (
            "v1_0012 should have added the wazuh_* columns at head, "
            f"got: {sorted(cols_at_head)}"
        )

        # CHECK constraint must list 'provided' at head.
        ck_at_head = _profile_check_constraint_def(engine)
        assert "'provided'" in ck_at_head, (
            "ck_tenants_profile should admit 'provided' at head after "
            f"v1_0012, got: {ck_at_head!r}"
        )

        # Step back across exactly v1_0012.
        command.downgrade(cfg, "-1")

        cols_after_down = _column_names(engine, "integration_configs")
        # The five new columns must be gone; legacy columns remain.
        assert not (_NEW_COLUMNS & cols_after_down), (
            "downgrade -1 should have dropped the wazuh_* columns, "
            f"still present: {sorted(_NEW_COLUMNS & cols_after_down)}"
        )
        # Sanity: pre-existing columns survive the downgrade.
        assert "wazuh_url" in cols_after_down
        assert "llm_api_key_plain" in cols_after_down

        # CHECK constraint must NOT list 'provided' after downgrade and
        # must still list the three pre-v1_0012 values.
        ck_after_down = _profile_check_constraint_def(engine)
        assert "'provided'" not in ck_after_down, (
            "ck_tenants_profile should NOT admit 'provided' after "
            f"downgrade -1, got: {ck_after_down!r}"
        )
        for legacy_value in ("'poc'", "'persistent'", "'legacy'"):
            assert legacy_value in ck_after_down, (
                f"ck_tenants_profile should still admit {legacy_value} "
                f"after downgrade -1, got: {ck_after_down!r}"
            )

        # Re-apply so subsequent tests in this run see the post-state.
        command.upgrade(cfg, "head")
        cols_again = _column_names(engine, "integration_configs")
        assert _NEW_COLUMNS.issubset(cols_again)
        ck_again = _profile_check_constraint_def(engine)
        assert "'provided'" in ck_again
    finally:
        engine.dispose()
