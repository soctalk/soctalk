"""Alembic migration environment configuration."""

import os
from logging.config import fileConfig

from alembic import context
from sqlalchemy import create_engine, pool
from sqlmodel import SQLModel

# Import all models — v0 legacy (investigations/events/etc.) + v1 native IR.
# Autogenerate walks SQLModel.metadata, so every table-bearing module must
# be imported here or it will be silently dropped from migrations.
from soctalk.persistence.models import (  # noqa: F401
    AnalyzerStats,
    Event,
    InvestigationReadModel,
    IOCStats,
    MetricsHourly,
    PendingReview,
    RuleStats,
)

# v1 native IR + tenancy + auth models. Imported so they're registered
# with SQLModel.metadata — not strictly required for the current
# raw-SQL migrations, but kept so ``alembic revision --autogenerate``
# can see the full surface if we need it again.
import soctalk.core.ir.models  # noqa: F401
import soctalk.core.tenancy.models  # noqa: F401
import soctalk.core.auth.models  # noqa: F401

# this is the Alembic Config object, which provides
# access to the values within the .ini file in use.
config = context.config

# Interpret the config file for Python logging.
# This line sets up loggers basically.
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Use SQLModel's metadata for autogenerate support
target_metadata = SQLModel.metadata


def get_url() -> str:
    """Get database URL from environment, converting async to sync driver."""
    url = os.getenv(
        "DATABASE_URL",
        "postgresql+asyncpg://soctalk:soctalk@localhost:5432/soctalk",
    )
    # Convert async driver to sync driver for Alembic
    # asyncpg -> psycopg2 (or just postgresql for default driver)
    if "+asyncpg" in url:
        url = url.replace("+asyncpg", "+psycopg2")
    return url


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode.

    This configures the context with just a URL
    and not an Engine, though an Engine is acceptable
    here as well.  By skipping the Engine creation
    we don't even need a DBAPI to be available.

    Calls to context.execute() here emit the given string to the
    script output.
    """
    url = get_url()
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode.

    In this scenario we need to create an Engine
    and associate a connection with the context.
    """
    connectable = create_engine(
        get_url(),
        poolclass=pool.NullPool,
    )

    from sqlalchemy import text

    with connectable.connect() as connection:
        # Some revision ids in this chain exceed alembic's default
        # VARCHAR(32) for ``alembic_version.version_num`` (e.g.
        # ``add_llm_settings_to_user_settings`` = 37 chars). Pre-create
        # the version table with a wider column on empty DBs; on
        # already-migrated DBs widen it in place. Both paths must land
        # before alembic tries to write to the table.
        connection.execute(text("""
            CREATE TABLE IF NOT EXISTS alembic_version (
              version_num VARCHAR(64) NOT NULL,
              CONSTRAINT alembic_version_pkc PRIMARY KEY (version_num)
            )
        """))
        connection.execute(text(
            "ALTER TABLE alembic_version "
            "ALTER COLUMN version_num TYPE VARCHAR(64)"
        ))
        connection.commit()

        context.configure(
            connection=connection,
            target_metadata=target_metadata,
        )

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
