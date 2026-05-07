"""v1_add_auth_models (pass-through)

Revision ID: ce989e482ad9
Revises: a11c9ed4a018
Create Date: 2026-04-22

History note
------------
Previously added ``password_credentials`` + ``sessions`` tables that had
been missing because my earlier consolidated migration didn't include
them. Those tables are actually created correctly by the legacy
``v1_0002_internal_auth`` migration, so this file is now a pass-through.
Kept as a named revision to preserve continuity for any dev DB stamped
at ``ce989e482ad9`` during the broken interval.
"""

from __future__ import annotations

from typing import Sequence, Union

from alembic import op  # noqa: F401
import sqlalchemy as sa  # noqa: F401


revision: str = "ce989e482ad9"
down_revision: Union[str, Sequence[str], None] = "a11c9ed4a018"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """No-op: see module docstring."""


def downgrade() -> None:
    """No-op: see module docstring."""
