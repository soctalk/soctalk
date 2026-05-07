"""organizations: slug + branding columns for MSSP-side public landing.

Revision ID: v1_0010_organizations_slug
Revises: v1_0009_case_runs_lease
Create Date: 2026-04-30

Symmetric to ``branding_configs`` for tenants: gives the canonical UI
something to fetch unauthenticated against ``<slug>.mssp.<base>`` so it
can render branded login pages and pin scope before the user types
credentials. Backfills ``slug`` from ``lower(mssp_name)`` for existing
installs; new orgs are expected to set it explicitly at bootstrap.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op


revision = "v1_0010_organizations_slug"
down_revision = "v1_0009_case_runs_lease"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Add columns nullable so we can backfill, then promote ``slug`` to
    # NOT NULL + UNIQUE after.
    op.add_column("organizations", sa.Column("slug", sa.String(63), nullable=True))
    op.add_column("organizations", sa.Column("logo_url", sa.String(500), nullable=True))
    op.add_column("organizations", sa.Column("primary_color", sa.String(16), nullable=True))
    op.add_column("organizations", sa.Column("secondary_color", sa.String(16), nullable=True))
    op.add_column("organizations", sa.Column("favicon_url", sa.String(500), nullable=True))

    # Backfill: lowercase mssp_name with non-[a-z0-9-] stripped. Falls
    # back to install_label, then to a stub. Caller can correct via an
    # admin tool later if needed.
    op.execute(
        """
        UPDATE organizations
           SET slug = COALESCE(
                 NULLIF(
                   regexp_replace(lower(mssp_name), '[^a-z0-9-]+', '-', 'g'),
                   ''
                 ),
                 NULLIF(
                   regexp_replace(lower(install_label), '[^a-z0-9-]+', '-', 'g'),
                   ''
                 ),
                 'mssp-' || substr(mssp_id::text, 1, 8)
               )
         WHERE slug IS NULL
        """
    )

    op.alter_column("organizations", "slug", nullable=False)
    op.create_unique_constraint(
        "uq_organizations_slug", "organizations", ["slug"]
    )
    op.create_index("ix_organizations_slug", "organizations", ["slug"])


def downgrade() -> None:
    op.drop_index("ix_organizations_slug", table_name="organizations")
    op.drop_constraint("uq_organizations_slug", "organizations")
    op.drop_column("organizations", "favicon_url")
    op.drop_column("organizations", "secondary_color")
    op.drop_column("organizations", "primary_color")
    op.drop_column("organizations", "logo_url")
    op.drop_column("organizations", "slug")
