"""IntegrationConfig: external Wazuh credential columns for 'provided' profile.

Revision ID: v1_0012_integration_external_wazuh
Revises: v1_0014_chat_focused_tenant
Create Date: 2026-05-22

Context
-------
The 'provided' deployment profile lets a tenant bring their own existing
Wazuh deployment (indexer + API) rather than have SocTalk provision one
in the tenant namespace. The adapter in that tenant points at the external
endpoints with credentials minted out-of-band.

Four new nullable columns on ``integration_configs`` capture the BYO-SIEM
connection material:

  * wazuh_username           VARCHAR(255)   — Wazuh API account name.
  * wazuh_password_plain     VARCHAR(4096)  — Wazuh API password (plaintext).
  * wazuh_api_token_plain    VARCHAR(4096)  — Optional pre-minted API token.
  * wazuh_api_url            VARCHAR(500)   — https://wazuh.example.com:55000

``integration_configs.wazuh_indexer_url`` (VARCHAR(500)) is intentionally
NOT added here: it is already created by ``v1_0013_mssp_chat_scope``,
which this revision now descends from (see the ordering note below).
Both features want the same column with the same shape, so v1_0013 owns
it and this migration only adds the four columns unique to the
external-SIEM credential set. The ``IntegrationConfig`` SQLModel declares
all five fields regardless of which migration created the column.

CHECK constraint expansion
--------------------------
This revision also expands the ``ck_tenants_profile`` CHECK constraint
(introduced in v1_0005) to admit the new ``'provided'`` profile value
alongside the existing ``'poc'``, ``'persistent'``, and ``'legacy'``
values. Without this change, INSERTs of tenants with profile='provided'
are rejected at the DB level even though the Python/Pydantic/SQLModel
layers accept the value.

MVP tradeoff
------------
Plaintext storage of indexer password and API token mirrors the existing
``llm_api_key_plain`` compromise. KMS/Fernet hardening is tracked as a
follow-up across all sensitive columns at once, not per-column.

Migration ordering note
-----------------------
This revision was originally authored against v1_0011 in parallel with
the chat feature chain (v1_0012_chat_tables → v1_0013_mssp_chat_scope →
v1_0014_chat_focused_tenant), producing two alembic heads. It has been
re-parented onto v1_0014_chat_focused_tenant to linearize history into a
single head. The ``v1_0012_`` filename prefix is therefore lower than its
actual position in the chain (after v1_0014) — alembic orders by the
down_revision pointer, not the numeric prefix, so this is cosmetic only.

Reversible.
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision: str = "v1_0012_integration_external_wazuh"
down_revision: str | None = "v1_0014_chat_focused_tenant"
branch_labels: str | None = None
depends_on: str | None = None


_COLUMNS: list[tuple[str, int]] = [
    ("wazuh_username", 255),
    ("wazuh_password_plain", 4096),
    ("wazuh_api_token_plain", 4096),
    ("wazuh_api_url", 500),
]


def upgrade() -> None:
    for name, length in _COLUMNS:
        op.add_column(
            "integration_configs",
            sa.Column(name, sa.String(length=length), nullable=True),
        )

    # Expand the tenants.profile CHECK constraint to include 'provided'.
    op.execute("ALTER TABLE tenants DROP CONSTRAINT ck_tenants_profile")
    op.execute(
        "ALTER TABLE tenants ADD CONSTRAINT ck_tenants_profile "
        "CHECK (profile IN ('poc', 'persistent', 'legacy', 'provided'))"
    )


def downgrade() -> None:
    # Restore the pre-v1_0012 CHECK constraint first. We do this before
    # dropping the new columns so the constraint roll-back is independent
    # of column state on ``integration_configs``.
    op.execute("ALTER TABLE tenants DROP CONSTRAINT ck_tenants_profile")
    op.execute(
        "ALTER TABLE tenants ADD CONSTRAINT ck_tenants_profile "
        "CHECK (profile IN ('poc', 'persistent', 'legacy'))"
    )

    for name, _length in reversed(_COLUMNS):
        op.drop_column("integration_configs", name)
