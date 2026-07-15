"""merge authored_playbook_active + authorization_facts

Revision ID: a1a451de05a1
Revises: v1_0034_authored_playbook_active, v1_0034_authorization_facts
Create Date: 2026-07-15 10:06:52.370518

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'a1a451de05a1'
down_revision: Union[str, Sequence[str], None] = ('v1_0034_authored_playbook_active', 'v1_0034_authorization_facts')
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    pass


def downgrade() -> None:
    """Downgrade schema."""
    pass
