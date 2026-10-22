"""add_intake_fields_to_scan

Revision ID: f9834dfe4820
Revises: 7db19cc7dd3c
Create Date: 2026-10-22 20:46:37.092547

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'f9834dfe4820'
down_revision: Union[str, Sequence[str], None] = '7db19cc7dd3c'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema to add intake_status and workspace_id to scans table."""
    with op.batch_alter_table('scans', schema=None) as batch_op:
        batch_op.add_column(sa.Column('intake_status', sa.String(length=50), nullable=True, server_default='created'))
        batch_op.add_column(sa.Column('workspace_id', sa.String(length=36), nullable=True))
        batch_op.create_index(batch_op.f('ix_scans_intake_status'), ['intake_status'], unique=False)
        batch_op.create_index(batch_op.f('ix_scans_workspace_id'), ['workspace_id'], unique=False)


def downgrade() -> None:
    """Downgrade schema."""
    with op.batch_alter_table('scans', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_scans_workspace_id'))
        batch_op.drop_index(batch_op.f('ix_scans_intake_status'))
        batch_op.drop_column('workspace_id')
        batch_op.drop_column('intake_status')
