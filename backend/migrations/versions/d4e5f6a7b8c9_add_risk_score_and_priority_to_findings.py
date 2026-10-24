"""add_risk_score_and_priority_to_findings

Revision ID: d4e5f6a7b8c9
Revises: c3d4e5f6a7b8
Create Date: 2026-10-24 03:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'd4e5f6a7b8c9'
down_revision: Union[str, Sequence[str], None] = 'c3d4e5f6a7b8'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema to add risk_score, priority, and cvss_score to findings table."""
    with op.batch_alter_table('findings', schema=None) as batch_op:
        batch_op.add_column(sa.Column('risk_score', sa.Integer(), nullable=True))
        batch_op.add_column(sa.Column('priority', sa.String(length=50), nullable=True))
        batch_op.add_column(sa.Column('cvss_score', sa.Float(), nullable=True))
        batch_op.create_index(batch_op.f('ix_findings_risk_score'), ['risk_score'], unique=False)
        batch_op.create_index(batch_op.f('ix_findings_priority'), ['priority'], unique=False)


def downgrade() -> None:
    """Downgrade schema to remove risk_score, priority, and cvss_score."""
    with op.batch_alter_table('findings', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_findings_priority'))
        batch_op.drop_index(batch_op.f('ix_findings_risk_score'))
        batch_op.drop_column('cvss_score')
        batch_op.drop_column('priority')
        batch_op.drop_column('risk_score')
