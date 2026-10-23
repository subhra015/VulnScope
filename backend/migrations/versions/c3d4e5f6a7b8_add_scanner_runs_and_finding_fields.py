"""add_scanner_runs_and_finding_fields

Revision ID: c3d4e5f6a7b8
Revises: f9834dfe4820
Create Date: 2026-10-23 20:48:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'c3d4e5f6a7b8'
down_revision: Union[str, Sequence[str], None] = 'f9834dfe4820'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema to add scanner_runs table and extra finding fields."""
    # 1. Create scanner_runs table
    op.create_table(
        'scanner_runs',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('scan_id', sa.String(length=36), nullable=False),
        sa.Column('scanner_name', sa.String(length=50), nullable=False),
        sa.Column('status', sa.String(length=50), nullable=False, server_default='pending'),
        sa.Column('scanner_version', sa.String(length=100), nullable=True),
        sa.Column('started_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('duration_seconds', sa.Float(), nullable=True),
        sa.Column('findings_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('error_message', sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(['scan_id'], ['scans.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('scanner_runs', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_scanner_runs_id'), ['id'], unique=False)
        batch_op.create_index(batch_op.f('ix_scanner_runs_scan_id'), ['scan_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_scanner_runs_scanner_name'), ['scanner_name'], unique=False)
        batch_op.create_index(batch_op.f('ix_scanner_runs_status'), ['status'], unique=False)

    # 2. Add extra finding fields to findings table
    with op.batch_alter_table('findings', schema=None) as batch_op:
        batch_op.add_column(sa.Column('category', sa.String(length=50), nullable=True))
        batch_op.add_column(sa.Column('package_name', sa.String(length=255), nullable=True))
        batch_op.add_column(sa.Column('package_version', sa.String(length=100), nullable=True))
        batch_op.add_column(sa.Column('ecosystem', sa.String(length=100), nullable=True))
        batch_op.add_column(sa.Column('fixed_version', sa.String(length=100), nullable=True))
        batch_op.create_index(batch_op.f('ix_findings_category'), ['category'], unique=False)


def downgrade() -> None:
    """Downgrade schema."""
    with op.batch_alter_table('findings', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_findings_category'))
        batch_op.drop_column('fixed_version')
        batch_op.drop_column('ecosystem')
        batch_op.drop_column('package_version')
        batch_op.drop_column('package_name')
        batch_op.drop_column('category')

    with op.batch_alter_table('scanner_runs', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_scanner_runs_status'))
        batch_op.drop_index(batch_op.f('ix_scanner_runs_scanner_name'))
        batch_op.drop_index(batch_op.f('ix_scanner_runs_scan_id'))
        batch_op.drop_index(batch_op.f('ix_scanner_runs_id'))

    op.drop_table('scanner_runs')
