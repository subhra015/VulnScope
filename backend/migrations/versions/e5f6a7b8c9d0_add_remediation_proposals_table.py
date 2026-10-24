"""add_remediation_proposals_table

Revision ID: e5f6a7b8c9d0
Revises: d4e5f6a7b8c9
Create Date: 2026-10-24 12:30:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from app.models.base import UTCDateTime


# revision identifiers, used by Alembic.
revision: str = 'e5f6a7b8c9d0'
down_revision: Union[str, Sequence[str], None] = 'd4e5f6a7b8c9'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Create remediation_proposals table and its indexes."""
    op.create_table(
        'remediation_proposals',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('scan_id', sa.String(length=36), nullable=False),
        sa.Column('finding_id', sa.String(length=36), nullable=False),
        sa.Column('finding_fingerprint', sa.String(length=255), nullable=True),
        sa.Column('status', sa.String(length=50), nullable=False),
        sa.Column('provider', sa.String(length=50), nullable=False),
        sa.Column('model_name', sa.String(length=100), nullable=False),
        sa.Column('explanation', sa.Text(), nullable=False),
        sa.Column('likely_root_cause', sa.Text(), nullable=False),
        sa.Column('potential_impact', sa.Text(), nullable=False),
        sa.Column('remediation_steps_json', sa.Text(), nullable=False),
        sa.Column('secure_coding_pattern', sa.Text(), nullable=True),
        sa.Column('testing_recommendations_json', sa.Text(), nullable=False),
        sa.Column('caveats_and_assumptions_json', sa.Text(), nullable=False),
        sa.Column('patch_appropriate', sa.Boolean(), nullable=False),
        sa.Column('target_file_path', sa.String(length=1000), nullable=True),
        sa.Column('change_summary', sa.Text(), nullable=True),
        sa.Column('diff_content', sa.Text(), nullable=True),
        sa.Column('validation_error', sa.Text(), nullable=True),
        sa.Column('user_notes', sa.Text(), nullable=True),
        sa.Column('created_at', UTCDateTime(), nullable=False),
        sa.Column('updated_at', UTCDateTime(), nullable=False),
        sa.ForeignKeyConstraint(['finding_id'], ['findings.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['scan_id'], ['scans.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_remediation_proposals_finding_fingerprint'), 'remediation_proposals', ['finding_fingerprint'], unique=False)
    op.create_index(op.f('ix_remediation_proposals_finding_id'), 'remediation_proposals', ['finding_id'], unique=False)
    op.create_index(op.f('ix_remediation_proposals_id'), 'remediation_proposals', ['id'], unique=False)
    op.create_index(op.f('ix_remediation_proposals_scan_id'), 'remediation_proposals', ['scan_id'], unique=False)
    op.create_index(op.f('ix_remediation_proposals_status'), 'remediation_proposals', ['status'], unique=False)


def downgrade() -> None:
    """Drop remediation_proposals table and its indexes."""
    op.drop_index(op.f('ix_remediation_proposals_status'), table_name='remediation_proposals')
    op.drop_index(op.f('ix_remediation_proposals_scan_id'), table_name='remediation_proposals')
    op.drop_index(op.f('ix_remediation_proposals_id'), table_name='remediation_proposals')
    op.drop_index(op.f('ix_remediation_proposals_finding_id'), table_name='remediation_proposals')
    op.drop_index(op.f('ix_remediation_proposals_finding_fingerprint'), table_name='remediation_proposals')
    op.drop_table('remediation_proposals')
