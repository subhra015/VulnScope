"""
Scan database model.
Tracks vulnerability analysis scan executions and lifecycle states.
"""

from datetime import datetime
from typing import TYPE_CHECKING, List, Optional
from sqlalchemy import ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, UTCDateTime, generate_uuid, utc_now

if TYPE_CHECKING:
    from app.models.repository import Repository
    from app.models.finding import Finding
    from app.models.scanner_run import ScannerRun
    from app.models.remediation_proposal import RemediationProposal


class Scan(Base):
    """
    Represents a vulnerability and risk analysis scan execution.
    In Phase 1, stores scan metadata with initial status 'created'.
    No scanning execution or result generation occurs in Phase 1.
    """
    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=generate_uuid,
        index=True,
    )
    repository_id: Mapped[Optional[str]] = mapped_column(
        String(36),
        ForeignKey("repositories.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    project_name: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        index=True,
    )
    source_type: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
    )  # "github" or "zip"
    source_reference: Mapped[Optional[str]] = mapped_column(
        String(500),
        nullable=True,
    )
    status: Mapped[str] = mapped_column(
        String(50),
        default="created",
        nullable=False,
        index=True,
    )  # Security scan status: 'created', 'queued', 'running', 'completed', 'failed'
    intake_status: Mapped[Optional[str]] = mapped_column(
        String(50),
        default="created",
        nullable=True,
        index=True,
    )  # Source intake status: 'created', 'ingesting', 'ready', 'failed'
    workspace_id: Mapped[Optional[str]] = mapped_column(
        String(36),
        nullable=True,
        index=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        UTCDateTime,
        default=utc_now,
        nullable=False,
        index=True,
    )
    started_at: Mapped[Optional[datetime]] = mapped_column(
        UTCDateTime,
        nullable=True,
    )
    completed_at: Mapped[Optional[datetime]] = mapped_column(
        UTCDateTime,
        nullable=True,
    )
    error_summary: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
    )

    # Relationships
    repository: Mapped[Optional["Repository"]] = relationship(
        "Repository",
        back_populates="scans",
    )
    findings: Mapped[List["Finding"]] = relationship(
        "Finding",
        back_populates="scan",
        cascade="all, delete-orphan",
    )
    scanner_runs: Mapped[List["ScannerRun"]] = relationship(
        "ScannerRun",
        back_populates="scan",
        cascade="all, delete-orphan",
        order_by="ScannerRun.scanner_name",
    )
    remediation_proposals: Mapped[List["RemediationProposal"]] = relationship(
        "RemediationProposal",
        back_populates="scan",
        cascade="all, delete-orphan",
    )

    def __repr__(self) -> str:
        return f"<Scan(id={self.id}, project_name={self.project_name}, status={self.status})>"
