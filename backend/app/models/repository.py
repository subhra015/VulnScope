"""
Repository database model.
Tracks project/repository metadata and source information.
"""

from datetime import datetime
from typing import TYPE_CHECKING, List, Optional
from sqlalchemy import String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, UTCDateTime, generate_uuid, utc_now

if TYPE_CHECKING:
    from app.models.scan import Scan


class Repository(Base):
    """
    Represents a code repository or source code target.
    In Phase 1, stores metadata without cloning or fetching files.
    """
    __tablename__ = "repositories"

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=generate_uuid,
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
    )  # e.g., "github", "zip"
    source_reference: Mapped[Optional[str]] = mapped_column(
        String(500),
        nullable=True,
    )  # Non-sensitive source reference, e.g. "https://github.com/org/repo" or "upload.zip"
    created_at: Mapped[datetime] = mapped_column(
        UTCDateTime,
        default=utc_now,
        nullable=False,
    )

    # Relationship to scans
    scans: Mapped[List["Scan"]] = relationship(
        "Scan",
        back_populates="repository",
        cascade="all, delete-orphan",
    )

    def __repr__(self) -> str:
        return f"<Repository(id={self.id}, project_name={self.project_name}, source_type={self.source_type})>"
