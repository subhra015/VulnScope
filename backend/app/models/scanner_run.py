"""
ScannerRun database model.
Tracks individual scanner execution metadata, status, version, duration, and error details.
"""

from datetime import datetime
from typing import TYPE_CHECKING, Optional
from sqlalchemy import Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, UTCDateTime, generate_uuid, utc_now

if TYPE_CHECKING:
    from app.models.scan import Scan


class ScannerRun(Base):
    """
    Represents the execution lifecycle and outcome of a specific scanner tool
    (e.g., Semgrep, Gitleaks, OSV-Scanner) within a scan.
    """
    __tablename__ = "scanner_runs"

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=generate_uuid,
        index=True,
    )
    scan_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    scanner_name: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        index=True,
    )  # "semgrep", "gitleaks", "osv-scanner"
    status: Mapped[str] = mapped_column(
        String(50),
        default="pending",
        nullable=False,
        index=True,
    )  # "pending", "running", "completed", "failed", "unavailable", "timed_out"
    scanner_version: Mapped[Optional[str]] = mapped_column(
        String(100),
        nullable=True,
    )
    started_at: Mapped[Optional[datetime]] = mapped_column(
        UTCDateTime,
        nullable=True,
    )
    completed_at: Mapped[Optional[datetime]] = mapped_column(
        UTCDateTime,
        nullable=True,
    )
    duration_seconds: Mapped[Optional[float]] = mapped_column(
        Float,
        nullable=True,
    )
    findings_count: Mapped[int] = mapped_column(
        Integer,
        default=0,
        nullable=False,
    )
    error_message: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
    )

    # Relationships
    scan: Mapped["Scan"] = relationship(
        "Scan",
        back_populates="scanner_runs",
    )

    def __repr__(self) -> str:
        return f"<ScannerRun(id={self.id}, scanner={self.scanner_name}, status={self.status})>"
