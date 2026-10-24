"""
Finding database model.
Prepares schema for scanner results (Semgrep, Gitleaks, OSV).
In Phase 1, no scanner results are generated.
"""

from datetime import datetime
from typing import TYPE_CHECKING, Optional
from sqlalchemy import Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, UTCDateTime, generate_uuid, utc_now

if TYPE_CHECKING:
    from app.models.scan import Scan


class Finding(Base):
    """
    Represents an individual security finding, secret exposure, or dependency vulnerability.
    Schema prepared for Phase 3 scanner integrations.
    """
    __tablename__ = "findings"

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
    finding_fingerprint: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True,
        index=True,
    )  # SHA-256 or hash for regression tracking across scans
    scanner_name: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )  # "semgrep", "gitleaks", "osv-scanner"
    rule_id: Mapped[str] = mapped_column(
        String(200),
        nullable=False,
    )  # e.g., "python.lang.security.insecure-deserialization"
    category: Mapped[Optional[str]] = mapped_column(
        String(50),
        nullable=True,
        index=True,
    )  # "code", "secret", "dependency"
    title: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )
    description: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )
    severity: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
    )  # "critical", "high", "medium", "low", "info"
    confidence: Mapped[Optional[str]] = mapped_column(
        String(50),
        nullable=True,
    )  # "high", "medium", "low"
    file_path: Mapped[Optional[str]] = mapped_column(
        String(1000),
        nullable=True,
    )
    start_line: Mapped[Optional[int]] = mapped_column(
        Integer,
        nullable=True,
    )
    end_line: Mapped[Optional[int]] = mapped_column(
        Integer,
        nullable=True,
    )
    package_name: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True,
    )
    package_version: Mapped[Optional[str]] = mapped_column(
        String(100),
        nullable=True,
    )
    ecosystem: Mapped[Optional[str]] = mapped_column(
        String(100),
        nullable=True,
    )
    fixed_version: Mapped[Optional[str]] = mapped_column(
        String(100),
        nullable=True,
    )
    redacted_evidence: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
    )
    remediation_guidance: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
    )
    advisory_url: Mapped[Optional[str]] = mapped_column(
        String(1000),
        nullable=True,
    )
    risk_score: Mapped[Optional[int]] = mapped_column(
        Integer,
        nullable=True,
        index=True,
    )
    priority: Mapped[Optional[str]] = mapped_column(
        String(50),
        nullable=True,
        index=True,
    )
    cvss_score: Mapped[Optional[float]] = mapped_column(
        Float,
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        UTCDateTime,
        default=utc_now,
        nullable=False,
    )

    # Relationships
    scan: Mapped["Scan"] = relationship(
        "Scan",
        back_populates="findings",
    )

    def __repr__(self) -> str:
        return f"<Finding(id={self.id}, rule_id={self.rule_id}, severity={self.severity})>"
