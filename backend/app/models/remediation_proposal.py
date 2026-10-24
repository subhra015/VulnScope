"""
Remediation Proposal database model.
Tracks AI-assisted explanations, proposed unified diffs, explicit review states,
and rescan verification lifecycle for security findings.
"""

from datetime import datetime
import json
from typing import TYPE_CHECKING, List, Optional
from sqlalchemy import Boolean, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, UTCDateTime, generate_uuid, utc_now

if TYPE_CHECKING:
    from app.models.finding import Finding
    from app.models.scan import Scan


class RemediationProposal(Base):
    """
    Represents an AI-assisted remediation proposal and optional code patch.
    Maintains a strict, verifiable lifecycle:
    'proposed' -> 'reviewed' / 'rejected' / 'downloaded' -> 'verification_pending' -> 'verified_by_rescan' / 'unconfirmed'.
    """
    __tablename__ = "remediation_proposals"

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
    finding_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("findings.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    finding_fingerprint: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True,
        index=True,
    )
    # Lifecycle states:
    # 'proposed', 'reviewed', 'rejected', 'downloaded', 'validation_failed',
    # 'verification_pending', 'verified_by_rescan', 'unconfirmed'
    status: Mapped[str] = mapped_column(
        String(50),
        default="proposed",
        nullable=False,
        index=True,
    )
    provider: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
    )  # "ollama", "openai", "fallback"
    model_name: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )
    explanation: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )
    likely_root_cause: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )
    potential_impact: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )
    remediation_steps_json: Mapped[str] = mapped_column(
        Text,
        default="[]",
        nullable=False,
    )
    secure_coding_pattern: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
    )
    testing_recommendations_json: Mapped[str] = mapped_column(
        Text,
        default="[]",
        nullable=False,
    )
    caveats_and_assumptions_json: Mapped[str] = mapped_column(
        Text,
        default="[]",
        nullable=False,
    )
    patch_appropriate: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
    )
    target_file_path: Mapped[Optional[str]] = mapped_column(
        String(1000),
        nullable=True,
    )
    change_summary: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
    )
    diff_content: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
    )
    validation_error: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
    )
    user_notes: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        UTCDateTime,
        default=utc_now,
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        UTCDateTime,
        default=utc_now,
        nullable=False,
    )

    # Helper properties for JSON lists
    @property
    def remediation_steps(self) -> List[str]:
        try:
            return json.loads(self.remediation_steps_json)
        except Exception:
            return []

    @remediation_steps.setter
    def remediation_steps(self, value: List[str]) -> None:
        self.remediation_steps_json = json.dumps(value)

    @property
    def testing_recommendations(self) -> List[str]:
        try:
            return json.loads(self.testing_recommendations_json)
        except Exception:
            return []

    @testing_recommendations.setter
    def testing_recommendations(self, value: List[str]) -> None:
        self.testing_recommendations_json = json.dumps(value)

    @property
    def caveats_and_assumptions(self) -> List[str]:
        try:
            return json.loads(self.caveats_and_assumptions_json)
        except Exception:
            return []

    @caveats_and_assumptions.setter
    def caveats_and_assumptions(self, value: List[str]) -> None:
        self.caveats_and_assumptions_json = json.dumps(value)

    # Relationships
    scan: Mapped["Scan"] = relationship(
        "Scan",
        back_populates="remediation_proposals",
    )
    finding: Mapped["Finding"] = relationship(
        "Finding",
        back_populates="remediation_proposals",
    )

    def __repr__(self) -> str:
        return f"<RemediationProposal(id={self.id}, finding_id={self.finding_id}, status={self.status})>"
