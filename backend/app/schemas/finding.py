"""
Pydantic schemas for findings, risk explanations, and remediation guidance.
"""

from datetime import datetime
from typing import TYPE_CHECKING, Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field

if TYPE_CHECKING:
    from app.services.ai.schemas import RemediationProposalResponse


class ScoringFactorSchema(BaseModel):
    name: str = Field(..., description="Factor dimension name")
    weight: float = Field(..., description="Weight coefficient (0-1)")
    raw_score: float = Field(..., description="Raw score component (0-100)")
    contribution: float = Field(..., description="Weighted contribution to total score")
    description: str = Field(..., description="Detailed justification")


class RiskExplanationSchema(BaseModel):
    score: int = Field(..., ge=0, le=100, description="Calculated finding-risk priority score (0-100)")
    priority: str = Field(..., description="Priority tier: 'critical', 'high', 'medium', 'low'")
    priority_label: str = Field(..., description="Human-readable priority label")
    factors: List[ScoringFactorSchema] = Field(default_factory=list, description="Breakdown of scoring factors")
    evidence: Dict[str, Any] = Field(default_factory=dict, description="Extracted input evidence")
    reason: str = Field(..., description="Concise human-readable rationale")
    missing_evidence: List[str] = Field(default_factory=list, description="Uncertainty caveats and missing data points")


class RemediationGuidanceSchema(BaseModel):
    category: str = Field(..., description="Finding category: 'code', 'secret', or 'dependency'")
    summary: str = Field(..., description="Remediation summary")
    steps: List[str] = Field(default_factory=list, description="Concrete step-by-step remediation actions")
    unsafe_pattern: Optional[str] = Field(default=None, description="Explanation of unsafe implementation pattern")
    safer_alternative: Optional[str] = Field(default=None, description="Recommended safe pattern or snippet")
    caveats: List[str] = Field(default_factory=list, description="Essential caveats, limitations, or warnings")
    references: List[str] = Field(default_factory=list, description="Authoritative reference URLs")
    fixed_version: Optional[str] = Field(default=None, description="Upstream fixed version if verified")
    package_ecosystem: Optional[str] = Field(default=None, description="Dependency ecosystem")


class FindingResponse(BaseModel):
    id: str
    scan_id: str
    finding_fingerprint: Optional[str] = None
    scanner_name: str
    category: Optional[str] = Field(default="code", description="Finding category: 'code', 'secret', or 'dependency'")
    rule_id: str
    title: str
    description: str
    severity: str
    confidence: Optional[str] = None
    file_path: Optional[str] = None
    start_line: Optional[int] = None
    end_line: Optional[int] = None
    package_name: Optional[str] = None
    package_version: Optional[str] = None
    ecosystem: Optional[str] = None
    fixed_version: Optional[str] = None
    redacted_evidence: Optional[str] = None
    remediation_guidance: Optional[str] = None
    advisory_url: Optional[str] = None
    risk_score: Optional[int] = Field(default=None, description="Finding-risk priority score (0-100)")
    priority: Optional[str] = Field(default=None, description="Risk priority ('critical', 'high', 'medium', 'low')")
    cvss_score: Optional[float] = Field(default=None, description="CVSS base score if available")
    lifecycle_status: Optional[str] = Field(default=None, description="Lifecycle status ('new', 'recurring', 'changed')")
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class FindingDetailResponse(FindingResponse):
    risk_explanation: Optional[RiskExplanationSchema] = Field(default=None, description="Detailed score explanation")
    remediation: Optional[RemediationGuidanceSchema] = Field(default=None, description="Structured remediation guidance")
    ai_proposal: Optional[Any] = Field(default=None, description="AI-assisted remediation proposal if generated")


class FindingsListResponse(BaseModel):
    total: int = Field(..., description="Total count of matching findings")
    items: List[FindingResponse] = Field(default_factory=list, description="Paginated list of normalized findings")
    limit: int = Field(default=50, description="Page size limit")
    offset: int = Field(default=0, description="Offset position")

    model_config = ConfigDict(from_attributes=True)


class RiskSummaryResponse(BaseModel):
    scan_id: str
    total_findings: int
    priority_distribution: Dict[str, int] = Field(..., description="Counts for critical, high, medium, low")
    severity_distribution: Dict[str, int] = Field(..., description="Counts for critical, high, medium, low, info")
    category_distribution: Dict[str, Dict[str, Any]] = Field(default_factory=dict, description="Distribution by category with avg scores")
    mean_risk_score: float = Field(default=0.0, description="Average risk score across findings")
    max_risk_score: int = Field(default=0, description="Maximum risk score observed in scan")
    scanner_coverage: Dict[str, str] = Field(default_factory=dict, description="Execution status for each scanner")
    coverage_notes: List[str] = Field(default_factory=list, description="Important caveats and missing coverage warnings")


class FindingChangeDetailSchema(BaseModel):
    field: str
    old_value: Any
    new_value: Any


class ComparisonFindingItemSchema(BaseModel):
    finding_id: str
    scan_id: str
    scanner_name: str
    category: Optional[str] = None
    rule_id: str
    title: str
    severity: str
    file_path: Optional[str] = None
    start_line: Optional[int] = None
    package_name: Optional[str] = None
    package_version: Optional[str] = None
    fixed_version: Optional[str] = None
    lifecycle_status: str
    changes: List[FindingChangeDetailSchema] = Field(default_factory=list)
    risk_score: Optional[int] = None
    priority: Optional[str] = None


class ScanComparisonResponse(BaseModel):
    scan_id: str
    baseline_scan_id: str
    repository_id: Optional[str] = None
    summary: Dict[str, int] = Field(..., description="Summary counts for new, recurring, resolved, changed, unconfirmed")
    new_findings: List[ComparisonFindingItemSchema] = Field(default_factory=list)
    recurring_findings: List[ComparisonFindingItemSchema] = Field(default_factory=list)
    resolved_findings: List[ComparisonFindingItemSchema] = Field(default_factory=list)
    changed_findings: List[ComparisonFindingItemSchema] = Field(default_factory=list)
    unconfirmed_findings: List[ComparisonFindingItemSchema] = Field(default_factory=list)
    comparability_notes: List[str] = Field(default_factory=list)
