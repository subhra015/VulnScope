"""
Pydantic schemas for findings.
"""

from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel, ConfigDict, Field


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
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class FindingsListResponse(BaseModel):
    total: int = Field(..., description="Total count of matching findings")
    items: List[FindingResponse] = Field(default_factory=list, description="Paginated list of normalized findings")
    limit: int = Field(default=50, description="Page size limit")
    offset: int = Field(default=0, description="Offset position")

    model_config = ConfigDict(from_attributes=True)
