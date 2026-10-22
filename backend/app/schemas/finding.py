"""
Pydantic schemas for findings.
"""

from datetime import datetime
from typing import Optional
from pydantic import BaseModel, ConfigDict, Field


class FindingResponse(BaseModel):
    id: str
    scan_id: str
    finding_fingerprint: Optional[str] = None
    scanner_name: str
    rule_id: str
    title: str
    description: str
    severity: str
    confidence: Optional[str] = None
    file_path: Optional[str] = None
    start_line: Optional[int] = None
    end_line: Optional[int] = None
    redacted_evidence: Optional[str] = None
    remediation_guidance: Optional[str] = None
    advisory_url: Optional[str] = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)
