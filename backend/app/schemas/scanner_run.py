"""
Pydantic schemas for ScannerRun records.
"""

from datetime import datetime
from typing import Optional
from pydantic import BaseModel, ConfigDict, Field


class ScannerRunResponse(BaseModel):
    id: str = Field(..., description="Unique scanner run record ID")
    scan_id: str = Field(..., description="Associated scan ID")
    scanner_name: str = Field(..., description="Scanner engine name ('semgrep', 'gitleaks', 'osv-scanner')")
    status: str = Field(..., description="Scanner status ('pending', 'running', 'completed', 'failed', 'unavailable', 'timed_out')")
    scanner_version: Optional[str] = Field(default=None, description="Reported scanner CLI version")
    started_at: Optional[datetime] = Field(default=None, description="Start timestamp")
    completed_at: Optional[datetime] = Field(default=None, description="Completion timestamp")
    duration_seconds: Optional[float] = Field(default=None, description="Execution duration in seconds")
    findings_count: int = Field(default=0, description="Number of normalized findings identified by this scanner")
    error_message: Optional[str] = Field(default=None, description="Sanitized error message if failed")

    model_config = ConfigDict(from_attributes=True)
