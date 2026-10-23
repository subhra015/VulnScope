"""
Pydantic schemas for Scan requests and responses.
"""

from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.schemas.finding import FindingResponse
from app.schemas.scanner_run import ScannerRunResponse


class SourceType(str, Enum):
    GITHUB = "github"
    ZIP = "zip"


class ScanCreateRequest(BaseModel):
    project_name: str = Field(
        ...,
        min_length=1,
        max_length=255,
        description="Name of the project or repository to scan",
        examples=["my-auth-service", "vulnscope-core"],
    )
    source_type: SourceType = Field(
        ...,
        description="Source type of the project: 'github' or 'zip'",
        examples=["github", "zip"],
    )
    source_reference: Optional[str] = Field(
        default=None,
        max_length=500,
        description="Optional non-sensitive source reference, e.g. repository URL or archive name",
        examples=["https://github.com/example/my-auth-service", "archive.zip"],
    )

    @field_validator("project_name")
    @classmethod
    def validate_project_name(cls, v: str) -> str:
        trimmed = v.strip()
        if not trimmed:
            raise ValueError("project_name cannot be blank or only whitespace")
        return trimmed

    @field_validator("source_reference")
    @classmethod
    def clean_source_reference(cls, v: Optional[str]) -> Optional[str]:
        if v is not None:
            trimmed = v.strip()
            return trimmed if trimmed else None
        return None


class ScanResponse(BaseModel):
    id: str = Field(..., description="Unique scan identifier")
    project_name: str = Field(..., description="Project name")
    source_type: str = Field(..., description="Source type (github or zip)")
    source_reference: Optional[str] = Field(default=None, description="Source reference")
    status: str = Field(..., description="Current status of the security scan ('created', 'running', 'completed', 'partial', 'failed')")
    intake_status: Optional[str] = Field(
        default="created",
        description="Current status of source intake ('created', 'ingesting', 'ready', 'failed')",
    )
    created_at: datetime = Field(..., description="UTC creation timestamp")
    started_at: Optional[datetime] = Field(default=None, description="UTC start timestamp")
    completed_at: Optional[datetime] = Field(default=None, description="UTC completion timestamp")
    error_summary: Optional[str] = Field(default=None, description="Error summary if scan or intake failed")

    model_config = ConfigDict(from_attributes=True)


class ScanDetailResponse(ScanResponse):
    repository_id: Optional[str] = Field(default=None, description="Associated repository ID")
    workspace_id: Optional[str] = Field(
        default=None,
        description="Isolated workspace identifier (UUID only, internal filesystem paths are omitted)",
    )
    findings: List[FindingResponse] = Field(
        default_factory=list,
        description="Security findings for this scan",
    )
    scanner_runs: List[ScannerRunResponse] = Field(
        default_factory=list,
        description="Individual scanner run executions (Semgrep, Gitleaks, OSV-Scanner)",
    )
    findings_summary: Optional[Dict[str, int]] = Field(
        default=None,
        description="Summary metrics (total, code, secret, dependency, critical, high, medium, low)",
    )

    model_config = ConfigDict(from_attributes=True)


class ScanRunResponse(BaseModel):
    scan_id: str = Field(..., description="Scan identifier")
    status: str = Field(..., description="Current scan status, e.g. 'running'")
    message: str = Field(..., description="Status message")
