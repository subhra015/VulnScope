"""
Pydantic schemas for Source Intake endpoints (ZIP & GitHub).
"""

from typing import Optional
from pydantic import BaseModel, Field, field_validator


class GithubIntakeRequest(BaseModel):
    repo_url: str = Field(
        ...,
        description="Public HTTPS URL of the GitHub repository to acquire",
        examples=["https://github.com/owner/repository"],
    )
    project_name: Optional[str] = Field(
        default=None,
        max_length=255,
        description="Optional custom project name. Defaults to the repository name if omitted.",
        examples=["my-service"],
    )
    ref: Optional[str] = Field(
        default=None,
        max_length=200,
        description="Optional branch name, tag, or commit SHA",
        examples=["main", "v1.0.0", "7db19cc"],
    )

    @field_validator("repo_url")
    @classmethod
    def validate_repo_url(cls, v: str) -> str:
        trimmed = v.strip()
        if not trimmed:
            raise ValueError("repo_url cannot be blank")
        return trimmed

    @field_validator("project_name")
    @classmethod
    def clean_project_name(cls, v: Optional[str]) -> Optional[str]:
        if v is not None:
            trimmed = v.strip()
            return trimmed if trimmed else None
        return None

    @field_validator("ref")
    @classmethod
    def clean_ref(cls, v: Optional[str]) -> Optional[str]:
        if v is not None:
            trimmed = v.strip()
            return trimmed if trimmed else None
        return None
