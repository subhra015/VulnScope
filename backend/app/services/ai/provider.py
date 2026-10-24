"""
Abstract base class and context models for AI providers.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Dict, Optional

from app.services.ai.schemas import AIRemediationResponseSchema, AIPatchResponseSchema


class AIProviderError(Exception):
    """Base exception for AI provider errors."""
    pass


class AIConfigurationError(AIProviderError):
    """Raised when an AI provider is improperly configured or presents security risks."""
    pass


class AIRateLimitError(AIProviderError):
    """Raised when an AI provider responds with HTTP 429 Too Many Requests."""
    pass


class AITimeoutError(AIProviderError):
    """Raised when an AI provider times out."""
    pass


class AIValidationError(AIProviderError):
    """Raised when an AI provider returns a response that fails schema validation."""
    pass


@dataclass
class FindingContext:
    """Bounded, sanitized context passed to an AI provider."""
    finding_id: str
    scan_id: str
    category: str
    rule_id: str
    title: str
    description: str
    scanner_name: str
    original_severity: str
    risk_score: Optional[int]
    risk_priority: Optional[str]
    risk_reason: Optional[str]
    package_name: Optional[str] = None
    package_version: Optional[str] = None
    ecosystem: Optional[str] = None
    fixed_version: Optional[str] = None
    advisory_url: Optional[str] = None
    file_path: Optional[str] = None
    start_line: Optional[int] = None
    end_line: Optional[int] = None
    source_snippet: Optional[str] = None
    deterministic_guidance_summary: Optional[str] = None
    deterministic_steps: Optional[list] = None


class AIProvider(ABC):
    """Abstract interface implemented by all AI remediation providers."""

    @abstractmethod
    def is_available(self) -> bool:
        """Return True if provider is active and ready."""
        pass

    @abstractmethod
    def get_metadata(self) -> Dict[str, str]:
        """Return metadata dict containing provider name, model, etc."""
        pass

    @abstractmethod
    async def generate_remediation(self, context: FindingContext) -> AIRemediationResponseSchema:
        """Generate structured explanation and remediation steps."""
        pass

    @abstractmethod
    async def generate_patch(self, context: FindingContext) -> AIPatchResponseSchema:
        """Generate proposed unified diff fix."""
        pass
