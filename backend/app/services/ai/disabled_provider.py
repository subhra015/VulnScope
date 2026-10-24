"""
Disabled AI provider implementation.
Raises clean exceptions or fallback signals when AI is disabled.
"""

from typing import Dict
from app.services.ai.provider import AIConfigurationError, AIProvider, FindingContext
from app.services.ai.schemas import AIRemediationResponseSchema, AIPatchResponseSchema


class DisabledAIProvider(AIProvider):
    """Represents a disabled AI provider state."""

    def is_available(self) -> bool:
        return False

    def get_metadata(self) -> Dict[str, str]:
        return {
            "provider": "disabled",
            "model": "none",
            "status": "disabled",
        }

    async def generate_remediation(self, context: FindingContext) -> AIRemediationResponseSchema:
        raise AIConfigurationError(
            "AI features are currently disabled. Configure AI_PROVIDER in environment to enable."
        )

    async def generate_patch(self, context: FindingContext) -> AIPatchResponseSchema:
        raise AIConfigurationError(
            "AI features are currently disabled. Configure AI_PROVIDER in environment to enable."
        )
