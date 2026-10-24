"""
AI Provider Factory.
Instantiates and configures AI providers based on application settings.
"""

from typing import Optional
from app.core.config import settings
from app.services.ai.disabled_provider import DisabledAIProvider
from app.services.ai.ollama_provider import OllamaProvider
from app.services.ai.openai_provider import OpenAIProvider
from app.services.ai.provider import AIProvider

_override_provider: Optional[AIProvider] = None


def set_ai_provider_override(provider: Optional[AIProvider]) -> None:
    """Set an override provider for deterministic automated testing."""
    global _override_provider
    _override_provider = provider


def get_ai_provider() -> AIProvider:
    """
    Returns the configured AI provider instance.
    Defaults to DisabledAIProvider if not enabled or misconfigured.
    """
    if _override_provider is not None:
        return _override_provider

    provider_name = settings.ai_provider.strip().lower()

    if provider_name == "ollama":
        try:
            return OllamaProvider()
        except Exception:
            return DisabledAIProvider()
    elif provider_name == "openai":
        try:
            return OpenAIProvider()
        except Exception:
            return DisabledAIProvider()
    else:
        return DisabledAIProvider()
