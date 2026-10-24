"""
OpenAI-compatible AI provider implementation.
Interacts with remote OpenAI-compatible HTTP endpoints (/v1/chat/completions)
with strict HTTPS enforcement, secret redaction in error reporting, and rate limit handling.
"""

import json
import logging
from typing import Any, Dict
import httpx

from app.core.config import settings
from app.services.ai.prompts import (
    build_patch_user_prompt,
    build_remediation_user_prompt,
    build_system_instruction,
)
from app.services.ai.provider import (
    AIConfigurationError,
    AIProvider,
    AIProviderError,
    AIRateLimitError,
    AITimeoutError,
    AIValidationError,
    FindingContext,
)
from app.services.ai.schemas import AIRemediationResponseSchema, AIPatchResponseSchema

logger = logging.getLogger(__name__)


class OpenAIProvider(AIProvider):
    """
    Connects to any remote OpenAI-compatible API endpoint via HTTPS.
    Guarantees API credentials are never logged, echoed, or included in client exceptions.
    """

    def __init__(self):
        try:
            self.base_url = settings.get_validated_ai_endpoint()
        except Exception as exc:
            raise AIConfigurationError(f"OpenAI configuration error: {exc}") from exc

        if not settings.ai_api_key:
            raise AIConfigurationError(
                "AI_API_KEY must be configured in environment when using OpenAI provider."
            )

        self.api_key = settings.ai_api_key
        self.model = settings.ai_model if settings.ai_model != "default" else "gpt-4o-mini"
        self.timeout = settings.ai_timeout_seconds

    def is_available(self) -> bool:
        return True

    def get_metadata(self) -> Dict[str, str]:
        return {
            "provider": "openai",
            "model": self.model,
            "base_url": self.base_url,
            "is_remote": "true",
        }

    async def _chat_completion(self, system_prompt: str, user_prompt: str) -> str:
        """Call OpenAI-compatible /chat/completions with JSON object mode."""
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "response_format": {"type": "json_object"},
            "max_tokens": settings.ai_max_output_tokens,
            "temperature": 0.2,
        }

        # Normalize endpoint
        url = self.base_url.rstrip("/")
        if not url.endswith("/chat/completions"):
            url = f"{url}/chat/completions"

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.post(url, headers=headers, json=payload)
        except httpx.TimeoutException as exc:
            raise AITimeoutError(f"OpenAI request timed out after {self.timeout}s") from exc
        except httpx.ConnectError as exc:
            # Safe sanitized exception (never exposes credentials)
            raise AIProviderError(f"Connection to remote AI provider failed: {exc}") from exc
        except Exception as exc:
            raise AIProviderError(f"OpenAI provider request error: {exc}") from exc

        if resp.status_code == 429:
            raise AIRateLimitError("OpenAI provider rate limit exceeded (HTTP 429). Please retry later.")

        if resp.status_code != 200:
            # Never leak full response which might contain authorization reflection
            raise AIProviderError(f"OpenAI provider returned HTTP status {resp.status_code}.")

        try:
            data = resp.json()
            choices = data.get("choices", [])
            if not choices:
                raise AIValidationError("OpenAI returned response with no choices.")
            content = choices[0].get("message", {}).get("content", "")
            return content
        except Exception as exc:
            raise AIValidationError(f"Invalid JSON envelope from OpenAI: {exc}") from exc

    def _extract_json_block(self, raw_text: str) -> Dict[str, Any]:
        """Strip markdown code fence if present and parse JSON."""
        clean = raw_text.strip()
        if clean.startswith("```"):
            clean = clean.split("\n", 1)[-1]
            if clean.endswith("```"):
                clean = clean.rsplit("```", 1)[0]
            clean = clean.strip()

        try:
            return json.loads(clean)
        except Exception as exc:
            raise AIValidationError(f"Model output is not valid JSON: {exc}") from exc

    async def generate_remediation(self, context: FindingContext) -> AIRemediationResponseSchema:
        system_prompt = build_system_instruction()
        user_prompt = build_remediation_user_prompt(context)

        raw_output = await self._chat_completion(system_prompt, user_prompt)
        parsed_dict = self._extract_json_block(raw_output)

        try:
            return AIRemediationResponseSchema.model_validate(parsed_dict)
        except Exception as exc:
            raise AIValidationError(f"OpenAI response failed schema validation: {exc}") from exc

    async def generate_patch(self, context: FindingContext) -> AIPatchResponseSchema:
        system_prompt = build_system_instruction()
        user_prompt = build_patch_user_prompt(context)

        raw_output = await self._chat_completion(system_prompt, user_prompt)
        parsed_dict = self._extract_json_block(raw_output)

        try:
            return AIPatchResponseSchema.model_validate(parsed_dict)
        except Exception as exc:
            raise AIValidationError(f"OpenAI patch response failed schema validation: {exc}") from exc
