"""
Local Ollama AI provider implementation.
Interacts with local Ollama instance via HTTP (/api/chat) using strictly bounded local endpoints.
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
    AITimeoutError,
    AIValidationError,
    FindingContext,
)
from app.services.ai.schemas import AIRemediationResponseSchema, AIPatchResponseSchema

logger = logging.getLogger(__name__)


class OllamaProvider(AIProvider):
    """
    Connects to a locally running Ollama instance.
    Guarantees no outbound external internet requests; restricted strictly to loopback interfaces.
    """

    def __init__(self):
        try:
            self.base_url = settings.get_validated_ai_endpoint()
        except Exception as exc:
            raise AIConfigurationError(f"Ollama configuration error: {exc}") from exc

        self.model = settings.ai_model if settings.ai_model != "default" else "llama3"
        self.timeout = settings.ai_timeout_seconds

    def is_available(self) -> bool:
        return True

    def get_metadata(self) -> Dict[str, str]:
        return {
            "provider": "ollama",
            "model": self.model,
            "base_url": self.base_url,
            "is_remote": "false",
        }

    async def _chat_completion(self, system_prompt: str, user_prompt: str) -> str:
        """Call Ollama /api/chat with JSON format enforcement."""
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "stream": False,
            "format": "json",
            "options": {
                "num_predict": settings.ai_max_output_tokens,
                "temperature": 0.2,
            },
        }

        url = f"{self.base_url}/api/chat"
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.post(url, json=payload)
        except httpx.TimeoutException as exc:
            raise AITimeoutError(f"Ollama request timed out after {self.timeout}s") from exc
        except httpx.ConnectError as exc:
            raise AIProviderError(f"Cannot connect to Ollama at {self.base_url}: {exc}") from exc
        except Exception as exc:
            raise AIProviderError(f"Ollama request failed: {exc}") from exc

        if resp.status_code != 200:
            raise AIProviderError(f"Ollama returned HTTP {resp.status_code}: {resp.text[:200]}")

        try:
            data = resp.json()
            message = data.get("message", {}).get("content", "")
            return message
        except Exception as exc:
            raise AIValidationError(f"Invalid JSON envelope from Ollama: {exc}") from exc

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
            raise AIValidationError(f"Ollama response failed schema validation: {exc}") from exc

    async def generate_patch(self, context: FindingContext) -> AIPatchResponseSchema:
        system_prompt = build_system_instruction()
        user_prompt = build_patch_user_prompt(context)

        raw_output = await self._chat_completion(system_prompt, user_prompt)
        parsed_dict = self._extract_json_block(raw_output)

        try:
            return AIPatchResponseSchema.model_validate(parsed_dict)
        except Exception as exc:
            raise AIValidationError(f"Ollama patch response failed schema validation: {exc}") from exc
