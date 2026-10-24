"""
Automated tests for AI Provider Abstraction and Error Handling.
Tests:
- Disabled provider behavior
- Valid response parsing into structured schema
- Malformed responses rejected
- Provider timeouts and honest error handling
- API keys never leaked in logs or errors
- SSRF prevention (remote requires HTTPS, rejects cloud metadata, local requires loopback)
- Deterministic Phase 4 fallback when AI is unavailable
"""

import pytest
from app.core.config import Settings
from app.services.ai.disabled_provider import DisabledAIProvider
from app.services.ai.factory import get_ai_provider, set_ai_provider_override
from app.services.ai.ollama_provider import OllamaProvider
from app.services.ai.openai_provider import OpenAIProvider
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


class MockAIProvider(AIProvider):
    """Mock provider returning controlled responses for testing."""

    def __init__(self, response_data: dict, patch_data: dict = None, should_fail=False, fail_type=None):
        self.response_data = response_data
        self.patch_data = patch_data or {
            "target_file_path": "src/app.py",
            "change_summary": "Sanitize user input",
            "diff_content": "--- a/src/app.py\n+++ b/src/app.py\n@@ -1,2 +1,2 @@\n- raw_input\n+ safe_input\n",
        }
        self.should_fail = should_fail
        self.fail_type = fail_type

    def is_available(self) -> bool:
        return True

    def get_metadata(self) -> dict:
        return {"provider": "mock", "model": "mock-model", "is_remote": "false"}

    async def generate_remediation(self, context: FindingContext) -> AIRemediationResponseSchema:
        if self.should_fail:
            if self.fail_type == "timeout":
                raise AITimeoutError("Mock timeout exceeded")
            elif self.fail_type == "rate_limit":
                raise AIRateLimitError("Mock rate limit exceeded")
            else:
                raise AIProviderError("Mock provider connection failed")
        return AIRemediationResponseSchema.model_validate(self.response_data)

    async def generate_patch(self, context: FindingContext) -> AIPatchResponseSchema:
        if self.should_fail:
            raise AIProviderError("Mock patch generation failed")
        return AIPatchResponseSchema.model_validate(self.patch_data)


def test_disabled_provider_raises_configuration_error():
    """Disabled provider cleanly reports disabled status and raises on invocation."""
    provider = DisabledAIProvider()
    assert not provider.is_available()
    meta = provider.get_metadata()
    assert meta["provider"] == "disabled"

    ctx = FindingContext(
        finding_id="f-1",
        scan_id="s-1",
        category="code",
        rule_id="py.sqli",
        title="SQL Injection",
        description="Unsafe query",
        scanner_name="semgrep",
        original_severity="high",
        risk_score=75,
        risk_priority="high",
        risk_reason="Unsanitized user input in query",
    )

    with pytest.raises(AIConfigurationError, match="disabled"):
        import asyncio
        asyncio.run(provider.generate_remediation(ctx))


def test_valid_response_schema_validation():
    """Valid structured dictionary parses cleanly into AIRemediationResponseSchema."""
    valid_data = {
        "explanation": "SQL query uses direct string concatenation allowing statement manipulation.",
        "likely_root_cause": "UserInput is interpolated directly into cursor.execute() without parameterized query.",
        "potential_impact": "Unauthorized database reading or data modification.",
        "remediation_steps": [
            "Replace string formatting with parameterized query syntax: cursor.execute('SELECT * FROM users WHERE id = %s', (uid,))",
            "Audit all database access layers for similar unparameterized queries.",
        ],
        "secure_coding_pattern": "cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))",
        "testing_recommendations": [
            "Write integration test with quote characters (' OR '1'='1) to confirm injection is blocked.",
        ],
        "caveats_and_assumptions": [
            "Assumes backend uses standard DB-API compliant database driver.",
        ],
        "patch_appropriate": True,
    }

    schema = AIRemediationResponseSchema.model_validate(valid_data)
    assert schema.explanation.startswith("SQL query")
    assert len(schema.remediation_steps) == 2
    assert schema.patch_appropriate is True


def test_malformed_response_schema_rejected():
    """Missing mandatory fields fail Pydantic validation."""
    malformed_data = {
        "explanation": "Incomplete data missing steps and root cause",
    }
    with pytest.raises(Exception):
        AIRemediationResponseSchema.model_validate(malformed_data)


def test_ssrf_prevention_ollama_restricts_to_loopback():
    """Ollama provider rejects external and cloud metadata URLs."""
    # Invalid external URL for local provider
    settings_evil = Settings(ai_provider="ollama", ai_base_url="http://169.254.169.254/latest/meta-data")
    with pytest.raises(ValueError, match="restricted to loopback"):
        settings_evil.get_validated_ai_endpoint()

    settings_external = Settings(ai_provider="ollama", ai_base_url="http://evil-proxy.com")
    with pytest.raises(ValueError, match="restricted to loopback"):
        settings_external.get_validated_ai_endpoint()

    # Valid loopback
    settings_valid = Settings(ai_provider="ollama", ai_base_url="http://localhost:11434")
    assert settings_valid.get_validated_ai_endpoint() == "http://localhost:11434"

    settings_valid_ip = Settings(ai_provider="ollama", ai_base_url="http://127.0.0.1:11434")
    assert settings_valid_ip.get_validated_ai_endpoint() == "http://127.0.0.1:11434"


def test_ssrf_prevention_openai_enforces_https_and_blocks_metadata():
    """Remote OpenAI provider requires HTTPS and blocks link-local metadata."""
    # Insecure HTTP
    settings_http = Settings(ai_provider="openai", ai_base_url="http://api.openai.com/v1", ai_api_key="sk-test")
    with pytest.raises(ValueError, match="must use HTTPS"):
        settings_http.get_validated_ai_endpoint()

    # Metadata endpoint
    settings_meta = Settings(ai_provider="openai", ai_base_url="https://169.254.169.254/v1", ai_api_key="sk-test")
    with pytest.raises(ValueError, match="cloud instance metadata"):
        settings_meta.get_validated_ai_endpoint()

    # Valid HTTPS
    settings_valid = Settings(ai_provider="openai", ai_base_url="https://api.openai.com/v1", ai_api_key="sk-test")
    assert settings_valid.get_validated_ai_endpoint() == "https://api.openai.com/v1"


def test_api_key_not_leaked_in_openai_provider_repr_or_metadata():
    """OpenAIProvider never exposes API key in metadata or strings."""
    settings_ai = Settings(
        ai_provider="openai",
        ai_base_url="https://api.openai.com/v1",
        ai_api_key="SECRET_API_KEY_12345",
        ai_model="gpt-4o-mini",
    )
    # Monkeypatch settings
    import app.core.config

    settings = app.core.config.settings

    old_prov = settings.ai_provider
    old_key = settings.ai_api_key
    old_base_url = settings.ai_base_url
    old_model = settings.ai_model

    settings.ai_provider = "openai"
    settings.ai_api_key = "SECRET_API_KEY_12345"
    settings.ai_base_url = "https://api.openai.com/v1"
    settings.ai_model = "gpt-4o-mini"

    try:
        prov = OpenAIProvider()
        meta = prov.get_metadata()

        assert "SECRET_API_KEY_12345" not in str(meta)
        assert "api_key" not in meta
        assert "SECRET_API_KEY_12345" not in repr(prov)
    finally:
        settings.ai_provider = old_prov
        settings.ai_api_key = old_key
        settings.ai_base_url = old_base_url
        settings.ai_model = old_model