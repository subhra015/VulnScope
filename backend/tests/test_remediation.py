"""
Unit tests for VulnScope Remediation Guidance Service (Phase 4).
Verifies category-specific advice, security constraints (no leaked secrets),
fixed-version accuracy, and trusted references.
"""

import pytest
from app.services.remediation_service import RemediationService


class TestRemediationService:
    """Test suite for structured remediation recommendations."""

    def test_secret_remediation_rotation_and_safety(self):
        """Verify secret remediation mandates rotation and never leaks raw secrets."""
        raw_secret_value = "ghp_FakeLiveSecretToken1234567890abcdef"
        guidance = RemediationService.generate_remediation(
            category="secret",
            rule_id="github-pat",
            scanner_name="gitleaks",
            file_path="src/config.py",
        )

        assert guidance.category == "secret"
        # Never expose or reference secret value
        assert raw_secret_value not in str(guidance.to_dict())

        # Must mandate immediate revocation/rotation
        assert any("revoke" in step.lower() or "rotate" in step.lower() for step in guidance.steps)
        # Must recommend secrets manager or environment variables
        assert any("environment variable" in step.lower() or "secrets manager" in step.lower() for step in guidance.steps)

        # Must include critical caveats
        caveat_text = " ".join(guidance.caveats).lower()
        assert "not invalidate" in caveat_text or "does not invalidate" in caveat_text
        assert "git history" in caveat_text

    def test_dependency_remediation_with_fixed_version(self):
        """Verify dependency remediation suggests fixed version only when explicitly provided."""
        guidance = RemediationService.generate_remediation(
            category="dependency",
            rule_id="CVE-2023-32681",
            package_name="requests",
            package_version="2.25.1",
            ecosystem="PyPI",
            fixed_version="2.31.0",
            advisory_url="https://github.com/advisories/GHSA-j8r2-6x86-q33q",
        )

        assert guidance.category == "dependency"
        assert guidance.fixed_version == "2.31.0"
        assert "2.31.0" in guidance.summary
        assert any("upgrade requests from 2.25.1 to patched version 2.31.0" in step.lower() for step in guidance.steps)
        # Compatibility caveat
        assert any("breaking changes" in c.lower() for c in guidance.caveats)
        # Trusted advisory reference included
        assert "https://github.com/advisories/GHSA-j8r2-6x86-q33q" in guidance.references

    def test_dependency_remediation_without_fixed_version(self):
        """Verify dependency remediation indicates when no fix is recorded."""
        guidance = RemediationService.generate_remediation(
            category="dependency",
            rule_id="CVE-2024-99999",
            package_name="vulnerable-lib",
            package_version="0.1.0",
            ecosystem="npm",
            fixed_version=None,
        )

        assert guidance.category == "dependency"
        assert guidance.fixed_version is None
        assert "no verified upstream fixed version" in guidance.summary.lower()
        assert any("compensating controls" in s.lower() for s in guidance.steps)

    def test_code_remediation_sql_injection(self):
        """Verify code remediation provides parameterized query advice for SQL injection."""
        guidance = RemediationService.generate_remediation(
            category="code",
            rule_id="python.sqlalchemy.security.raw-sql-concat",
            title="SQL Injection via string formatting",
            description="Detected query concatenated with user input",
        )

        assert guidance.category == "code"
        assert "parameterized" in guidance.summary.lower() or "orm" in guidance.summary.lower()
        assert any("parameterized" in step.lower() for step in guidance.steps)
        assert guidance.unsafe_pattern is not None
        assert guidance.safer_alternative is not None
        assert any("owasp.org" in ref.lower() for ref in guidance.references)

    def test_code_remediation_command_injection(self):
        """Verify command injection remediation recommends shell=False and list arguments."""
        guidance = RemediationService.generate_remediation(
            category="code",
            rule_id="python.lang.security.dangerous-subprocess-use",
            title="Dangerous subprocess call",
            description="subprocess.Popen with shell=True",
        )

        assert any("shell=false" in s.lower() for s in guidance.steps)
        assert "shell=false" in (guidance.safer_alternative or "").lower()

    def test_trusted_reference_domain_validation(self):
        """Verify only trustworthy security domains are included in references."""
        untrusted = "http://malicious-site.example.com/exploit"
        res_untrusted = RemediationService.generate_remediation(
            category="code",
            rule_id="test.rule",
            advisory_url=untrusted,
        )
        assert untrusted not in res_untrusted.references

        trusted = "https://owasp.org/www-community/attacks/xss/"
        res_trusted = RemediationService.generate_remediation(
            category="code",
            rule_id="test.rule",
            advisory_url=trusted,
        )
        assert trusted in res_trusted.references
