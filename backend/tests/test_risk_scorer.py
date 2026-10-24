"""
Unit tests for VulnScope Risk Prioritization Engine (Phase 4).
Tests deterministic scoring, bounds, factor explanations, conservative fallbacks,
and evidence-grounded scoring rules.
"""

import pytest
from app.services.risk_scorer import RiskScorer, RiskExplanation


class TestRiskScorer:
    """Test suite for deterministic finding-risk prioritization."""

    def test_score_bounds_and_determinism(self):
        """Verify scores are strictly bounded in [0, 100] and deterministic."""
        score1 = RiskScorer.calculate_score(
            severity="critical",
            confidence="high",
            category="secret",
            rule_id="gitleaks.jwt-token",
            file_path="config/auth.py",
            start_line=15,
        )
        score2 = RiskScorer.calculate_score(
            severity="critical",
            confidence="high",
            category="secret",
            rule_id="gitleaks.jwt-token",
            file_path="config/auth.py",
            start_line=15,
        )

        assert 0 <= score1.score <= 100
        assert score1.score == score2.score
        assert score1.priority == score2.priority
        assert score1.priority == "critical"
        assert score1.reason == score2.reason
        assert len(score1.factors) == 4
        assert [f.contribution for f in score1.factors] == [f.contribution for f in score2.factors]

    def test_severity_to_priority_tiers(self):
        """Verify priority classifications across different severity levels."""
        crit = RiskScorer.calculate_score(severity="critical", confidence="high", category="secret")
        assert crit.priority == "critical"
        assert crit.score >= 85

        high = RiskScorer.calculate_score(
            severity="high",
            confidence="high",
            category="code",
            rule_id="python.lang.security.injection.sql-injection",
            file_path="app/db.py",
            start_line=45,
        )
        assert high.priority in ("critical", "high")
        assert high.score >= 70

        med = RiskScorer.calculate_score(
            severity="medium",
            confidence="medium",
            category="code",
            rule_id="python.security.audit.permissive-cors",
        )
        assert med.priority == "medium"
        assert 40 <= med.score < 70

        low = RiskScorer.calculate_score(
            severity="low",
            confidence="low",
            category="code",
            rule_id="python.style.comment-notice",
        )
        assert low.priority == "low"
        assert low.score < 40

    def test_conservative_fallbacks_for_missing_evidence(self):
        """Verify explicit conservative fallback rules for unknown severity and missing confidence."""
        res = RiskScorer.calculate_score(
            severity=None,
            confidence=None,
            category=None,
            rule_id="unknown.rule",
        )

        # Missing data is NOT treated as zero risk! Default baseline is applied.
        assert 40 <= res.score <= 70
        assert res.priority == "medium"

        # Missing evidence is transparently recorded
        assert any("severity" in item.lower() for item in res.missing_evidence)
        assert any("confidence" in item.lower() for item in res.missing_evidence)
        assert any("category" in item.lower() for item in res.missing_evidence)
        assert any("context" in item.lower() or "exposure" in item.lower() for item in res.missing_evidence)

    def test_cvss_authoritative_for_dependencies(self):
        """Verify CVSS is used as authoritative base metric for dependency vulnerabilities without double counting."""
        high_cvss = RiskScorer.calculate_score(
            severity="low",  # Scanner may report low, but CVSS 9.8 is authoritative
            confidence="high",
            category="dependency",
            rule_id="CVE-2023-9999",
            cvss_score=9.8,
            package_name="requests",
            package_version="2.25.0",
        )
        assert high_cvss.score >= 85
        assert high_cvss.priority == "critical"
        assert "CVSS v3 base score (9.8/10)" in high_cvss.factors[0].description

        low_cvss = RiskScorer.calculate_score(
            severity="critical",  # Scanner severity should not inflate score if CVSS is low
            confidence="high",
            category="dependency",
            rule_id="CVE-2023-1111",
            cvss_score=2.0,
            package_name="foo",
            package_version="1.0.0",
        )
        assert low_cvss.score < 60
        assert low_cvss.priority in ("medium", "low")

    def test_distinguish_scanner_severity_from_risk_priority(self):
        """Ensure scanner severity remains separate from VulnScope's risk priority."""
        finding_data = {
            "severity": "low",
            "confidence": "high",
            "category": "secret",  # Secret leaks get elevated priority due to blast radius
            "rule_id": "slack-webhook-url",
            "file_path": "deploy.py",
            "start_line": 5,
        }
        res = RiskScorer.calculate_score(**finding_data)
        # Scanner severity is "low", but risk priority is elevated to Medium or High
        assert res.evidence["scanner_severity"] == "low"
        assert res.score > 40
        assert res.priority in ("medium", "high")

    def test_unpatched_dependency_residual_risk(self):
        """Verify unpatched dependencies receive higher exploitability weight than patched ones."""
        unpatched = RiskScorer.calculate_score(
            severity="high",
            confidence="high",
            category="dependency",
            rule_id="CVE-2024-0001",
            fixed_version=None,
        )
        patched = RiskScorer.calculate_score(
            severity="high",
            confidence="high",
            category="dependency",
            rule_id="CVE-2024-0001",
            fixed_version="1.2.3",
        )
        assert unpatched.score >= patched.score
        assert "no verified upstream fixed version" in unpatched.factors[2].description.lower()
