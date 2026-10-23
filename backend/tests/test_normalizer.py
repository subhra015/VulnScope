"""
Unit tests for FindingNormalizer:
Validates unified finding schema mapping, path sanitization,
secret redaction, OSV fixed version extraction, and intra-scan deduplication.
"""

from pathlib import Path
import pytest

from app.services.finding_normalizer import FindingNormalizer, NormalizedFindingData


def test_normalize_relative_path_posix_and_windows():
    # Windows drive letter
    assert FindingNormalizer.normalize_relative_path("C:\\Users\\dev\\project\\src\\main.py") == "Users/dev/project/src/main.py"

    # With target dir prefix stripping
    target = Path("D:/app/workspaces/uuid/source")
    raw = "D:\\app\\workspaces\\uuid\\source\\backend\\app.py"
    assert FindingNormalizer.normalize_relative_path(raw, target) == "backend/app.py"

    # Directory traversal defense
    assert FindingNormalizer.normalize_relative_path("../../etc/passwd") == "etc/passwd"
    assert FindingNormalizer.normalize_relative_path("./local/test.py") == "local/test.py"


def test_normalize_semgrep_finding():
    raw = {
        "check_id": "python.security.sql-injection",
        "path": "app/db.py",
        "start": {"line": 25, "col": 4},
        "end": {"line": 25, "col": 30},
        "extra": {
            "message": "User input passed to raw SQL query.",
            "severity": "ERROR",
            "metadata": {
                "cwe": ["CWE-89"],
                "owasp": ["A03:2021"],
                "confidence": "HIGH",
                "references": ["https://owasp.org/sql-injection"],
            },
        },
    }

    norm = FindingNormalizer.normalize_semgrep_finding(raw, "scan-1")
    assert norm.category == "code"
    assert norm.scanner_name == "semgrep"
    assert norm.severity == "high"
    assert norm.confidence == "high"
    assert norm.file_path == "app/db.py"
    assert norm.start_line == 25
    assert norm.rule_id == "python.security.sql-injection"
    assert "CWE-89" in norm.remediation_guidance
    assert norm.advisory_url == "https://owasp.org/sql-injection"
    assert norm.finding_fingerprint is not None


def test_normalize_gitleaks_finding_redaction():
    raw = {
        "RuleID": "slack-webhook",
        "Description": "Slack Webhook URL",
        "File": "config/alerts.json",
        "StartLine": 5,
        "EndLine": 5,
    }

    norm = FindingNormalizer.normalize_gitleaks_finding(raw, "scan-1")
    assert norm.category == "secret"
    assert norm.scanner_name == "gitleaks"
    assert norm.severity == "critical"
    # Verify description is generic
    assert norm.description == "Potential exposed credential detected in source code."
    assert norm.redacted_evidence == "[REDACTED SECRET EVIDENCE]"
    assert norm.file_path == "config/alerts.json"
    assert norm.start_line == 5


def test_normalize_osv_finding_with_fixed_version():
    raw = {
        "package_name": "urllib3",
        "package_version": "1.26.4",
        "ecosystem": "PyPI",
        "source_path": "requirements.txt",
        "vuln": {
            "id": "GHSA-q2x7-8rv6-6q7h",
            "summary": "urllib3 Information Disclosure",
            "details": "CRLF injection and proxy authorization header leak.",
            "aliases": ["CVE-2021-33503"],
            "affected": [
                {
                    "ranges": [
                        {
                            "type": "ECOSYSTEM",
                            "events": [
                                {"introduced": "0"},
                                {"fixed": "1.26.5"},
                            ],
                        }
                    ]
                }
            ],
            "severity": [
                {
                    "type": "CVSS_V3",
                    "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N (7.5)",
                }
            ],
        },
    }

    norm = FindingNormalizer.normalize_osv_finding(raw, "scan-1")
    assert norm.category == "dependency"
    assert norm.scanner_name == "osv-scanner"
    assert norm.rule_id == "CVE-2021-33503"  # Preferred alias
    assert norm.package_name == "urllib3"
    assert norm.package_version == "1.26.4"
    assert norm.fixed_version == "1.26.5"
    assert norm.severity == "high"
    assert "1.26.5" in norm.remediation_guidance


def test_intra_scan_deduplication():
    # Duplicate findings with exact same fingerprint
    semgrep_raw = {
        "check_id": "test.rule",
        "path": "app.py",
        "start": {"line": 10},
        "extra": {"message": "duplicate message", "severity": "WARNING"},
    }
    scanner_results = [
        ("semgrep", [semgrep_raw, semgrep_raw, semgrep_raw])
    ]

    results = FindingNormalizer.normalize_all(scanner_results, "scan-1")
    # All 3 duplicates should be collapsed to 1
    assert len(results) == 1
