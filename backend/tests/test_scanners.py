"""
Unit tests for external security scanner adapters:
SemgrepScanner, GitleaksScanner, OSVScanner.
Tests verify parsing, error recovery, timeouts, output limits, and secret redaction.
"""

import json
from pathlib import Path
from unittest.mock import MagicMock
import pytest

from app.scanners.base import ScannerResult
from app.scanners.semgrep import SemgrepScanner
from app.scanners.gitleaks import GitleaksScanner
from app.scanners.osv_scanner import OSVScanner
from app.services.scanner_runner import ProcessExecutionResult, ScannerRunner

FIXTURES_DIR = Path(__file__).parent / "fixtures"


class FakeRunner(ScannerRunner):
    """Injected fake runner for deterministic test control."""

    def __init__(self, returncode: int = 0, stdout: str = "", stderr: str = "", timed_out: bool = False, error: str = None):
        super().__init__()
        self._returncode = returncode
        self._stdout = stdout
        self._stderr = stderr
        self._timed_out = timed_out
        self._error = error

    def run(self, args, timeout_seconds, cwd=None, extra_env=None):
        return ProcessExecutionResult(
            returncode=self._returncode,
            stdout=self._stdout,
            stderr=self._stderr,
            duration_seconds=0.1,
            timed_out=self._timed_out,
            error=self._error,
        )


# =========================================================================
# Semgrep Scanner Adapter Tests
# =========================================================================

def test_semgrep_parse_valid_fixture(tmp_path):
    fixture_content = (FIXTURES_DIR / "semgrep_output.json").read_text(encoding="utf-8")
    runner = FakeRunner(returncode=0, stdout=fixture_content)
    scanner = SemgrepScanner(runner=runner, binary_path="semgrep")

    result = scanner.scan(tmp_path, "scan-123")
    assert result.status == "completed"
    assert len(result.raw_findings) == 2
    assert result.raw_findings[0]["check_id"] == "python.lang.security.audit.eval-detected.eval-detected"
    assert result.raw_findings[1]["check_id"] == "python.lang.security.insecure-hash-md5.insecure-hash-md5"


def test_semgrep_exit_code_1_with_findings(tmp_path):
    fixture_content = (FIXTURES_DIR / "semgrep_output.json").read_text(encoding="utf-8")
    # Semgrep exits with 1 when blocking findings are reported
    runner = FakeRunner(returncode=1, stdout=fixture_content)
    scanner = SemgrepScanner(runner=runner, binary_path="semgrep")

    result = scanner.scan(tmp_path, "scan-123")
    assert result.status == "completed"
    assert len(result.raw_findings) == 2


def test_semgrep_empty_results(tmp_path):
    runner = FakeRunner(returncode=0, stdout=json.dumps({"results": [], "errors": []}))
    scanner = SemgrepScanner(runner=runner, binary_path="semgrep")

    result = scanner.scan(tmp_path, "scan-123")
    assert result.status == "completed"
    assert result.raw_findings == []


def test_semgrep_malformed_json(tmp_path):
    runner = FakeRunner(returncode=0, stdout="FATAL: Broken {json not closed")
    scanner = SemgrepScanner(runner=runner, binary_path="semgrep")

    result = scanner.scan(tmp_path, "scan-123")
    assert result.status == "failed"
    assert "JSON" in result.error_message


def test_semgrep_timeout(tmp_path):
    runner = FakeRunner(returncode=-1, timed_out=True)
    scanner = SemgrepScanner(runner=runner, binary_path="semgrep")

    result = scanner.scan(tmp_path, "scan-123")
    assert result.status == "timed_out"
    assert "timed out" in result.error_message.lower()


def test_semgrep_unavailable(tmp_path, monkeypatch):
    scanner = SemgrepScanner(binary_path=None)
    monkeypatch.setattr(scanner, "get_binary_path", lambda: None)

    result = scanner.scan(tmp_path, "scan-123")
    assert result.status == "unavailable"
    assert "not installed" in result.error_message.lower()


# =========================================================================
# Gitleaks Scanner Adapter Tests
# =========================================================================

def test_gitleaks_parse_valid_fixture(tmp_path):
    fixture_content = (FIXTURES_DIR / "gitleaks_output.json").read_text(encoding="utf-8")

    class GitleaksFakeRunner(ScannerRunner):
        def run(self, args, timeout_seconds, cwd=None, extra_env=None):
            # Extract report path from args and write the fixture content
            for arg in args:
                if arg.startswith("--report-path="):
                    report_path = Path(arg.split("=", 1)[1])
                    report_path.write_text(fixture_content, encoding="utf-8")
            return ProcessExecutionResult(returncode=1, stdout="", stderr="", duration_seconds=0.1)

    runner = GitleaksFakeRunner()
    scanner = GitleaksScanner(runner=runner, binary_path="gitleaks")

    result = scanner.scan(tmp_path, "scan-123", workspace_root=tmp_path)
    assert result.status == "completed"
    assert len(result.raw_findings) == 2

    # CRITICAL: Verify raw Secret and Match are NEVER included
    for finding in result.raw_findings:
        assert "Secret" not in finding
        assert "Match" not in finding
        assert "Line" not in finding
        assert finding["Description"] == "Potential exposed credential detected"
        assert "ghp_" not in str(finding)
        assert "synthetic_fake_key" not in str(finding)


def test_gitleaks_clean_run_zero_findings(tmp_path):
    class CleanGitleaksFakeRunner(ScannerRunner):
        def run(self, args, timeout_seconds, cwd=None, extra_env=None):
            for arg in args:
                if arg.startswith("--report-path="):
                    report_path = Path(arg.split("=", 1)[1])
                    report_path.write_text("[]", encoding="utf-8")
            return ProcessExecutionResult(returncode=0, stdout="", stderr="", duration_seconds=0.1)

    runner = CleanGitleaksFakeRunner()
    scanner = GitleaksScanner(runner=runner, binary_path="gitleaks")

    result = scanner.scan(tmp_path, "scan-123", workspace_root=tmp_path)
    assert result.status == "completed"
    assert result.raw_findings == []


def test_gitleaks_temporary_report_cleanup(tmp_path):
    written_reports = []

    class ReportTrackingRunner(ScannerRunner):
        def run(self, args, timeout_seconds, cwd=None, extra_env=None):
            for arg in args:
                if arg.startswith("--report-path="):
                    p = Path(arg.split("=", 1)[1])
                    p.write_text("[]", encoding="utf-8")
                    written_reports.append(p)
            return ProcessExecutionResult(returncode=0, stdout="", stderr="", duration_seconds=0.1)

    runner = ReportTrackingRunner()
    scanner = GitleaksScanner(runner=runner, binary_path="gitleaks")

    scanner.scan(tmp_path, "scan-123", workspace_root=tmp_path)
    assert len(written_reports) == 1
    # Report must be deleted in finally block
    assert not written_reports[0].exists()


def test_gitleaks_fatal_exit_code(tmp_path):
    runner = FakeRunner(returncode=2, stderr="fatal error: invalid flag")
    scanner = GitleaksScanner(runner=runner, binary_path="gitleaks")

    result = scanner.scan(tmp_path, "scan-123", workspace_root=tmp_path)
    assert result.status == "failed"
    assert "fatal error" in result.error_message.lower() or "exit code 2" in result.error_message.lower()


# =========================================================================
# OSV Scanner Adapter Tests
# =========================================================================

def test_osv_parse_valid_fixture(tmp_path):
    fixture_content = (FIXTURES_DIR / "osv_output.json").read_text(encoding="utf-8")
    runner = FakeRunner(returncode=1, stdout=fixture_content)
    scanner = OSVScanner(runner=runner, binary_path="osv-scanner")

    result = scanner.scan(tmp_path, "scan-123")
    assert result.status == "completed"
    assert len(result.raw_findings) == 1
    finding = result.raw_findings[0]
    assert finding["package_name"] == "requests"
    assert finding["package_version"] == "2.19.0"
    assert finding["ecosystem"] == "PyPI"
    assert finding["vuln"]["id"] == "PYSEC-2018-28"


def test_osv_clean_run_zero_vulnerabilities(tmp_path):
    runner = FakeRunner(returncode=0, stdout=json.dumps({"results": []}))
    scanner = OSVScanner(runner=runner, binary_path="osv-scanner")

    result = scanner.scan(tmp_path, "scan-123")
    assert result.status == "completed"
    assert result.raw_findings == []


def test_osv_malformed_json(tmp_path):
    runner = FakeRunner(returncode=1, stdout="{ broken json")
    scanner = OSVScanner(runner=runner, binary_path="osv-scanner")

    result = scanner.scan(tmp_path, "scan-123")
    assert result.status == "failed"
    assert "JSON" in result.error_message


def test_osv_timeout(tmp_path):
    runner = FakeRunner(returncode=-1, timed_out=True)
    scanner = OSVScanner(runner=runner, binary_path="osv-scanner")

    result = scanner.scan(tmp_path, "scan-123")
    assert result.status == "timed_out"
    assert "timed out" in result.error_message.lower()
