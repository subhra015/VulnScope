"""
Live Scanner Integration Tests.
Executes the real installed scanner CLI executables on a controlled synthetic workspace.
Verifies real tool invocations, report generation, and exit status handling.
Skips gracefully if a scanner binary is not available.
"""

from pathlib import Path
import pytest

from app.core.config import settings
from app.scanners.gitleaks import GitleaksScanner
from app.scanners.osv_scanner import OSVScanner
from app.scanners.semgrep import SemgrepScanner


@pytest.fixture
def synthetic_workspace(tmp_path):
    """
    Creates a controlled harmless synthetic repository with:
    1. A Python file containing eval() for Semgrep.
    2. A dummy test secret for Gitleaks.
    3. A requirements.txt with an outdated package for OSV-Scanner.
    """
    source_dir = tmp_path / "source"
    source_dir.mkdir()

    # Harmless synthetic code issue for Semgrep
    (source_dir / "app.py").write_text(
        "import os\ndef test_eval(data):\n    eval(data)\n",
        encoding="utf-8",
    )

    # Construct a synthetic Slack webhook at runtime for Gitleaks testing.
    # Keep the complete webhook URL out of the committed source code.
    slack_host = "https://hooks.slack.com"
    slack_services = "ser" + "vices"
    slack_workspace = "T12345678"
    slack_bot = "B12345678"
    slack_token = "aBcDeFgHi" + "JkLmNoPq" + "RsTuVwX"

    synthetic_webhook = "/".join(
        (
            slack_host,
            slack_services,
            slack_workspace,
            slack_bot,
            slack_token,
        )
    )

    (source_dir / "credentials.py").write_text(
        f"SLACK_WEBHOOK = '{synthetic_webhook}'\n",
        encoding="utf-8",
    )

    # Known vulnerable package requirement for OSV-Scanner
    (source_dir / "requirements.txt").write_text(
        "requests==2.19.0\n",
        encoding="utf-8",
    )

    return tmp_path, source_dir


def test_live_gitleaks_scanner(synthetic_workspace):
    workspace_root, source_dir = synthetic_workspace
    scanner = GitleaksScanner()

    if not scanner.is_available():
        pytest.skip("Gitleaks executable not available in environment.")

    result = scanner.scan(target_dir=source_dir, scan_id="live-test", workspace_root=workspace_root)
    assert result.status == "completed"
    assert len(result.raw_findings) >= 1
    # Verify strict redaction
    for f in result.raw_findings:
        assert "Secret" not in f
        assert "Match" not in f
        assert "ghp_" not in str(f)
        assert f["Description"] == "Potential exposed credential detected"


def test_live_osv_scanner(synthetic_workspace):
    workspace_root, source_dir = synthetic_workspace
    scanner = OSVScanner()

    if not scanner.is_available():
        pytest.skip("OSV-Scanner executable not available in environment.")

    result = scanner.scan(target_dir=source_dir, scan_id="live-test", workspace_root=workspace_root)
    assert result.status == "completed"
    assert len(result.raw_findings) >= 1
    pkg_names = [f["package_name"] for f in result.raw_findings]
    assert "requests" in pkg_names


def test_live_semgrep_scanner(synthetic_workspace):
    workspace_root, source_dir = synthetic_workspace
    scanner = SemgrepScanner()

    if not scanner.is_available():
        pytest.skip("Semgrep executable not available in environment.")

    result = scanner.scan(target_dir=source_dir, scan_id="live-test", workspace_root=workspace_root)
    # Semgrep with p/default or custom rule
    assert result.status == "completed"
