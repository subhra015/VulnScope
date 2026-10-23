"""
Safety and Subprocess Hardening Tests.
Verifies defense against argument injection, workspace path escape,
out-of-tree report placement, and prohibition of project script execution.
"""

from pathlib import Path
import pytest
from app.core.config import settings
from app.scanners.gitleaks import GitleaksScanner
from app.scanners.osv_scanner import OSVScanner
from app.scanners.semgrep import SemgrepScanner
from app.services.scanner_runner import ScannerRunner
from app.services.workspace import WorkspaceSecurityError, workspace_manager


def test_command_uses_shell_false(monkeypatch):
    """Ensure subprocess execution strictly sets shell=False."""
    import subprocess
    captured_kwargs = {}

    orig_popen = subprocess.Popen

    def mock_popen(args, **kwargs):
        captured_kwargs.update(kwargs)
        raise FileNotFoundError("Mock stop")

    monkeypatch.setattr(subprocess, "Popen", mock_popen)
    runner = ScannerRunner()
    runner.run(["echo", "safe; rm -rf /"], timeout_seconds=5)

    assert captured_kwargs.get("shell") is False


def test_environment_sanitized_excludes_secrets(monkeypatch):
    """Ensure application secrets and sensitive env vars are scrubbed before subprocess launch."""
    monkeypatch.setenv("DATABASE_URL", "postgresql://admin:secretpass@localhost/db")
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_super_secret_token_12345")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "AKIASECRET12345")

    runner = ScannerRunner()
    sanitized = runner.get_sanitized_env()

    assert "DATABASE_URL" not in sanitized
    assert "GITHUB_TOKEN" not in sanitized
    assert "AWS_SECRET_ACCESS_KEY" not in sanitized
    # Safe system keys are kept
    assert "PATH" in sanitized


def test_workspace_manager_rejects_arbitrary_path_traversal():
    """Ensure scanner cannot be directed outside the designated workspace base dir."""
    with pytest.raises(WorkspaceSecurityError):
        workspace_manager.get_workspace_path("../../etc/passwd")

    with pytest.raises(WorkspaceSecurityError):
        workspace_manager.get_workspace_path("invalid-uuid-format-here")


def test_temporary_gitleaks_report_placed_outside_target_dir(tmp_path):
    """
    Verify temporary Gitleaks reports are created outside the target repository snapshot
    so the scanner cannot discover its own report as an exposed secret.
    """
    workspace_root = tmp_path / "workspace"
    workspace_root.mkdir()
    source_dir = workspace_root / "source"
    source_dir.mkdir()

    created_reports = []

    class ReportPathSpy(ScannerRunner):
        def run(self, args, timeout_seconds, cwd=None, extra_env=None):
            for arg in args:
                if arg.startswith("--report-path="):
                    p = Path(arg.split("=", 1)[1])
                    created_reports.append(p)
                    p.write_text("[]", encoding="utf-8")
            return type("Result", (), {
                "returncode": 0, "stdout": "", "stderr": "", "duration_seconds": 0.05,
                "timed_out": False, "error": None
            })()

    scanner = GitleaksScanner(runner=ReportPathSpy(), binary_path="gitleaks")
    scanner.scan(target_dir=source_dir, scan_id="test-scan", workspace_root=workspace_root)

    assert len(created_reports) == 1
    report_path = created_reports[0]
    # Report must NOT be inside the source directory
    assert not report_path.is_relative_to(source_dir)
    # Report was cleaned up
    assert not report_path.exists()


def test_osv_scanner_disables_call_analysis_no_build_scripts(tmp_path):
    """
    Ensure OSV-scanner command args NEVER include --call-analysis,
    which would execute project build scripts.
    """
    captured_args = []

    class ArgSpy(ScannerRunner):
        def run(self, args, timeout_seconds, cwd=None, extra_env=None):
            captured_args.extend(args)
            return type("Result", (), {
                "returncode": 0, "stdout": "{\"results\":[]}", "stderr": "", "duration_seconds": 0.05,
                "timed_out": False, "error": None
            })()

    scanner = OSVScanner(runner=ArgSpy(), binary_path="osv-scanner")
    scanner.scan(target_dir=tmp_path, scan_id="test-scan")

    assert not any("--call-analysis" in a for a in captured_args)
