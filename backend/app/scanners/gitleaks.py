"""
Gitleaks Secret Detection Scanner Adapter.
Integrates Gitleaks CLI for identifying exposed credentials, tokens, and cryptographic keys.
Enforces strict secret redaction and safe out-of-tree report cleanup.
"""

from datetime import datetime, timezone
import json
from pathlib import Path
import tempfile
from typing import Any, Dict, List, Optional
import uuid

from app.core.config import settings
from app.scanners.base import BaseScanner, ScannerResult
from app.services.scanner_runner import ScannerRunner, default_scanner_runner


class GitleaksScanner(BaseScanner):
    """
    Adapter for Gitleaks secret scanner.
    """

    def __init__(self, runner: Optional[ScannerRunner] = None, binary_path: Optional[str] = None):
        self.runner = runner or default_scanner_runner
        self._binary_path = binary_path

    @property
    def name(self) -> str:
        return "gitleaks"

    @property
    def category(self) -> str:
        return "secret"

    def get_binary_path(self) -> Optional[str]:
        if self._binary_path:
            return self._binary_path
        return settings.resolve_scanner_binary("gitleaks")

    def is_available(self) -> bool:
        return self.get_binary_path() is not None

    def get_version(self) -> Optional[str]:
        bin_path = self.get_binary_path()
        if not bin_path:
            return None
        res = self.runner.run([bin_path, "version"], timeout_seconds=10.0)
        if res.returncode == 0 and res.stdout.strip():
            return res.stdout.strip().splitlines()[0][:50]
        return None

    def scan(self, target_dir: Path, scan_id: str, workspace_root: Optional[Path] = None) -> ScannerResult:
        started_at = datetime.now(timezone.utc)
        bin_path = self.get_binary_path()

        if not bin_path:
            return ScannerResult(
                scanner_name=self.name,
                status="unavailable",
                scanner_version=None,
                started_at=started_at,
                completed_at=datetime.now(timezone.utc),
                duration_seconds=0.0,
                raw_findings=[],
                error_message="Gitleaks CLI executable is not installed or not found on system PATH.",
            )

        scanner_version = self.get_version()

        # Place temporary report OUTSIDE the scanned target repository
        if workspace_root and workspace_root.is_dir():
            report_file = workspace_root / f"gitleaks_report_{scan_id}_{uuid.uuid4().hex[:8]}.json"
        else:
            report_file = Path(tempfile.gettempdir()) / f"vs_gitleaks_{uuid.uuid4().hex}.json"

        # Build arguments
        cmd = [
            bin_path,
            "dir",
            str(target_dir),
            "--report-format=json",
            f"--report-path={str(report_file)}",
            "--no-banner",
            "--redact=100",
        ]

        raw_findings: List[Dict[str, Any]] = []
        try:
            exec_res = self.runner.run(
                cmd,
                timeout_seconds=settings.gitleaks_timeout_seconds,
                cwd=target_dir,
            )
            completed_at = datetime.now(timezone.utc)

            if exec_res.timed_out:
                return ScannerResult(
                    scanner_name=self.name,
                    status="timed_out",
                    scanner_version=scanner_version,
                    started_at=started_at,
                    completed_at=completed_at,
                    duration_seconds=exec_res.duration_seconds,
                    raw_findings=[],
                    error_message=f"Gitleaks scan timed out after {settings.gitleaks_timeout_seconds} seconds.",
                )

            # Check report file:
            # Gitleaks exits with 0 if no leaks, or 1 if leaks are found.
            # If report file exists, read and sanitize findings.
            if report_file.exists():
                try:
                    content = report_file.read_text(encoding="utf-8", errors="replace").strip()
                    if content:
                        parsed = json.loads(content)
                        if isinstance(parsed, list):
                            # SECURITY: Strictly scrub raw Secret, Match, and Line content
                            for item in parsed:
                                sanitized_item = {
                                    "RuleID": item.get("RuleID", "generic-secret"),
                                    "Description": "Potential exposed credential detected",
                                    "File": item.get("File", ""),
                                    "StartLine": item.get("StartLine"),
                                    "EndLine": item.get("EndLine"),
                                    "StartColumn": item.get("StartColumn"),
                                    "EndColumn": item.get("EndColumn"),
                                    "Fingerprint": item.get("Fingerprint"),
                                    # Explicitly omitted: "Secret", "Match", "Line"
                                }
                                raw_findings.append(sanitized_item)
                except Exception as exc:
                    return ScannerResult(
                        scanner_name=self.name,
                        status="failed",
                        scanner_version=scanner_version,
                        started_at=started_at,
                        completed_at=completed_at,
                        duration_seconds=exec_res.duration_seconds,
                        raw_findings=[],
                        error_message=f"Failed to parse Gitleaks report JSON: {type(exc).__name__}",
                    )

            # Exit code 0 (no leaks) or 1 (leaks found) is success when report was handled
            if exec_res.returncode in (0, 1):
                return ScannerResult(
                    scanner_name=self.name,
                    status="completed",
                    scanner_version=scanner_version,
                    started_at=started_at,
                    completed_at=completed_at,
                    duration_seconds=exec_res.duration_seconds,
                    raw_findings=raw_findings,
                    error_message=None,
                )

            # Otherwise, a genuine failure occurred
            err_msg = exec_res.stderr.strip()[:300] if exec_res.stderr.strip() else None
            if not err_msg and exec_res.error:
                err_msg = exec_res.error
            if not err_msg:
                err_msg = f"Gitleaks scan failed with exit code {exec_res.returncode}."

            return ScannerResult(
                scanner_name=self.name,
                status="failed",
                scanner_version=scanner_version,
                started_at=started_at,
                completed_at=completed_at,
                duration_seconds=exec_res.duration_seconds,
                raw_findings=[],
                error_message=err_msg,
            )

        finally:
            # Reliably clean up the report file outside the target tree
            if report_file.exists():
                try:
                    report_file.unlink(missing_ok=True)
                except OSError:
                    pass
