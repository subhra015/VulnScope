"""
Semgrep Static Application Security Testing (SAST) Scanner Adapter.
Integrates Semgrep CLI for rule-based static code analysis.
"""

from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from app.core.config import settings
from app.scanners.base import BaseScanner, ScannerResult
from app.services.scanner_runner import ScannerRunner, default_scanner_runner


class SemgrepScanner(BaseScanner):
    """
    Adapter for Semgrep SAST scanner.
    """

    def __init__(self, runner: Optional[ScannerRunner] = None, binary_path: Optional[str] = None):
        self.runner = runner or default_scanner_runner
        self._binary_path = binary_path

    @property
    def name(self) -> str:
        return "semgrep"

    @property
    def category(self) -> str:
        return "code"

    def get_binary_path(self) -> Optional[str]:
        if self._binary_path:
            return self._binary_path
        return settings.resolve_scanner_binary("semgrep")

    def is_available(self) -> bool:
        return self.get_binary_path() is not None

    def get_version(self) -> Optional[str]:
        bin_path = self.get_binary_path()
        if not bin_path:
            return None
        res = self.runner.run([bin_path, "--version"], timeout_seconds=10.0)
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
                error_message="Semgrep CLI executable is not installed or not found on system PATH.",
            )

        scanner_version = self.get_version()

        # Build arguments with shell=False safety
        # Config option uses settings.semgrep_rules_config (default 'p/default')
        cmd = [
            bin_path,
            "scan",
            "--config",
            settings.semgrep_rules_config,
            "--json",
            "--quiet",
            "--disable-version-check",
            "--metrics=off",
            str(target_dir),
        ]

        exec_res = self.runner.run(
            cmd,
            timeout_seconds=settings.semgrep_timeout_seconds,
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
                error_message=f"Semgrep scan timed out after {settings.semgrep_timeout_seconds} seconds.",
            )

        # Parse output JSON
        raw_findings: List[Dict[str, Any]] = []
        parsed_json: Optional[Dict[str, Any]] = None

        if exec_res.stdout.strip():
            try:
                # Find the JSON segment in stdout in case any warnings preceded it
                stdout_text = exec_res.stdout.strip()
                first_brace = stdout_text.find("{")
                last_brace = stdout_text.rfind("}")
                if first_brace != -1 and last_brace != -1 and last_brace > first_brace:
                    json_str = stdout_text[first_brace : last_brace + 1]
                    parsed_json = json.loads(json_str)
                else:
                    parsed_json = json.loads(stdout_text)
            except Exception as exc:
                return ScannerResult(
                    scanner_name=self.name,
                    status="failed",
                    scanner_version=scanner_version,
                    started_at=started_at,
                    completed_at=completed_at,
                    duration_seconds=exec_res.duration_seconds,
                    raw_findings=[],
                    error_message=f"Failed to parse Semgrep output as JSON: {type(exc).__name__}",
                )

        # If parsed_json exists, extract findings
        if parsed_json is not None and isinstance(parsed_json, dict):
            raw_findings = parsed_json.get("results", [])
            # In semgrep, 0 means OK, 1 means findings were found or non-fatal condition
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

        # If return code indicates fatal error (2, etc.) or parsing failed
        error_msg = exec_res.stderr.strip()[:300] if exec_res.stderr.strip() else None
        if not error_msg and exec_res.error:
            error_msg = exec_res.error
        if not error_msg:
            error_msg = f"Semgrep scan failed with process exit code {exec_res.returncode}."

        return ScannerResult(
            scanner_name=self.name,
            status="failed",
            scanner_version=scanner_version,
            started_at=started_at,
            completed_at=completed_at,
            duration_seconds=exec_res.duration_seconds,
            raw_findings=[],
            error_message=error_msg,
        )
