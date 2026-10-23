"""
OSV-Scanner Software Composition Analysis (SCA) Scanner Adapter.
Integrates OSV-Scanner CLI for detecting known vulnerabilities in project dependencies.
Strictly scans lockfiles/manifests without invoking package managers or build scripts.
"""

from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from app.core.config import settings
from app.scanners.base import BaseScanner, ScannerResult
from app.services.scanner_runner import ScannerRunner, default_scanner_runner


class OSVScanner(BaseScanner):
    """
    Adapter for OSV-Scanner dependency vulnerability scanner.
    """

    def __init__(self, runner: Optional[ScannerRunner] = None, binary_path: Optional[str] = None):
        self.runner = runner or default_scanner_runner
        self._binary_path = binary_path

    @property
    def name(self) -> str:
        return "osv-scanner"

    @property
    def category(self) -> str:
        return "dependency"

    def get_binary_path(self) -> Optional[str]:
        if self._binary_path:
            return self._binary_path
        return settings.resolve_scanner_binary("osv-scanner")

    def is_available(self) -> bool:
        return self.get_binary_path() is not None

    def get_version(self) -> Optional[str]:
        bin_path = self.get_binary_path()
        if not bin_path:
            return None
        res = self.runner.run([bin_path, "--version"], timeout_seconds=10.0)
        if res.returncode == 0 and res.stdout.strip():
            # Format usually starts with "osv-scanner version: 2.7.0"
            for line in res.stdout.strip().splitlines():
                if "version" in line.lower():
                    return line.split(":")[-1].strip()[:50]
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
                error_message="OSV-Scanner CLI executable is not installed or not found on system PATH.",
            )

        scanner_version = self.get_version()

        # Build arguments: recursive scan on source snapshot, allow no lockfiles, json output
        # Notice: NO call-analysis flag to strictly prevent running project build scripts
        cmd = [
            bin_path,
            "scan",
            "source",
            "--format",
            "json",
            "--allow-no-lockfiles",
            "-r",
            str(target_dir),
        ]

        exec_res = self.runner.run(
            cmd,
            timeout_seconds=settings.osv_scanner_timeout_seconds,
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
                error_message=f"OSV-Scanner scan timed out after {settings.osv_scanner_timeout_seconds} seconds.",
            )

        # Parse JSON output
        parsed_json: Optional[Dict[str, Any]] = None
        if exec_res.stdout.strip():
            try:
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
                    error_message=f"Failed to parse OSV-Scanner output as JSON: {type(exc).__name__}",
                )

        raw_findings: List[Dict[str, Any]] = []
        if parsed_json is not None and isinstance(parsed_json, dict):
            # OSV JSON has a 'results' list:
            # Each entry in 'results' has 'source' and 'packages'
            results_list = parsed_json.get("results", [])
            for res_item in results_list:
                source_info = res_item.get("source", {})
                source_path = ""
                if isinstance(source_info, dict):
                    source_path = source_info.get("path", "")
                elif isinstance(source_info, str):
                    source_path = source_info

                for pkg_entry in res_item.get("packages", []):
                    pkg_meta = pkg_entry.get("package", {})
                    pkg_name = pkg_meta.get("name", "unknown")
                    pkg_version = pkg_meta.get("version", "")
                    ecosystem = pkg_meta.get("ecosystem", "")

                    for vuln in pkg_entry.get("vulnerabilities", []):
                        raw_findings.append({
                            "vuln": vuln,
                            "package_name": pkg_name,
                            "package_version": pkg_version,
                            "ecosystem": ecosystem,
                            "source_path": source_path,
                            "groups": pkg_entry.get("groups", []),
                        })

            # In OSV-Scanner, returncode 0 = clean, 1 = vulnerabilities found
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

        # Genuine error condition
        err_msg = exec_res.stderr.strip()[:300] if exec_res.stderr.strip() else None
        if not err_msg and exec_res.error:
            err_msg = exec_res.error
        if not err_msg:
            err_msg = f"OSV-Scanner scan failed with exit code {exec_res.returncode}."

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
