"""
Scan Orchestrator Service.
Coordinates the execution of multiple security scanner engines (Semgrep, Gitleaks, OSV-Scanner),
enforces concurrency controls, manages scanner lifecycle records, and normalizes findings.
"""

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import logging
from pathlib import Path
import threading
from typing import Dict, List, Optional, Set, Tuple

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.session import SessionLocal
from app.models.base import utc_now
from app.models.finding import Finding
from app.models.scan import Scan
from app.models.scanner_run import ScannerRun
from app.scanners.base import BaseScanner, ScannerResult
from app.scanners.semgrep import SemgrepScanner
from app.scanners.gitleaks import GitleaksScanner
from app.scanners.osv_scanner import OSVScanner
from app.services.finding_normalizer import FindingNormalizer, NormalizedFindingData
from app.services.risk_scorer import RiskScorer
from app.services.workspace import WorkspaceSecurityError, workspace_manager

logger = logging.getLogger(__name__)


class ScanOrchestratorError(Exception):
    """Raised when scan orchestration encounters a business rule violation."""
    pass


class ScanOrchestrator:
    """
    Coordinates scanner execution, concurrency boundaries, and persistence.
    """

    def __init__(
        self,
        scanners: Optional[List[BaseScanner]] = None,
        max_workers: Optional[int] = None,
        session_factory=None,
    ):
        self.scanners = scanners or [
            SemgrepScanner(),
            GitleaksScanner(),
            OSVScanner(),
        ]
        self._max_workers = max_workers or settings.max_concurrent_scans
        self._executor = ThreadPoolExecutor(
            max_workers=self._max_workers,
            thread_name_prefix="vulnscope-scan",
        )
        self._active_scan_ids: Set[str] = set()
        self._lock = threading.Lock()
        self._session_factory = session_factory or SessionLocal

    def is_scan_running(self, scan_id: str) -> bool:
        """Check whether a scan is actively running in background."""
        with self._lock:
            return scan_id in self._active_scan_ids

    def trigger_scan(self, scan_id: str) -> bool:
        """
        Validate prerequisites, transition scan to 'running', and schedule background execution.
        Raises ScanOrchestratorError if scan does not exist, intake is not ready, or already running.
        """
        db = self._session_factory()
        try:
            stmt = select(Scan).where(Scan.id == scan_id)
            scan = db.scalars(stmt).first()

            if not scan:
                raise ScanOrchestratorError(f"Scan record with ID '{scan_id}' not found.")

            # Validate lifecycle state
            if scan.intake_status != "ready":
                raise ScanOrchestratorError(
                    f"Scan cannot start because source intake is '{scan.intake_status}'. Intake must be 'ready'."
                )

            with self._lock:
                if scan_id in self._active_scan_ids or scan.status == "running":
                    raise ScanOrchestratorError(
                        f"Scan '{scan_id}' is already actively executing."
                    )
                self._active_scan_ids.add(scan_id)

            # Validate workspace directory
            if not scan.workspace_id:
                with self._lock:
                    self._active_scan_ids.discard(scan_id)
                raise ScanOrchestratorError("Scan has no associated workspace.")

            try:
                source_dir = workspace_manager.get_source_dir(scan.workspace_id)
                if not source_dir.exists() or not source_dir.is_dir():
                    with self._lock:
                        self._active_scan_ids.discard(scan_id)
                    raise ScanOrchestratorError(
                        "Workspace source directory not found or unreadable."
                    )
            except WorkspaceSecurityError as exc:
                with self._lock:
                    self._active_scan_ids.discard(scan_id)
                raise ScanOrchestratorError(f"Invalid workspace path: {exc}")

            # Transition status to 'running'
            scan.status = "running"
            scan.started_at = utc_now()
            scan.error_summary = None
            db.commit()

            # Dispatch to bounded thread pool
            self._executor.submit(self._execute_scan_job, scan_id)
            return True

        except Exception:
            db.rollback()
            raise
        finally:
            db.close()

    def _execute_scan_job(self, scan_id: str) -> None:
        """
        Internal worker executed in thread pool.
        Executes all scanners, saves scanner_runs, normalizes findings, and updates status.
        """
        db = self._session_factory()
        try:
            stmt = select(Scan).where(Scan.id == scan_id)
            scan = db.scalars(stmt).first()
            if not scan:
                logger.error("Scan %s disappeared from database before execution", scan_id)
                return

            workspace_path = workspace_manager.get_workspace_path(scan.workspace_id)
            source_dir = workspace_manager.get_source_dir(scan.workspace_id)

            # Clear previous scanner runs and findings if re-scanning
            if scan.findings:
                for f in list(scan.findings):
                    db.delete(f)
            if scan.scanner_runs:
                for sr in list(scan.scanner_runs):
                    db.delete(sr)
            db.flush()

            scanner_results: List[Tuple[str, List[Dict]]] = []
            run_records: List[ScannerRun] = []
            has_completed = False
            has_failed_or_unavailable = False

            # Execute each scanner sequentially within this scan job
            for scanner in self.scanners:
                try:
                    result: ScannerResult = scanner.scan(
                        target_dir=source_dir,
                        scan_id=scan_id,
                        workspace_root=workspace_path,
                    )
                except Exception as exc:
                    logger.exception("Scanner %s raised unexpected exception: %s", scanner.name, exc)
                    result = ScannerResult(
                        scanner_name=scanner.name,
                        status="failed",
                        scanner_version=None,
                        started_at=datetime.now(timezone.utc),
                        completed_at=datetime.now(timezone.utc),
                        duration_seconds=0.0,
                        raw_findings=[],
                        error_message=f"Scanner execution error: {type(exc).__name__}",
                    )

                # Record outcome
                if result.status == "completed":
                    has_completed = True
                else:
                    has_failed_or_unavailable = True

                findings_for_tool = result.raw_findings if result.is_success else []
                scanner_results.append((scanner.name, findings_for_tool))

                scanner_run_record = ScannerRun(
                    scan_id=scan_id,
                    scanner_name=scanner.name,
                    status=result.status,
                    scanner_version=result.scanner_version,
                    started_at=result.started_at,
                    completed_at=result.completed_at,
                    duration_seconds=result.duration_seconds,
                    findings_count=len(findings_for_tool),
                    error_message=result.error_message,
                )
                db.add(scanner_run_record)
                run_records.append(scanner_run_record)

            db.flush()

            # Normalize and persist all findings
            normalized_findings: List[NormalizedFindingData] = FindingNormalizer.normalize_all(
                scanner_results=scanner_results,
                scan_id=scan_id,
                target_dir=source_dir,
            )

            # Update findings counts on run records after normalization/deduplication
            for run_rec in run_records:
                count = sum(1 for nf in normalized_findings if nf.scanner_name == run_rec.scanner_name)
                run_rec.findings_count = count

            for item in normalized_findings:
                risk_exp = RiskScorer.calculate_score(
                    severity=item.severity,
                    confidence=item.confidence,
                    category=item.category,
                    rule_id=item.rule_id,
                    cvss_score=item.cvss_score,
                    file_path=item.file_path,
                    start_line=item.start_line,
                    package_name=item.package_name,
                    package_version=item.package_version,
                    fixed_version=item.fixed_version,
                )
                finding_model = Finding(
                    scan_id=scan_id,
                    scanner_name=item.scanner_name,
                    category=item.category,
                    rule_id=item.rule_id,
                    title=item.title,
                    description=item.description,
                    severity=item.severity,
                    confidence=item.confidence,
                    file_path=item.file_path,
                    start_line=item.start_line,
                    end_line=item.end_line,
                    package_name=item.package_name,
                    package_version=item.package_version,
                    ecosystem=item.ecosystem,
                    fixed_version=item.fixed_version,
                    redacted_evidence=item.redacted_evidence,
                    remediation_guidance=item.remediation_guidance,
                    advisory_url=item.advisory_url,
                    finding_fingerprint=item.finding_fingerprint,
                    risk_score=risk_exp.score,
                    priority=risk_exp.priority,
                    cvss_score=item.cvss_score,
                )
                db.add(finding_model)

            # Compute overall scan status
            if has_completed and not has_failed_or_unavailable:
                final_status = "completed"
            elif has_completed and has_failed_or_unavailable:
                final_status = "partial"
            else:
                final_status = "failed"

            scan.status = final_status
            scan.completed_at = utc_now()
            db.commit()

        except Exception as exc:
            logger.exception("Fatal orchestration error for scan %s: %s", scan_id, exc)
            db.rollback()
            try:
                # Fallback update to mark scan failed
                stmt = select(Scan).where(Scan.id == scan_id)
                failed_scan = db.scalars(stmt).first()
                if failed_scan:
                    failed_scan.status = "failed"
                    failed_scan.completed_at = utc_now()
                    failed_scan.error_summary = "An unexpected error occurred during scan execution."
                    db.commit()
            except Exception:
                db.rollback()
        finally:
            with self._lock:
                self._active_scan_ids.discard(scan_id)
            db.close()


# Singleton instance
scan_orchestrator = ScanOrchestrator()
