"""
Unit tests for ScanOrchestrator:
Verifies scan lifecycle validation, concurrency boundaries, multi-engine dispatch,
status aggregation (completed, partial, failed), and database persistence.
"""

from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock
import pytest
from sqlalchemy import select

from app.models.finding import Finding
from app.models.repository import Repository
from app.models.scan import Scan
from app.models.scanner_run import ScannerRun
from app.scanners.base import BaseScanner, ScannerResult
from app.services.scan_orchestrator import ScanOrchestrator, ScanOrchestratorError
from app.services.workspace import workspace_manager


from tests.conftest import TestingSessionLocal


class MockScanner(BaseScanner):
    def __init__(self, name: str, category: str, status: str = "completed", findings=None, error=None):
        self._name = name
        self._category = category
        self._status = status
        self._findings = findings or []
        self._error = error

    @property
    def name(self) -> str:
        return self._name

    @property
    def category(self) -> str:
        return self._category

    def is_available(self) -> bool:
        return self._status != "unavailable"

    def get_version(self) -> str:
        return "1.0.0-mock"

    def scan(self, target_dir: Path, scan_id: str, workspace_root=None) -> ScannerResult:
        return ScannerResult(
            scanner_name=self._name,
            status=self._status,
            scanner_version="1.0.0-mock",
            started_at=datetime.now(timezone.utc),
            completed_at=datetime.now(timezone.utc),
            duration_seconds=0.05,
            raw_findings=self._findings,
            error_message=self._error,
        )


@pytest.fixture
def staged_scan(db_session, tmp_path):
    """Fixture providing a scan record with a valid temporary workspace."""
    ws_id, ws_path = workspace_manager.create_workspace()
    src_dir = ws_path / "source"
    src_dir.mkdir(parents=True, exist_ok=True)
    (src_dir / "main.py").write_text("print('hello world')")

    repo = Repository(
        project_name="test-project",
        source_type="zip",
    )
    db_session.add(repo)
    db_session.flush()

    scan = Scan(
        repository_id=repo.id,
        project_name="test-project",
        source_type="zip",
        status="created",
        intake_status="ready",
        workspace_id=ws_id,
    )
    db_session.add(scan)
    db_session.commit()
    db_session.refresh(scan)

    yield scan

    workspace_manager.cleanup_workspace(ws_id)


def test_orchestrator_rejects_unready_intake(db_session, staged_scan):
    staged_scan.intake_status = "ingesting"
    db_session.commit()

    orchestrator = ScanOrchestrator(scanners=[MockScanner("mock", "code")], session_factory=TestingSessionLocal)
    with pytest.raises(ScanOrchestratorError, match="must be 'ready'"):
        orchestrator.trigger_scan(staged_scan.id)


def test_orchestrator_rejects_nonexistent_scan():
    orchestrator = ScanOrchestrator(scanners=[MockScanner("mock", "code")], session_factory=TestingSessionLocal)
    with pytest.raises(ScanOrchestratorError, match="not found"):
        orchestrator.trigger_scan("non-existent-scan-id")


def test_orchestrator_rejects_duplicate_concurrent_scan(db_session, staged_scan):
    orchestrator = ScanOrchestrator(scanners=[MockScanner("mock", "code")], session_factory=TestingSessionLocal)

    # Mark scan as already executing in the orchestrator active set
    orchestrator._active_scan_ids.add(staged_scan.id)

    with pytest.raises(ScanOrchestratorError, match="already actively executing"):
        orchestrator.trigger_scan(staged_scan.id)

    orchestrator._active_scan_ids.discard(staged_scan.id)


def test_orchestrator_completed_all_scanners(db_session, staged_scan):
    scanners = [
        MockScanner("semgrep", "code", status="completed", findings=[
            {"check_id": "rule-1", "path": "main.py", "extra": {"message": "Code issue", "severity": "ERROR"}}
        ]),
        MockScanner("gitleaks", "secret", status="completed", findings=[
            {"RuleID": "git-secret", "File": "main.py", "StartLine": 1}
        ]),
        MockScanner("osv-scanner", "dependency", status="completed", findings=[]),
    ]

    orchestrator = ScanOrchestrator(scanners=scanners, session_factory=TestingSessionLocal)
    # Execute job synchronously for deterministic testing
    orchestrator._execute_scan_job(staged_scan.id)

    db_session.refresh(staged_scan)
    assert staged_scan.status == "completed"
    assert staged_scan.completed_at is not None

    # Check scanner runs recorded
    assert len(staged_scan.scanner_runs) == 3
    run_statuses = {sr.scanner_name: sr.status for sr in staged_scan.scanner_runs}
    assert run_statuses == {"semgrep": "completed", "gitleaks": "completed", "osv-scanner": "completed"}

    # Check normalized findings persisted
    findings = db_session.scalars(select(Finding).where(Finding.scan_id == staged_scan.id)).all()
    assert len(findings) == 2


def test_orchestrator_partial_status_when_one_fails(db_session, staged_scan):
    scanners = [
        MockScanner("semgrep", "code", status="completed", findings=[]),
        MockScanner("gitleaks", "secret", status="failed", error="Gitleaks crash"),
        MockScanner("osv-scanner", "dependency", status="unavailable", error="Binary missing"),
    ]

    orchestrator = ScanOrchestrator(scanners=scanners, session_factory=TestingSessionLocal)
    orchestrator._execute_scan_job(staged_scan.id)

    db_session.refresh(staged_scan)
    # At least one completed, but another failed/unavailable -> partial
    assert staged_scan.status == "partial"


def test_orchestrator_failed_status_when_all_fail(db_session, staged_scan):
    scanners = [
        MockScanner("semgrep", "code", status="failed", error="Execution error"),
        MockScanner("gitleaks", "secret", status="failed", error="Crash"),
        MockScanner("osv-scanner", "dependency", status="unavailable", error="Missing"),
    ]

    orchestrator = ScanOrchestrator(scanners=scanners, session_factory=TestingSessionLocal)
    orchestrator._execute_scan_job(staged_scan.id)

    db_session.refresh(staged_scan)
    assert staged_scan.status == "failed"


def test_orchestrator_zero_findings_completes(db_session, staged_scan):
    scanners = [
        MockScanner("semgrep", "code", status="completed", findings=[]),
        MockScanner("gitleaks", "secret", status="completed", findings=[]),
        MockScanner("osv-scanner", "dependency", status="completed", findings=[]),
    ]

    orchestrator = ScanOrchestrator(scanners=scanners, session_factory=TestingSessionLocal)
    orchestrator._execute_scan_job(staged_scan.id)

    db_session.refresh(staged_scan)
    assert staged_scan.status == "completed"
    assert len(staged_scan.findings) == 0
