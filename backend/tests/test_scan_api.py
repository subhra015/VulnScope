"""
Integration tests for Scan Execution and Findings API endpoints:
- POST /api/scans/{scan_id}/run
- GET /api/scans/{scan_id}
- GET /api/scans/{scan_id}/findings
"""

import pytest
from app.models.finding import Finding
from app.models.repository import Repository
from app.models.scan import Scan
from app.models.scanner_run import ScannerRun
from app.services.workspace import workspace_manager


@pytest.fixture
def api_test_scan(db_session):
    ws_id, ws_path = workspace_manager.create_workspace()
    src_dir = ws_path / "source"
    src_dir.mkdir(parents=True, exist_ok=True)
    (src_dir / "index.js").write_text("console.log('test')")

    repo = Repository(project_name="api-project", source_type="zip")
    db_session.add(repo)
    db_session.flush()

    scan = Scan(
        repository_id=repo.id,
        project_name="api-project",
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


def test_post_run_scan_not_found(client):
    res = client.post("/api/scans/00000000-0000-0000-0000-000000000000/run")
    assert res.status_code == 404
    assert "not found" in res.json()["detail"].lower()


def test_post_run_scan_intake_not_ready(client, db_session, api_test_scan):
    api_test_scan.intake_status = "ingesting"
    db_session.commit()

    res = client.post(f"/api/scans/{api_test_scan.id}/run")
    assert res.status_code == 400
    assert "intake must be 'ready'" in res.json()["detail"].lower()


def test_post_run_scan_already_running(client, db_session, api_test_scan):
    api_test_scan.status = "running"
    db_session.commit()

    res = client.post(f"/api/scans/{api_test_scan.id}/run")
    assert res.status_code == 409
    assert "already currently executing" in res.json()["detail"].lower()


def test_post_run_scan_success_accepted(client, api_test_scan, monkeypatch):
    # Mock orchestrator trigger_scan to avoid running background thread during endpoint test
    from app.api import scans
    monkeypatch.setattr(scans.scan_orchestrator, "trigger_scan", lambda scan_id: True)

    res = client.post(f"/api/scans/{api_test_scan.id}/run")
    assert res.status_code == 202
    data = res.json()
    assert data["scan_id"] == api_test_scan.id
    assert data["status"] == "running"


def test_get_scan_detail_with_summary(client, db_session, api_test_scan):
    # Add scanner run and finding
    sr = ScannerRun(
        scan_id=api_test_scan.id,
        scanner_name="semgrep",
        status="completed",
        findings_count=1,
    )
    db_session.add(sr)

    finding = Finding(
        scan_id=api_test_scan.id,
        scanner_name="semgrep",
        category="code",
        rule_id="py.test",
        title="Sample Code Issue",
        description="Sample Description",
        severity="high",
        file_path="src/app.py",
        start_line=10,
    )
    db_session.add(finding)
    db_session.commit()

    res = client.get(f"/api/scans/{api_test_scan.id}")
    assert res.status_code == 200
    data = res.json()
    assert len(data["scanner_runs"]) == 1
    assert data["scanner_runs"][0]["scanner_name"] == "semgrep"
    assert len(data["findings"]) == 1
    assert data["findings_summary"]["total"] == 1
    assert data["findings_summary"]["code"] == 1
    assert data["findings_summary"]["high"] == 1


def test_get_scan_findings_filtering_and_pagination(client, db_session, api_test_scan):
    # Add findings of various categories and severities
    f1 = Finding(
        scan_id=api_test_scan.id,
        scanner_name="semgrep",
        category="code",
        rule_id="rule.code",
        title="Code Vulnerability",
        description="Description 1",
        severity="high",
    )
    f2 = Finding(
        scan_id=api_test_scan.id,
        scanner_name="gitleaks",
        category="secret",
        rule_id="rule.secret",
        title="Secret Leak",
        description="Description 2",
        severity="critical",
    )
    f3 = Finding(
        scan_id=api_test_scan.id,
        scanner_name="osv-scanner",
        category="dependency",
        rule_id="CVE-2023-0001",
        title="Dependency Bug",
        description="Description 3",
        severity="medium",
    )
    db_session.add_all([f1, f2, f3])
    db_session.commit()

    # Query all
    res = client.get(f"/api/scans/{api_test_scan.id}/findings")
    assert res.status_code == 200
    data = res.json()
    assert data["total"] == 3
    assert len(data["items"]) == 3

    # Filter by category
    res_secret = client.get(f"/api/scans/{api_test_scan.id}/findings?category=secret")
    assert res_secret.status_code == 200
    data_secret = res_secret.json()
    assert data_secret["total"] == 1
    assert data_secret["items"][0]["category"] == "secret"

    # Filter by scanner
    res_semgrep = client.get(f"/api/scans/{api_test_scan.id}/findings?scanner=semgrep")
    assert res_semgrep.status_code == 200
    assert res_semgrep.json()["total"] == 1

    # Filter by severity
    res_crit = client.get(f"/api/scans/{api_test_scan.id}/findings?severity=critical")
    assert res_crit.status_code == 200
    assert res_crit.json()["total"] == 1

    # Pagination
    res_page = client.get(f"/api/scans/{api_test_scan.id}/findings?limit=1&offset=1")
    assert res_page.status_code == 200
    assert len(res_page.json()["items"]) == 1
    assert res_page.json()["total"] == 3
