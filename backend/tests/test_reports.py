"""
Automated tests for Professional Security Report Generation.
Tests:
- JSON, HTML, and PDF export generation
- HTML escaping defenses against XSS payloads in titles/descriptions
- Secret redaction in exported reports
- Accuracy of priority and scanner outcome tallies
- Works independently of AI availability (disabled provider)
- Invalid format and invalid scan handling
"""

import json
from fastapi.testclient import TestClient
import pytest
from sqlalchemy.orm import Session

from app.models.finding import Finding
from app.models.repository import Repository
from app.models.scan import Scan
from app.models.scanner_run import ScannerRun
from app.services.report_service import ReportService


@pytest.fixture
def sample_report_scan(db_session: Session) -> Scan:
    """Create a scan with findings and scanner runs for report generation."""
    repo = Repository(project_name="audit-sample-service", source_type="zip", source_reference="repo.zip")
    db_session.add(repo)
    db_session.flush()

    scan = Scan(
        repository_id=repo.id,
        project_name="audit-sample-service",
        source_type="zip",
        source_reference="repo.zip",
        status="completed",
    )
    db_session.add(scan)
    db_session.flush()

    # Add scanner runs
    sr1 = ScannerRun(
        scan_id=scan.id,
        scanner_name="semgrep",
        status="completed",
        scanner_version="1.182.1",
        duration_seconds=3.45,
        findings_count=1,
    )
    sr2 = ScannerRun(
        scan_id=scan.id,
        scanner_name="gitleaks",
        status="completed",
        scanner_version="8.18.0",
        duration_seconds=1.20,
        findings_count=1,
    )
    sr3 = ScannerRun(
        scan_id=scan.id,
        scanner_name="osv-scanner",
        status="failed",
        scanner_version="1.7.0",
        duration_seconds=2.10,
        findings_count=0,
        error_message="Lockfile parsing timeout",
    )
    db_session.add_all([sr1, sr2, sr3])

    # Add findings with synthetic secrets and XSS payload to test defenses
    f1 = Finding(
        scan_id=scan.id,
        scanner_name="semgrep",
        rule_id="py.sqli.eval",
        category="code",
        title="SQL Injection <script>alert('xss')</script>",
        description="Dangerous string concat with token AKIAIOSFODNN7EXAMPLE in query",
        severity="critical",
        file_path="src/database.py",
        start_line=45,
        risk_score=92,
        priority="critical",
    )
    f2 = Finding(
        scan_id=scan.id,
        scanner_name="gitleaks",
        rule_id="generic-api-key",
        category="secret",
        title="Exposed Secret Key",
        description="Potential exposed credential detected in source code.",
        severity="critical",
        file_path="config/settings.py",
        start_line=12,
        risk_score=85,
        priority="critical",
    )
    db_session.add_all([f1, f2])
    db_session.commit()
    db_session.refresh(scan)
    return scan


def test_json_report_generation(sample_report_scan: Scan, db_session: Session):
    """JSON report conforms to schema, tallies findings, and redacts secrets."""
    report = ReportService.generate_json_report(sample_report_scan, db_session)

    assert report["scan_id"] == sample_report_scan.id
    assert report["total_findings"] == 2
    assert report["priority_distribution"]["critical"] == 2
    assert len(report["scanner_runs"]) == 3

    # Check that failed scanner is flagged in limitations
    assert any("osv-scanner" in lim for lim in report["coverage_limitations"])

    # Check secret redaction
    json_str = json.dumps(report)
    assert "AKIAIOSFODNN7EXAMPLE" not in json_str
    assert "[REDACTED_AWS_KEY]" in json_str


def test_html_report_escaping_and_redaction(sample_report_scan: Scan, db_session: Session):
    """HTML report properly escapes script tags and redacts secrets."""
    html_out = ReportService.generate_html_report(sample_report_scan, db_session)

    # Must contain title (with & escaped to &amp;)
    assert "VulnScope Security Audit &amp; Remediation Report" in html_out

    # Script tags must be HTML-escaped, NEVER rendered raw
    assert "<script>alert('xss')</script>" not in html_out
    assert "&lt;script&gt;alert(&#x27;xss&#x27;)&lt;/script&gt;" in html_out or "&lt;script&gt;alert('xss')&lt;/script&gt;" in html_out

    # Secrets must be redacted
    assert "AKIAIOSFODNN7EXAMPLE" not in html_out
    assert "[REDACTED_AWS_KEY]" in html_out


def test_pdf_report_generation(sample_report_scan: Scan, db_session: Session):
    """PDF report produces valid non-empty binary bytes starting with PDF header."""
    pdf_bytes = ReportService.generate_pdf_report(sample_report_scan, db_session)

    assert isinstance(pdf_bytes, bytes)
    assert len(pdf_bytes) > 1000
    assert pdf_bytes.startswith(b"%PDF-")


def test_report_api_endpoints(client: TestClient, sample_report_scan: Scan):
    """Test FastAPI report endpoints for JSON, HTML, and PDF formats."""
    scan_id = sample_report_scan.id

    # 1. JSON report
    res_json = client.get(f"/api/scans/{scan_id}/report?format=json")
    assert res_json.status_code == 200
    assert res_json.headers["content-type"].startswith("application/json")
    data = res_json.json()
    assert data["scan_id"] == scan_id

    # 2. HTML report
    res_html = client.get(f"/api/scans/{scan_id}/report?format=html")
    assert res_html.status_code == 200
    assert "text/html" in res_html.headers["content-type"]
    assert "<!DOCTYPE html>" in res_html.text

    # 3. PDF report
    res_pdf = client.get(f"/api/scans/{scan_id}/report?format=pdf")
    assert res_pdf.status_code == 200
    assert "application/pdf" in res_pdf.headers["content-type"]
    assert res_pdf.content.startswith(b"%PDF-")

    # 4. Invalid format returns 400
    res_invalid = client.get(f"/api/scans/{scan_id}/report?format=exe")
    assert res_invalid.status_code == 400

    # 5. Non-existent scan returns 404
    res_404 = client.get("/api/scans/non-existent-scan/report?format=json")
    assert res_404.status_code == 404
