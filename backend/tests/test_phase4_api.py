"""
Integration tests for VulnScope Phase 4 API endpoints:
- /api/scans/{scan_id}/findings (priority sorting, filtering, lifecycle)
- /api/scans/{scan_id}/findings/{finding_id} (score explanation & remediation)
- /api/scans/{scan_id}/risk-summary (priority distribution, coverage caveats)
- /api/scans/{scan_id}/comparison/{baseline_scan_id} (comparability validation)
"""

import pytest
from app.models.finding import Finding
from app.models.repository import Repository
from app.models.scan import Scan
from app.models.scanner_run import ScannerRun


class TestPhase4Api:
    """Test suite for Phase 4 REST API endpoints."""

    @pytest.fixture
    def test_env(self, db_session):
        repo = Repository(
            project_name="phase4-api-test",
            source_type="github",
            source_reference="https://github.com/org/phase4-api-test",
        )
        db_session.add(repo)
        db_session.commit()

        scan = Scan(
            repository_id=repo.id,
            project_name=repo.project_name,
            source_type=repo.source_type,
            status="completed",
        )
        db_session.add(scan)
        db_session.flush()

        # Add scanner runs
        db_session.add(ScannerRun(scan_id=scan.id, scanner_name="semgrep", status="completed", findings_count=1))
        db_session.add(ScannerRun(scan_id=scan.id, scanner_name="gitleaks", status="completed", findings_count=1))
        db_session.add(ScannerRun(scan_id=scan.id, scanner_name="osv-scanner", status="completed", findings_count=1))

        # Add findings
        f1 = Finding(
            scan_id=scan.id,
            scanner_name="gitleaks",
            category="secret",
            rule_id="slack-bot-token",
            title="Exposed Slack Token",
            description="Leaked token",
            severity="critical",
            confidence="high",
            file_path="config.py",
            start_line=10,
            finding_fingerprint="fp-api-1",
        )
        f2 = Finding(
            scan_id=scan.id,
            scanner_name="semgrep",
            category="code",
            rule_id="python.security.sqli",
            title="SQL Injection Vulnerability",
            description="User input concatenated into query",
            severity="high",
            confidence="high",
            file_path="database.py",
            start_line=45,
            finding_fingerprint="fp-api-2",
        )
        f3 = Finding(
            scan_id=scan.id,
            scanner_name="osv-scanner",
            category="dependency",
            rule_id="CVE-2023-5555",
            title="Vulnerable Package",
            description="Buffer overflow in library",
            severity="medium",
            confidence="medium",
            package_name="vuln-lib",
            package_version="1.0.0",
            fixed_version="1.0.1",
            cvss_score=6.5,
            finding_fingerprint="fp-api-3",
        )
        db_session.add_all([f1, f2, f3])
        db_session.commit()

        return {"repo": repo, "scan": scan, "findings": [f1, f2, f3]}

    def test_findings_sorting_by_priority(self, client, test_env):
        """Verify findings list defaults to sorting by risk priority descending."""
        scan = test_env["scan"]
        res = client.get(f"/api/scans/{scan.id}/findings?sort_by=priority&sort_order=desc")
        assert res.status_code == 200
        data = res.json()
        assert data["total"] == 3
        items = data["items"]

        # Ensure descending priority order
        scores = [item["risk_score"] for item in items]
        assert scores == sorted(scores, reverse=True)
        # Secret leak should be highest
        assert items[0]["category"] == "secret"
        assert items[0]["priority"] == "critical"

    def test_findings_filtering_by_priority_and_category(self, client, test_env):
        """Verify filtering by priority tier and category."""
        scan = test_env["scan"]

        # Filter by priority=critical
        res_crit = client.get(f"/api/scans/{scan.id}/findings?priority=critical")
        assert res_crit.status_code == 200
        data_crit = res_crit.json()
        assert data_crit["total"] == 1
        assert data_crit["items"][0]["category"] == "secret"

        # Filter by category=dependency
        res_dep = client.get(f"/api/scans/{scan.id}/findings?category=dependency")
        assert res_dep.status_code == 200
        data_dep = res_dep.json()
        assert data_dep["total"] == 1
        assert data_dep["items"][0]["rule_id"] == "CVE-2023-5555"

    def test_get_finding_detail_with_explanation_and_remediation(self, client, test_env):
        """Verify retrieving an individual finding returns full score explanation and remediation."""
        scan = test_env["scan"]
        finding = test_env["findings"][0]

        res = client.get(f"/api/scans/{scan.id}/findings/{finding.id}")
        assert res.status_code == 200
        data = res.json()

        assert data["id"] == finding.id
        assert data["risk_explanation"] is not None
        assert data["risk_explanation"]["score"] >= 85
        assert data["risk_explanation"]["priority"] == "critical"
        assert len(data["risk_explanation"]["factors"]) == 4

        assert data["remediation"] is not None
        assert data["remediation"]["category"] == "secret"
        assert len(data["remediation"]["steps"]) > 0
        assert data["remediation"]["unsafe_pattern"] is not None
        assert data["remediation"]["safer_alternative"] is not None

    def test_finding_scan_ownership_validation_404(self, client, db_session, test_env):
        """Verify 404 is returned if a finding does not belong to the requested scan."""
        scan = test_env["scan"]
        other_scan = Scan(project_name="other-project", source_type="github", status="completed")
        db_session.add(other_scan)
        db_session.commit()

        finding = test_env["findings"][0]
        # Request finding under mismatched scan
        res = client.get(f"/api/scans/{other_scan.id}/findings/{finding.id}")
        assert res.status_code == 404
        assert "not found in scan" in res.json()["detail"].lower()

    def test_risk_summary_endpoint(self, client, test_env):
        """Verify risk summary endpoint accurately reports priority counts and coverage."""
        scan = test_env["scan"]
        res = client.get(f"/api/scans/{scan.id}/risk-summary")
        assert res.status_code == 200
        data = res.json()

        assert data["total_findings"] == 3
        assert "priority_distribution" in data
        assert data["priority_distribution"]["critical"] >= 1
        assert data["mean_risk_score"] > 0
        assert data["max_risk_score"] >= 85
        assert "scanner_coverage" in data
        assert data["scanner_coverage"]["semgrep"] == "completed"
        assert data["scanner_coverage"]["gitleaks"] == "completed"
        assert data["scanner_coverage"]["osv-scanner"] == "completed"

    def test_scan_comparison_endpoint(self, client, db_session, test_env):
        """Verify comparative diff endpoint between target and baseline scans."""
        repo = test_env["repo"]
        baseline = test_env["scan"]

        # Create target scan with 1 recurring and 1 new finding
        target = Scan(repository_id=repo.id, project_name=repo.project_name, source_type=repo.source_type, status="completed")
        db_session.add(target)
        db_session.flush()

        db_session.add(ScannerRun(scan_id=target.id, scanner_name="semgrep", status="completed"))
        db_session.add(ScannerRun(scan_id=target.id, scanner_name="gitleaks", status="completed"))
        db_session.add(ScannerRun(scan_id=target.id, scanner_name="osv-scanner", status="completed"))

        # Re-create f1 (recurring with identical attributes)
        db_session.add(Finding(
            scan_id=target.id,
            scanner_name="gitleaks",
            category="secret",
            rule_id="slack-bot-token",
            title="Exposed Slack Token",
            description="Leaked token",
            severity="critical",
            confidence="high",
            file_path="config.py",
            start_line=10,
            finding_fingerprint="fp-api-1",
        ))
        # New finding
        db_session.add(Finding(
            scan_id=target.id,
            scanner_name="semgrep",
            category="code",
            rule_id="python.security.ssrf",
            title="SSRF Vulnerability",
            description="Server-Side Request Forgery",
            severity="high",
            finding_fingerprint="fp-new-ssrf",
        ))
        db_session.commit()

        res = client.get(f"/api/scans/{target.id}/comparison/{baseline.id}")
        assert res.status_code == 200
        data = res.json()

        assert data["scan_id"] == target.id
        assert data["baseline_scan_id"] == baseline.id
        assert data["summary"]["recurring"] == 1
        assert data["summary"]["new"] == 1
        assert data["summary"]["resolved"] == 2
        assert len(data["new_findings"]) == 1
        assert data["new_findings"][0]["rule_id"] == "python.security.ssrf"

    def test_scan_comparison_different_repositories_400(self, client, db_session, test_env):
        """Verify comparison across different repositories returns 400 Bad Request."""
        scan1 = test_env["scan"]
        scan2 = Scan(project_name="totally-different-repo", source_type="github", status="completed")
        db_session.add(scan2)
        db_session.commit()

        res = client.get(f"/api/scans/{scan1.id}/comparison/{scan2.id}")
        assert res.status_code == 400
        assert "different" in res.json()["detail"].lower()
