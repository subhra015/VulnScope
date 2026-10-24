"""
Unit tests for VulnScope Finding Lifecycle & Scan Comparison Service (Phase 4).
Verifies:
- Stable matching (fingerprint and fallback heuristic)
- Lifecycle classifications: new, recurring, resolved, changed
- Partial scan safety: NO false resolution when scanner failed/unavailable
- Zero-finding scan handling
- Repository ownership / lineage validation (prevents comparing unrelated repos)
"""

import pytest
from app.models.finding import Finding
from app.models.repository import Repository
from app.models.scan import Scan
from app.models.scanner_run import ScannerRun
from app.services.lifecycle_service import (
    LifecycleService,
    ScanComparabilityError,
)


class TestLifecycleService:
    """Test suite for scan comparison and finding lifecycle tracking."""

    @pytest.fixture
    def test_repo(self, db_session):
        repo = Repository(
            project_name="lifecycle-repo",
            source_type="github",
            source_reference="https://github.com/org/lifecycle-repo",
        )
        db_session.add(repo)
        db_session.commit()
        db_session.refresh(repo)
        return repo

    def test_unrelated_repositories_cannot_be_compared(self, db_session):
        """Verify cross-repository comparison is strictly rejected."""
        repo1 = Repository(project_name="repo-1", source_type="github")
        repo2 = Repository(project_name="repo-2", source_type="github")
        db_session.add_all([repo1, repo2])
        db_session.commit()

        scan1 = Scan(repository_id=repo1.id, project_name="repo-1", source_type="github", status="completed")
        scan2 = Scan(repository_id=repo2.id, project_name="repo-2", source_type="github", status="completed")
        db_session.add_all([scan1, scan2])
        db_session.commit()

        with pytest.raises(ScanComparabilityError) as exc_info:
            LifecycleService.compare_scans(db_session, scan1, scan2)
        assert "different repositories" in str(exc_info.value).lower()

    def test_incomplete_or_failed_scans_cannot_be_compared(self, db_session, test_repo):
        """Verify running or failed scans cannot serve as valid baselines."""
        baseline = Scan(repository_id=test_repo.id, project_name=test_repo.project_name, source_type="github", status="failed")
        target = Scan(repository_id=test_repo.id, project_name=test_repo.project_name, source_type="github", status="completed")
        db_session.add_all([baseline, target])
        db_session.commit()

        with pytest.raises(ScanComparabilityError) as exc_info:
            LifecycleService.compare_scans(db_session, target, baseline)
        assert "failed" in str(exc_info.value).lower()

    def test_lifecycle_new_recurring_resolved_changed(self, db_session, test_repo):
        """Verify accurate classification of new, recurring, resolved, and changed findings."""
        # Baseline scan with 3 findings (A, B, C)
        baseline = Scan(repository_id=test_repo.id, project_name=test_repo.project_name, source_type="github", status="completed")
        db_session.add(baseline)
        db_session.flush()

        # Add successful scanner runs for baseline
        db_session.add(ScannerRun(scan_id=baseline.id, scanner_name="semgrep", status="completed"))
        db_session.add(ScannerRun(scan_id=baseline.id, scanner_name="gitleaks", status="completed"))
        db_session.add(ScannerRun(scan_id=baseline.id, scanner_name="osv-scanner", status="completed"))

        f_recurring = Finding(
            scan_id=baseline.id,
            scanner_name="semgrep",
            category="code",
            rule_id="py.xss",
            title="XSS Bug",
            description="XSS",
            severity="medium",
            file_path="views.py",
            start_line=10,
            finding_fingerprint="fp-recurring",
        )
        f_resolved = Finding(
            scan_id=baseline.id,
            scanner_name="gitleaks",
            category="secret",
            rule_id="generic-api-key",
            title="Secret Leak",
            description="Secret",
            severity="critical",
            file_path="config.py",
            start_line=5,
            finding_fingerprint="fp-resolved",
        )
        f_changed_base = Finding(
            scan_id=baseline.id,
            scanner_name="osv-scanner",
            category="dependency",
            rule_id="CVE-2023-1111",
            title="Vulnerable Lib",
            description="Dep bug",
            severity="high",
            package_name="lib-a",
            package_version="1.0.0",
            fixed_version="1.1.0",
            finding_fingerprint="fp-changed",
        )
        db_session.add_all([f_recurring, f_resolved, f_changed_base])
        db_session.commit()

        # Target scan (rescanned)
        target = Scan(repository_id=test_repo.id, project_name=test_repo.project_name, source_type="github", status="completed")
        db_session.add(target)
        db_session.flush()

        db_session.add(ScannerRun(scan_id=target.id, scanner_name="semgrep", status="completed"))
        db_session.add(ScannerRun(scan_id=target.id, scanner_name="gitleaks", status="completed"))
        db_session.add(ScannerRun(scan_id=target.id, scanner_name="osv-scanner", status="completed"))

        # In target:
        # 1. Recurring finding f_recurring
        t_recurring = Finding(
            scan_id=target.id,
            scanner_name="semgrep",
            category="code",
            rule_id="py.xss",
            title="XSS Bug",
            description="XSS",
            severity="medium",
            file_path="views.py",
            start_line=10,
            finding_fingerprint="fp-recurring",
        )
        # 2. Changed finding: f_changed with updated fixed_version and line
        t_changed = Finding(
            scan_id=target.id,
            scanner_name="osv-scanner",
            category="dependency",
            rule_id="CVE-2023-1111",
            title="Vulnerable Lib (Updated)",
            description="Dep bug",
            severity="high",
            package_name="lib-a",
            package_version="1.0.0",
            fixed_version="1.2.0",  # changed
            finding_fingerprint="fp-changed",
        )
        # 3. New finding
        t_new = Finding(
            scan_id=target.id,
            scanner_name="semgrep",
            category="code",
            rule_id="py.sqli",
            title="SQL Injection",
            description="SQLi",
            severity="high",
            file_path="models.py",
            start_line=25,
            finding_fingerprint="fp-new-finding",
        )
        db_session.add_all([t_recurring, t_changed, t_new])
        db_session.commit()

        result = LifecycleService.compare_scans(db_session, target, baseline)

        assert result.summary["new"] == 1
        assert result.summary["recurring"] == 1
        assert result.summary["resolved"] == 1
        assert result.summary["changed"] == 1
        assert result.summary["unconfirmed"] == 0

        assert result.new_findings[0].rule_id == "py.sqli"
        assert result.recurring_findings[0].rule_id == "py.xss"
        assert result.resolved_findings[0].rule_id == "generic-api-key"
        assert result.changed_findings[0].rule_id == "CVE-2023-1111"
        assert any(ch.field == "fixed_version" for ch in result.changed_findings[0].changes)

    def test_no_false_resolution_when_scanner_failed(self, db_session, test_repo):
        """Verify baseline findings are NOT marked resolved if target scanner failed or was missing."""
        baseline = Scan(repository_id=test_repo.id, project_name=test_repo.project_name, source_type="github", status="completed")
        db_session.add(baseline)
        db_session.flush()

        db_session.add(ScannerRun(scan_id=baseline.id, scanner_name="semgrep", status="completed"))
        b_finding = Finding(
            scan_id=baseline.id,
            scanner_name="semgrep",
            category="code",
            rule_id="py.sqli",
            title="SQL Injection",
            description="SQLi",
            severity="high",
            file_path="db.py",
            finding_fingerprint="fp-sqli",
        )
        db_session.add(b_finding)
        db_session.commit()

        # Target scan where semgrep FAILED
        target = Scan(repository_id=test_repo.id, project_name=test_repo.project_name, source_type="github", status="partial")
        db_session.add(target)
        db_session.flush()

        db_session.add(ScannerRun(
            scan_id=target.id,
            scanner_name="semgrep",
            status="failed",
            error_message="Semgrep CLI exited with crash",
        ))
        db_session.commit()

        result = LifecycleService.compare_scans(db_session, target, baseline)

        # MUST NOT be marked resolved! Must be marked unconfirmed!
        assert result.summary["resolved"] == 0
        assert result.summary["unconfirmed"] == 1
        assert result.unconfirmed_findings[0].rule_id == "py.sqli"
        assert any("semgrep" in note.lower() for note in result.comparability_notes)

    def test_zero_finding_scan_resolves_all_when_scanners_succeeded(self, db_session, test_repo):
        """Verify all baseline findings resolve when target scan completes successfully with 0 findings."""
        baseline = Scan(repository_id=test_repo.id, project_name=test_repo.project_name, source_type="github", status="completed")
        db_session.add(baseline)
        db_session.flush()

        db_session.add(ScannerRun(scan_id=baseline.id, scanner_name="gitleaks", status="completed"))
        f_leak = Finding(
            scan_id=baseline.id,
            scanner_name="gitleaks",
            category="secret",
            rule_id="generic-secret",
            title="Secret",
            description="Secret",
            severity="critical",
            file_path=".env",
            finding_fingerprint="fp-secret",
        )
        db_session.add(f_leak)
        db_session.commit()

        # Target clean scan with zero findings
        target = Scan(repository_id=test_repo.id, project_name=test_repo.project_name, source_type="github", status="completed")
        db_session.add(target)
        db_session.flush()

        db_session.add(ScannerRun(scan_id=target.id, scanner_name="gitleaks", status="completed", findings_count=0))
        db_session.commit()

        result = LifecycleService.compare_scans(db_session, target, baseline)

        assert result.summary["resolved"] == 1
        assert result.summary["recurring"] == 0
        assert result.summary["new"] == 0
        assert result.summary["total_target"] == 0
        assert result.resolved_findings[0].rule_id == "generic-secret"
