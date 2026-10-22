"""
Tests for SQLAlchemy database models and relationships.
"""

from datetime import datetime, timezone
from sqlalchemy.orm import Session
from app.models.repository import Repository
from app.models.scan import Scan
from app.models.finding import Finding


def test_repository_model_creation(db_session: Session):
    """Test Repository model persistence and attributes."""
    repo = Repository(
        project_name="security-test-project",
        source_type="github",
        source_reference="https://github.com/test/repo",
    )
    db_session.add(repo)
    db_session.commit()
    db_session.refresh(repo)

    assert repo.id is not None
    assert repo.project_name == "security-test-project"
    assert repo.source_type == "github"
    assert repo.created_at.tzinfo is not None


def test_scan_repository_relationship(db_session: Session):
    """Test relationship between Scan and Repository."""
    repo = Repository(
        project_name="rel-test-project",
        source_type="zip",
    )
    db_session.add(repo)
    db_session.commit()

    scan = Scan(
        repository_id=repo.id,
        project_name=repo.project_name,
        source_type=repo.source_type,
        status="created",
    )
    db_session.add(scan)
    db_session.commit()
    db_session.refresh(scan)

    assert scan.repository is not None
    assert scan.repository.id == repo.id
    assert len(repo.scans) == 1
    assert repo.scans[0].id == scan.id


def test_finding_scan_relationship_and_cascade(db_session: Session):
    """Test Finding model and cascade deletion when parent scan is deleted."""
    scan = Scan(
        project_name="cascade-test",
        source_type="github",
        status="created",
    )
    db_session.add(scan)
    db_session.commit()

    finding = Finding(
        scan_id=scan.id,
        finding_fingerprint="sha256-test-fingerprint",
        scanner_name="semgrep",
        rule_id="rules.security.sql_injection",
        title="Potential SQL Injection",
        description="User input passed directly into raw query",
        severity="high",
        confidence="high",
        file_path="src/database.py",
        start_line=42,
        end_line=45,
    )
    db_session.add(finding)
    db_session.commit()
    db_session.refresh(scan)

    assert len(scan.findings) == 1
    assert scan.findings[0].scanner_name == "semgrep"
    assert scan.findings[0].severity == "high"

    # Delete scan and verify cascade deletion of finding
    finding_id = finding.id
    db_session.delete(scan)
    db_session.commit()

    remaining_finding = db_session.get(Finding, finding_id)
    assert remaining_finding is None
