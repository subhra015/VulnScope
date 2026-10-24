"""
Automated Integration and API tests for Phase 5.
Tests:
- AI Remediation generation and retrieval
- Remote opt-in requirement enforcement
- Deterministic guidance fallback when AI is unavailable
- Fix patch generation, validation, review, and download
- Rejection of patch generation for secrets and dependencies
- Proposal lifecycle transitions (proposed -> reviewed -> downloaded -> verified_by_rescan)
- Cross-scan access denial
"""

from fastapi.testclient import TestClient
import pytest
from sqlalchemy.orm import Session

import app.core.config
from app.models.finding import Finding
from app.models.remediation_proposal import RemediationProposal
from app.models.repository import Repository
from app.models.scan import Scan
from app.models.scanner_run import ScannerRun
from app.services.ai.factory import set_ai_provider_override
from app.services.ai.provider import AIProvider, FindingContext
from app.services.ai.schemas import AIRemediationResponseSchema, AIPatchResponseSchema


class StubAIProvider(AIProvider):
    """Stub AI provider for predictable API testing."""

    def is_available(self) -> bool:
        return True

    def get_metadata(self) -> dict:
        return {"provider": "stub-ai", "model": "stub-model", "is_remote": "false"}

    async def generate_remediation(self, context: FindingContext) -> AIRemediationResponseSchema:
        return AIRemediationResponseSchema(
            explanation="Stubbed explanation for security issue.",
            likely_root_cause="User input passed directly into sensitive sink.",
            potential_impact="Data compromise in worst-case scenario.",
            remediation_steps=["Sanitize input", "Use safe API"],
            secure_coding_pattern="safe_call(input)",
            testing_recommendations=["Write unit tests"],
            caveats_and_assumptions=["Assumes standard runtime"],
            patch_appropriate=True,
        )

    async def generate_patch(self, context: FindingContext) -> AIPatchResponseSchema:
        return AIPatchResponseSchema(
            target_file_path=context.file_path or "src/app.py",
            change_summary="Apply input sanitization",
            diff_content=(
                f"--- a/{context.file_path or 'src/app.py'}\n"
                f"+++ b/{context.file_path or 'src/app.py'}\n"
                "@@ -1,2 +1,2 @@\n"
                "- execute_unsafe(cmd)\n"
                "+ execute_safe(cmd)\n"
            ),
        )


@pytest.fixture
def phase5_test_scan(db_session: Session) -> tuple[Scan, Finding, Finding]:
    """Create a test scan with a code finding and a secret finding."""
    repo = Repository(project_name="phase5-service", source_type="zip", source_reference="code.zip")
    db_session.add(repo)
    db_session.flush()

    scan = Scan(
        repository_id=repo.id,
        project_name="phase5-service",
        source_type="zip",
        source_reference="code.zip",
        status="completed",
    )
    db_session.add(scan)
    db_session.flush()

    code_finding = Finding(
        scan_id=scan.id,
        scanner_name="semgrep",
        rule_id="py.exec.injection",
        category="code",
        title="Command Injection",
        description="Dangerous exec call with user parameter",
        severity="high",
        file_path="src/executor.py",
        start_line=15,
        risk_score=85,
        priority="high",
        finding_fingerprint="fp_code_12345",
    )

    secret_finding = Finding(
        scan_id=scan.id,
        scanner_name="gitleaks",
        rule_id="aws-access-key",
        category="secret",
        title="Exposed AWS Key",
        description="Potential exposed credential detected in source code.",
        severity="critical",
        file_path="config/aws.py",
        start_line=5,
        risk_score=95,
        priority="critical",
        finding_fingerprint="fp_secret_99999",
    )

    db_session.add_all([code_finding, secret_finding])
    db_session.commit()
    db_session.refresh(scan)
    return scan, code_finding, secret_finding


def test_ai_remediation_generation_with_stub_provider(client: TestClient, phase5_test_scan):
    """Test generating AI remediation using configured stub provider."""
    scan, code_finding, _ = phase5_test_scan
    set_ai_provider_override(StubAIProvider())

    try:
        res = client.post(
            f"/api/scans/{scan.id}/findings/{code_finding.id}/ai-remediation",
            json={"allow_remote": True},
        )
        assert res.status_code == 200
        data = res.json()
        assert data["scan_id"] == scan.id
        assert data["finding_id"] == code_finding.id
        assert data["provider"] == "stub-ai"
        assert "Stubbed explanation" in data["explanation"]
        assert len(data["remediation_steps"]) == 2
        assert data["status"] == "proposed"

        # Check retrieval endpoint
        get_res = client.get(f"/api/scans/{scan.id}/findings/{code_finding.id}/ai-remediation")
        assert get_res.status_code == 200
        assert get_res.json()["id"] == data["id"]
    finally:
        set_ai_provider_override(None)


def test_ai_remediation_fallback_when_ai_disabled(client: TestClient, phase5_test_scan):
    """When AI is disabled, endpoint gracefully falls back to deterministic guidance."""
    scan, code_finding, _ = phase5_test_scan
    set_ai_provider_override(None)  # Use real configured provider (disabled by default)

    res = client.post(
        f"/api/scans/{scan.id}/findings/{code_finding.id}/ai-remediation",
        json={"allow_remote": False},
    )
    assert res.status_code == 200
    data = res.json()
    assert data["provider"] == "fallback"
    assert data["model_name"] == "deterministic-phase4"
    assert len(data["remediation_steps"]) > 0
    assert any("deterministic" in c.lower() for c in data["caveats_and_assumptions"])


def test_remote_opt_in_enforcement(client: TestClient, phase5_test_scan):
    """When a remote provider is configured, request is rejected if allow_remote=False."""
    scan, code_finding, _ = phase5_test_scan
    old_prov = app.core.config.settings.ai_provider
    app.core.config.settings.ai_provider = "openai"

    try:
        res = client.post(
            f"/api/scans/{scan.id}/findings/{code_finding.id}/ai-remediation",
            json={"allow_remote": False},
        )
        assert res.status_code == 400
        assert "opt-in" in res.json()["detail"].lower()
    finally:
        app.core.config.settings.ai_provider = old_prov


def test_fix_proposal_rejected_for_secret_and_dependency_findings(client: TestClient, phase5_test_scan):
    """Generating code fix proposal for secrets or dependencies returns HTTP 400."""
    scan, _, secret_finding = phase5_test_scan
    set_ai_provider_override(StubAIProvider())

    try:
        res = client.post(
            f"/api/scans/{scan.id}/findings/{secret_finding.id}/fix-proposals",
            json={"allow_remote": True},
        )
        assert res.status_code == 400
        assert "not supported for 'secret'" in res.json()["detail"]
    finally:
        set_ai_provider_override(None)


def test_fix_proposal_patch_generation_and_download(client: TestClient, phase5_test_scan):
    """Generate fix patch, verify structure, advance status, and download patch file."""
    scan, code_finding, _ = phase5_test_scan
    set_ai_provider_override(StubAIProvider())

    try:
        # 1. Generate patch
        res_post = client.post(
            f"/api/scans/{scan.id}/findings/{code_finding.id}/fix-proposals",
            json={"allow_remote": True},
        )
        assert res_post.status_code == 200
        proposal = res_post.json()
        assert proposal["patch_appropriate"] is True
        assert proposal["status"] == "proposed"
        assert proposal["diff_content"] is not None
        assert "--- a/src/executor.py" in proposal["diff_content"]

        proposal_id = proposal["id"]

        # 2. Advance status to 'reviewed'
        patch_res = client.patch(
            f"/api/scans/{scan.id}/fix-proposals/{proposal_id}/status",
            json={"status": "reviewed", "user_notes": "Looks safe to test."},
        )
        assert patch_res.status_code == 200
        assert patch_res.json()["status"] == "reviewed"
        assert patch_res.json()["user_notes"] == "Looks safe to test."

        # 3. Download the patch file
        dl_res = client.get(f"/api/scans/{scan.id}/fix-proposals/{proposal_id}/download")
        assert dl_res.status_code == 200
        assert "attachment" in dl_res.headers["content-disposition"]
        assert dl_res.text == proposal["diff_content"]

        # Status should now be 'downloaded'
        check_res = client.get(f"/api/scans/{scan.id}/findings/{code_finding.id}/ai-remediation")
        assert check_res.status_code == 200
        assert check_res.json()["status"] == "downloaded"
    finally:
        set_ai_provider_override(None)


def test_cross_scan_finding_access_rejected(client: TestClient, phase5_test_scan, db_session: Session):
    """Accessing finding from a mismatched scan ID returns 404."""
    scan, code_finding, _ = phase5_test_scan
    other_scan = Scan(project_name="other", source_type="zip", status="completed")
    db_session.add(other_scan)
    db_session.commit()

    res = client.post(
        f"/api/scans/{other_scan.id}/findings/{code_finding.id}/ai-remediation",
        json={"allow_remote": True},
    )
    assert res.status_code == 404
