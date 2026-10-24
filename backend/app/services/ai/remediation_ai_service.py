"""
VulnScope AI Remediation and Proposed Fix Service.
Coordinates finding context sanitization, provider invocation, schema validation,
unified diff patch validation, and rescan verification tracking.
"""

from datetime import datetime, timezone
import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional
from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.base import utc_now
from app.models.finding import Finding
from app.models.remediation_proposal import RemediationProposal
from app.models.scan import Scan
from app.services.ai.factory import get_ai_provider
from app.services.ai.patch_validator import PatchValidator
from app.services.ai.provider import (
    AIConfigurationError,
    AIProviderError,
    AIRateLimitError,
    AITimeoutError,
    AIValidationError,
    FindingContext,
)
from app.services.ai.sanitizer import RedactionService
from app.services.ai.schemas import AIRemediationResponseSchema, AIPatchResponseSchema
from app.services.lifecycle_service import LifecycleService
from app.services.remediation_service import RemediationService
from app.services.risk_scorer import RiskScorer
from app.services.workspace import workspace_manager

logger = logging.getLogger(__name__)


class AIRemediationService:
    """
    Manages AI explanations and proposed fix patches with defense-in-depth safety controls.
    """

    @classmethod
    def _get_workspace_source_dir(cls, scan: Scan) -> Optional[Path]:
        """Resolve workspace source directory if workspace still exists."""
        if not scan.workspace_id:
            return None
        workspaces_root = settings.get_resolved_workspaces_dir()
        ws_dir = workspaces_root / scan.workspace_id / "source"
        if ws_dir.is_dir():
            return ws_dir
        return None

    @classmethod
    def _build_finding_context(
        cls,
        scan: Scan,
        finding: Finding,
        workspace_source_dir: Optional[Path],
    ) -> FindingContext:
        """
        Assemble bounded, sanitized context for finding remediation.
        """
        # Ensure Phase 4 risk score
        if finding.risk_score is None:
            risk_exp = RiskScorer.score_finding(finding)
            finding.risk_score = risk_exp.score
            finding.priority = risk_exp.priority
        else:
            risk_exp = RiskScorer.score_finding(finding)

        # Get deterministic guidance as baseline
        det_guidance = RemediationService.get_guidance_for_finding(finding)

        # Extract bounded source snippet only when category is 'code' and file exists
        source_snippet = None
        if finding.category == "code" and finding.file_path and workspace_source_dir:
            source_snippet = RedactionService.extract_source_snippet(
                workspace_source_dir=workspace_source_dir,
                rel_file_path=finding.file_path,
                start_line=finding.start_line,
                end_line=finding.end_line,
                max_lines=settings.ai_max_snippet_lines,
                max_bytes=settings.ai_max_snippet_bytes,
            )

        # Sanitize text fields
        clean_desc = RedactionService.redact_secrets(finding.description)
        clean_title = RedactionService.redact_secrets(finding.title)

        return FindingContext(
            finding_id=finding.id,
            scan_id=scan.id,
            category=finding.category or "code",
            rule_id=finding.rule_id,
            title=clean_title,
            description=clean_desc,
            scanner_name=finding.scanner_name,
            original_severity=finding.severity,
            risk_score=finding.risk_score,
            risk_priority=finding.priority,
            risk_reason=risk_exp.reason,
            package_name=finding.package_name,
            package_version=finding.package_version,
            ecosystem=finding.ecosystem,
            fixed_version=finding.fixed_version,
            advisory_url=finding.advisory_url,
            file_path=finding.file_path,
            start_line=finding.start_line,
            end_line=finding.end_line,
            source_snippet=source_snippet,
            deterministic_guidance_summary=det_guidance.summary,
            deterministic_steps=det_guidance.steps,
        )

    @classmethod
    def _create_deterministic_fallback_remediation(
        cls,
        finding: Finding,
        note: str = "AI provider unavailable; using verified deterministic Phase 4 guidance.",
    ) -> AIRemediationResponseSchema:
        """
        Generate structured response from Phase 4 deterministic guidance when AI is unavailable.
        """
        det = RemediationService.get_guidance_for_finding(finding)
        category = (finding.category or "code").lower()
        patch_app = category == "code" and finding.file_path is not None and not RedactionService.is_sensitive_file(finding.file_path)

        caveats = list(det.caveats)
        caveats.append(note)

        impact = f"Potential security impact related to {finding.rule_id} with severity {finding.severity}."
        if category == "secret":
            impact = "Unauthorized access to internal systems, credentials leakage, or account compromise."
        elif category == "dependency":
            impact = f"Known public vulnerability affecting {finding.package_name or 'dependency'}."

        return AIRemediationResponseSchema(
            explanation=det.summary,
            likely_root_cause=f"Identified {finding.category or 'security'} pattern matching rule '{finding.rule_id}'.",
            potential_impact=impact,
            remediation_steps=det.steps,
            secure_coding_pattern=det.safer_alternative,
            testing_recommendations=[
                "Run unit and regression test suite to ensure functionality remains unchanged.",
                f"Rescan repository with {finding.scanner_name} to confirm resolution.",
            ],
            caveats_and_assumptions=caveats,
            patch_appropriate=patch_app,
        )

    @classmethod
    async def generate_or_get_remediation(
        cls,
        db: Session,
        scan: Scan,
        finding: Finding,
        allow_remote: bool = False,
    ) -> RemediationProposal:
        """
        Generate or retrieve AI-assisted remediation proposal for a finding.
        """
        # Validate finding belongs to scan
        if finding.scan_id != scan.id:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Finding '{finding.id}' does not belong to scan '{scan.id}'.",
            )

        # Check remote opt-in requirement
        is_remote = settings.is_ai_remote()
        if is_remote and settings.ai_remote_opt_in_required and not allow_remote:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=(
                    "Remote AI processing requires explicit opt-in. "
                    "Set allow_remote=true to consent to transmitting sanitized context to configured external provider."
                ),
            )

        workspace_source = cls._get_workspace_source_dir(scan)
        context = cls._build_finding_context(scan, finding, workspace_source)

        provider = get_ai_provider()
        metadata = provider.get_metadata()
        provider_name = metadata.get("provider", "disabled")
        model_name = metadata.get("model", "none")

        remediation_result: Optional[AIRemediationResponseSchema] = None

        if provider.is_available():
            try:
                remediation_result = await provider.generate_remediation(context)
            except (AITimeoutError, AIRateLimitError, AIProviderError, AIValidationError) as exc:
                logger.warning("AI provider %s error: %s. Falling back to deterministic guidance.", provider_name, exc)
                remediation_result = cls._create_deterministic_fallback_remediation(
                    finding, note=f"AI provider {provider_name} encountered an error ({type(exc).__name__}); falling back to deterministic guidance."
                )
                provider_name = "fallback"
                model_name = "deterministic-phase4"
        else:
            remediation_result = cls._create_deterministic_fallback_remediation(
                finding, note="AI features are disabled or unconfigured; using deterministic Phase 4 guidance."
            )
            provider_name = "fallback"
            model_name = "deterministic-phase4"

        # Check if proposal record already exists
        existing_stmt = select(RemediationProposal).where(
            RemediationProposal.scan_id == scan.id,
            RemediationProposal.finding_id == finding.id,
        )
        proposal = db.scalars(existing_stmt).first()

        if not proposal:
            proposal = RemediationProposal(
                scan_id=scan.id,
                finding_id=finding.id,
                finding_fingerprint=finding.finding_fingerprint,
                status="proposed",
                provider=provider_name,
                model_name=model_name,
                explanation=remediation_result.explanation,
                likely_root_cause=remediation_result.likely_root_cause,
                potential_impact=remediation_result.potential_impact,
                secure_coding_pattern=remediation_result.secure_coding_pattern,
                patch_appropriate=remediation_result.patch_appropriate,
                target_file_path=finding.file_path,
            )
            proposal.remediation_steps = remediation_result.remediation_steps
            proposal.testing_recommendations = remediation_result.testing_recommendations
            proposal.caveats_and_assumptions = remediation_result.caveats_and_assumptions
            db.add(proposal)
        else:
            # Update proposal fields
            proposal.provider = provider_name
            proposal.model_name = model_name
            proposal.explanation = remediation_result.explanation
            proposal.likely_root_cause = remediation_result.likely_root_cause
            proposal.potential_impact = remediation_result.potential_impact
            proposal.secure_coding_pattern = remediation_result.secure_coding_pattern
            proposal.patch_appropriate = remediation_result.patch_appropriate
            proposal.remediation_steps = remediation_result.remediation_steps
            proposal.testing_recommendations = remediation_result.testing_recommendations
            proposal.caveats_and_assumptions = remediation_result.caveats_and_assumptions
            proposal.updated_at = utc_now()

        db.commit()
        db.refresh(proposal)
        return proposal

    @classmethod
    async def generate_fix_proposal(
        cls,
        db: Session,
        scan: Scan,
        finding: Finding,
        allow_remote: bool = False,
    ) -> RemediationProposal:
        """
        Generate candidate unified diff patch for a code finding.
        Validates the patch before storing it.
        """
        # Validate finding belongs to scan
        if finding.scan_id != scan.id:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Finding '{finding.id}' does not belong to scan '{scan.id}'.",
            )

        # Disallow code patches for secrets or dependencies
        category = (finding.category or "code").lower()
        if category in ("secret", "dependency"):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=(
                    f"Code patch generation is not supported for '{category}' findings. "
                    "Use verified remediation steps to rotate secrets or update package dependencies."
                ),
            )

        if not finding.file_path:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Finding has no associated file path; code patch cannot be generated.",
            )

        # Check remote opt-in requirement
        is_remote = settings.is_ai_remote()
        if is_remote and settings.ai_remote_opt_in_required and not allow_remote:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Remote AI processing requires explicit opt-in (allow_remote=true).",
            )

        provider = get_ai_provider()
        if not provider.is_available():
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="AI provider is not configured or currently unavailable. Cannot generate code patch.",
            )

        workspace_source = cls._get_workspace_source_dir(scan)
        context = cls._build_finding_context(scan, finding, workspace_source)

        try:
            patch_result = await provider.generate_patch(context)
        except (AITimeoutError, AIRateLimitError, AIProviderError, AIValidationError) as exc:
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=f"AI provider failed to generate fix patch: {exc}",
            ) from exc

        # Validate the generated diff
        val_result = PatchValidator.validate_patch(
            diff_content=patch_result.diff_content,
            expected_rel_path=finding.file_path,
            workspace_source_dir=workspace_source,
        )

        # Retrieve or create proposal record
        existing_stmt = select(RemediationProposal).where(
            RemediationProposal.scan_id == scan.id,
            RemediationProposal.finding_id == finding.id,
        )
        proposal = db.scalars(existing_stmt).first()

        metadata = provider.get_metadata()
        provider_name = metadata.get("provider", "ai")
        model_name = metadata.get("model", "default")

        if not proposal:
            proposal = RemediationProposal(
                scan_id=scan.id,
                finding_id=finding.id,
                finding_fingerprint=finding.finding_fingerprint,
                provider=provider_name,
                model_name=model_name,
                explanation=f"Proposed fix for {finding.title}",
                likely_root_cause="Automated fix generation",
                potential_impact="Remediate code vulnerability via unified diff patch",
                patch_appropriate=True,
                target_file_path=finding.file_path,
                change_summary=patch_result.change_summary,
            )
            proposal.remediation_steps = ["Review the unified diff carefully.", "Apply patch in local environment.", "Rescan to verify resolution."]
            db.add(proposal)
        else:
            proposal.patch_appropriate = True
            proposal.change_summary = patch_result.change_summary
            proposal.target_file_path = finding.file_path

        if val_result.is_valid and val_result.sanitized_diff:
            proposal.status = "proposed"
            proposal.diff_content = val_result.sanitized_diff
            proposal.validation_error = None
        else:
            proposal.status = "validation_failed"
            proposal.diff_content = patch_result.diff_content
            proposal.validation_error = val_result.error or "Patch validation failed"

        proposal.updated_at = utc_now()
        db.commit()
        db.refresh(proposal)
        return proposal

    @classmethod
    def update_proposal_status(
        cls,
        db: Session,
        proposal: RemediationProposal,
        new_status: str,
        user_notes: Optional[str] = None,
    ) -> RemediationProposal:
        """
        Advance or update proposal lifecycle status with transition validation.
        """
        clean_status = new_status.strip().lower()
        allowed_statuses = {"reviewed", "rejected", "verification_pending", "downloaded"}

        if clean_status not in allowed_statuses:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid status '{new_status}'. Allowed transitions: {', '.join(sorted(allowed_statuses))}",
            )

        # Disallow reviewing or downloading an invalid patch
        if proposal.status == "validation_failed" and clean_status in ("reviewed", "downloaded"):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Cannot review or download a patch that failed structural validation.",
            )

        proposal.status = clean_status
        if user_notes:
            proposal.user_notes = user_notes
        proposal.updated_at = utc_now()

        db.commit()
        db.refresh(proposal)
        return proposal

    @classmethod
    def check_rescan_verification(
        cls,
        db: Session,
        proposal: RemediationProposal,
    ) -> str:
        """
        Check if an eligible subsequent scan of the same repository lineage confirms the finding is resolved.
        Distinguishes:
        - 'verified_by_rescan': comparable successful scan no longer detects the finding.
        - 'unconfirmed': coverage incomplete or rescan inconclusive.
        """
        scan = proposal.scan
        if not scan or not scan.repository_id:
            return proposal.status

        finding = proposal.finding
        if not finding or not finding.finding_fingerprint:
            return proposal.status

        # Find subsequent scans for the same repository
        subsequent_scans_stmt = (
            select(Scan)
            .where(
                Scan.repository_id == scan.repository_id,
                Scan.created_at > scan.created_at,
                Scan.status.in_(["completed", "partial"]),
            )
            .order_by(Scan.created_at.asc())
        )
        later_scans = db.scalars(subsequent_scans_stmt).all()

        for later_scan in later_scans:
            # Check scanner coverage for finding's scanner
            scanner_run = next(
                (sr for sr in later_scan.scanner_runs if sr.scanner_name.lower() == finding.scanner_name.lower()),
                None,
            )

            if not scanner_run or scanner_run.status != "completed":
                # Scanner did not run or failed; resolution cannot be confirmed
                continue

            # Check if finding fingerprint is still present in later scan
            still_present = any(
                f.finding_fingerprint == finding.finding_fingerprint
                for f in later_scan.findings
            )

            if not still_present:
                proposal.status = "verified_by_rescan"
                proposal.updated_at = utc_now()
                db.commit()
                db.refresh(proposal)
                return "verified_by_rescan"

        return proposal.status
