"""
Scans API router.
Manages scan record creation, listing, status retrieval, background scan execution,
normalized findings querying with risk prioritization, remediation guidance,
and finding lifecycle comparison.
"""

import json
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from sqlalchemy import case, func, select
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.models.base import utc_now
from app.models.finding import Finding
from app.models.remediation_proposal import RemediationProposal
from app.models.repository import Repository
from app.models.scan import Scan
from app.models.scanner_run import ScannerRun
from app.schemas.finding import (
    FindingDetailResponse,
    FindingResponse,
    FindingsListResponse,
    RemediationGuidanceSchema,
    RiskExplanationSchema,
    RiskSummaryResponse,
    ScanComparisonResponse,
    ScoringFactorSchema,
)
from app.schemas.scan import (
    ScanCreateRequest,
    ScanDetailResponse,
    ScanResponse,
    ScanRunResponse,
)
from app.services.ai.remediation_ai_service import AIRemediationService
from app.services.ai.schemas import (
    AIPatchRequest,
    AIRemediationRequest,
    RemediationProposalResponse,
    UpdateProposalStatusRequest,
)
from app.services.lifecycle_service import (
    LifecycleService,
    ScanComparabilityError,
)
from app.services.remediation_service import RemediationService
from app.services.report_service import ReportService
from app.services.risk_scorer import RiskScorer
from app.services.scan_orchestrator import ScanOrchestratorError, scan_orchestrator

router = APIRouter(prefix="/scans", tags=["scans"])


def _calculate_findings_summary(findings: List[Finding]) -> dict:
    """Compute summary counts across categories, severities, and priorities."""
    summary = {
        "total": len(findings),
        "code": 0,
        "secret": 0,
        "dependency": 0,
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
        "priority_critical": 0,
        "priority_high": 0,
        "priority_medium": 0,
        "priority_low": 0,
    }
    for f in findings:
        cat = (f.category or "code").lower()
        if cat in summary:
            summary[cat] += 1
        sev = (f.severity or "medium").lower()
        if sev in summary:
            summary[sev] += 1

        # Priority tally
        prio = (f.priority or "").lower()
        if not prio and f.risk_score is None:
            exp = RiskScorer.score_finding(f)
            prio = exp.priority
        key = f"priority_{prio}"
        if key in summary:
            summary[key] += 1

    return summary


def _ensure_finding_scores(finding: Finding) -> None:
    """Ensure finding has risk_score and priority populated."""
    if finding.risk_score is None or finding.priority is None:
        exp = RiskScorer.score_finding(finding)
        finding.risk_score = exp.score
        finding.priority = exp.priority


@router.get("", response_model=List[ScanResponse])
def list_scans(db: Session = Depends(get_db)) -> List[ScanResponse]:
    """
    List all scan records, ordered by creation time (newest first).
    Returns an empty list if no scans have been recorded.
    """
    stmt = select(Scan).order_by(Scan.created_at.desc())
    scans = db.scalars(stmt).all()
    return list(scans)


@router.post("", response_model=ScanResponse, status_code=status.HTTP_201_CREATED)
def create_scan(
    payload: ScanCreateRequest,
    db: Session = Depends(get_db),
) -> ScanResponse:
    """
    Create a new scan record in the database.
    """
    repo_stmt = select(Repository).where(
        Repository.project_name == payload.project_name,
        Repository.source_type == payload.source_type.value,
    )
    repo = db.scalars(repo_stmt).first()

    if not repo:
        repo = Repository(
            project_name=payload.project_name,
            source_type=payload.source_type.value,
            source_reference=payload.source_reference,
        )
        db.add(repo)
        db.flush()
    elif payload.source_reference and not repo.source_reference:
        repo.source_reference = payload.source_reference
        db.flush()

    new_scan = Scan(
        repository_id=repo.id,
        project_name=payload.project_name,
        source_type=payload.source_type.value,
        source_reference=payload.source_reference,
        status="created",
    )
    db.add(new_scan)
    db.commit()
    db.refresh(new_scan)

    return new_scan


@router.get("/{scan_id}", response_model=ScanDetailResponse)
def get_scan(
    scan_id: str,
    db: Session = Depends(get_db),
) -> ScanDetailResponse:
    """
    Retrieve details for a specific scan record by its ID, including individual
    scanner runs, normalized findings, and metrics summary.
    """
    stmt = select(Scan).where(Scan.id == scan_id)
    scan = db.scalars(stmt).first()

    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan record with ID '{scan_id}' not found",
        )

    # Ensure all findings have risk scores populated
    for f in scan.findings:
        _ensure_finding_scores(f)

    # Build response model with computed findings summary
    response = ScanDetailResponse.model_validate(scan)
    response.findings_summary = _calculate_findings_summary(scan.findings)
    return response


@router.post("/{scan_id}/run", response_model=ScanRunResponse, status_code=status.HTTP_202_ACCEPTED)
def run_scan(
    scan_id: str,
    db: Session = Depends(get_db),
) -> ScanRunResponse:
    """
    Trigger multi-engine security scanning (Semgrep, Gitleaks, OSV-Scanner)
    on a validated repository snapshot.
    Returns HTTP 202 Accepted and executes asynchronously in background.
    """
    stmt = select(Scan).where(Scan.id == scan_id)
    scan = db.scalars(stmt).first()

    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan record with ID '{scan_id}' not found",
        )

    if scan.intake_status != "ready":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Cannot scan project. Intake status is '{scan.intake_status}'. Intake must be 'ready'.",
        )

    if scan.status == "running" or scan_orchestrator.is_scan_running(scan_id):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Scan '{scan_id}' is already currently executing.",
        )

    try:
        scan_orchestrator.trigger_scan(scan_id)
    except ScanOrchestratorError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc

    return ScanRunResponse(
        scan_id=scan_id,
        status="running",
        message="Security scan execution started in background.",
    )


@router.get("/{scan_id}/findings", response_model=FindingsListResponse)
def get_scan_findings(
    scan_id: str,
    scanner: Optional[str] = Query(None, description="Filter by scanner name ('semgrep', 'gitleaks', 'osv-scanner')"),
    category: Optional[str] = Query(None, description="Filter by category ('code', 'secret', 'dependency')"),
    severity: Optional[str] = Query(None, description="Filter by severity ('critical', 'high', 'medium', 'low', 'info')"),
    priority: Optional[str] = Query(None, description="Filter by risk priority ('critical', 'high', 'medium', 'low')"),
    sort_by: str = Query("priority", description="Sort field ('priority', 'risk_score', 'severity', 'created_at')"),
    sort_order: str = Query("desc", description="Sort direction ('asc', 'desc')"),
    baseline_scan_id: Optional[str] = Query(None, description="Optional baseline scan ID to evaluate lifecycle statuses"),
    limit: int = Query(50, ge=1, le=500, description="Page limit"),
    offset: int = Query(0, ge=0, description="Page offset"),
    db: Session = Depends(get_db),
) -> FindingsListResponse:
    """
    List normalized findings for a specific scan with deterministic risk prioritization,
    filtering, pagination, and optional lifecycle status annotation.
    """
    # Verify scan exists
    scan_stmt = select(Scan).where(Scan.id == scan_id)
    scan = db.scalars(scan_stmt).first()
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan record with ID '{scan_id}' not found",
        )

    # Backfill scores for any unscored findings in this scan
    all_findings_stmt = select(Finding).where(Finding.scan_id == scan_id)
    all_findings = db.scalars(all_findings_stmt).all()
    needs_flush = False
    for f in all_findings:
        if f.risk_score is None or f.priority is None:
            _ensure_finding_scores(f)
            needs_flush = True
    if needs_flush:
        db.flush()

    base_query = select(Finding).where(Finding.scan_id == scan_id)
    count_query = select(func.count(Finding.id)).where(Finding.scan_id == scan_id)

    if scanner:
        base_query = base_query.where(Finding.scanner_name == scanner.strip().lower())
        count_query = count_query.where(Finding.scanner_name == scanner.strip().lower())

    if category:
        base_query = base_query.where(Finding.category == category.strip().lower())
        count_query = count_query.where(Finding.category == category.strip().lower())

    if severity:
        base_query = base_query.where(Finding.severity == severity.strip().lower())
        count_query = count_query.where(Finding.severity == severity.strip().lower())

    if priority:
        base_query = base_query.where(Finding.priority == priority.strip().lower())
        count_query = count_query.where(Finding.priority == priority.strip().lower())

    # Sorting
    is_desc = sort_order.strip().lower() != "asc"
    if sort_by in ("priority", "risk_score"):
        order_col = Finding.risk_score.desc() if is_desc else Finding.risk_score.asc()
        base_query = base_query.order_by(order_col, Finding.created_at.asc())
    elif sort_by == "severity":
        # Severity rank: critical (4), high (3), medium (2), low (1), info (0)
        sev_rank = case(
            (Finding.severity == "critical", 4),
            (Finding.severity == "high", 3),
            (Finding.severity == "medium", 2),
            (Finding.severity == "low", 1),
            else_=0,
        )
        base_query = base_query.order_by(sev_rank.desc() if is_desc else sev_rank.asc(), Finding.created_at.asc())
    else:
        order_col = Finding.created_at.desc() if is_desc else Finding.created_at.asc()
        base_query = base_query.order_by(order_col)

    total = db.scalar(count_query) or 0
    items = db.scalars(base_query.offset(offset).limit(limit)).all()

    # Determine baseline scan for lifecycle status if available
    baseline_scan: Optional[Scan] = None
    if baseline_scan_id:
        baseline_scan = db.scalars(select(Scan).where(Scan.id == baseline_scan_id)).first()
    else:
        baseline_scan = LifecycleService.find_latest_baseline(db, scan)

    finding_responses: List[FindingResponse] = []
    for f in items:
        resp = FindingResponse.model_validate(f)
        if baseline_scan:
            resp.lifecycle_status = LifecycleService.get_finding_lifecycle_status(db, scan, f, baseline_scan)
        else:
            resp.lifecycle_status = "new"
        finding_responses.append(resp)

    return FindingsListResponse(
        total=total,
        items=finding_responses,
        limit=limit,
        offset=offset,
    )


@router.get("/{scan_id}/findings/{finding_id}", response_model=FindingDetailResponse)
def get_scan_finding_detail(
    scan_id: str,
    finding_id: str,
    db: Session = Depends(get_db),
) -> FindingDetailResponse:
    """
    Retrieve single finding details including full deterministic risk score explanation,
    scoring factors breakdown, missing evidence caveats, and structured remediation guidance.
    Validates scan ownership and returns 404 for missing or mismatched records.
    """
    scan = db.scalars(select(Scan).where(Scan.id == scan_id)).first()
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan record with ID '{scan_id}' not found",
        )

    finding = db.scalars(select(Finding).where(Finding.id == finding_id)).first()
    if not finding or finding.scan_id != scan_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Finding with ID '{finding_id}' not found in scan '{scan_id}'",
        )

    _ensure_finding_scores(finding)

    # Compute risk score explanation
    risk_exp = RiskScorer.score_finding(finding)
    risk_schema = RiskExplanationSchema(
        score=risk_exp.score,
        priority=risk_exp.priority,
        priority_label=risk_exp.priority_label,
        factors=[
            ScoringFactorSchema(
                name=f.name,
                weight=f.weight,
                raw_score=f.raw_score,
                contribution=f.contribution,
                description=f.description,
            )
            for f in risk_exp.factors
        ],
        evidence=risk_exp.evidence,
        reason=risk_exp.reason,
        missing_evidence=risk_exp.missing_evidence,
    )

    # Compute remediation guidance
    guidance = RemediationService.get_guidance_for_finding(finding)
    rem_schema = RemediationGuidanceSchema(
        category=guidance.category,
        summary=guidance.summary,
        steps=guidance.steps,
        unsafe_pattern=guidance.unsafe_pattern,
        safer_alternative=guidance.safer_alternative,
        caveats=guidance.caveats,
        references=guidance.references,
        fixed_version=guidance.fixed_version,
        package_ecosystem=guidance.package_ecosystem,
    )

    # Determine lifecycle status
    lifecycle_status = LifecycleService.get_finding_lifecycle_status(db, scan, finding)

    response = FindingDetailResponse.model_validate(finding)
    response.risk_explanation = risk_schema
    response.remediation = rem_schema
    response.lifecycle_status = lifecycle_status

    # Check for existing AI proposal
    proposal = db.scalars(
        select(RemediationProposal).where(
            RemediationProposal.scan_id == scan_id,
            RemediationProposal.finding_id == finding_id,
        )
    ).first()
    if proposal:
        AIRemediationService.check_rescan_verification(db, proposal)
        response.ai_proposal = RemediationProposalResponse.model_validate(proposal)

    return response


@router.get("/{scan_id}/risk-summary", response_model=RiskSummaryResponse)
def get_scan_risk_summary(
    scan_id: str,
    db: Session = Depends(get_db),
) -> RiskSummaryResponse:
    """
    Retrieve comprehensive risk-priority summary for a scan, including priority distribution,
    severity distribution, category averages, scanner coverage, and coverage caveats.
    """
    scan = db.scalars(select(Scan).where(Scan.id == scan_id)).first()
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan record with ID '{scan_id}' not found",
        )

    findings = scan.findings or []
    for f in findings:
        _ensure_finding_scores(f)

    priority_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    cat_stats: Dict[str, Dict[str, Any]] = {
        "code": {"count": 0, "total_score": 0, "avg_risk_score": 0.0},
        "secret": {"count": 0, "total_score": 0, "avg_risk_score": 0.0},
        "dependency": {"count": 0, "total_score": 0, "avg_risk_score": 0.0},
    }

    scores = []
    for f in findings:
        score = f.risk_score if f.risk_score is not None else 50
        scores.append(score)
        p = (f.priority or "medium").lower()
        if p in priority_counts:
            priority_counts[p] += 1
        s = (f.severity or "medium").lower()
        if s in severity_counts:
            severity_counts[s] += 1

        cat = (f.category or "code").lower()
        if cat in cat_stats:
            cat_stats[cat]["count"] += 1
            cat_stats[cat]["total_score"] += score

    # Compute averages
    for cat_data in cat_stats.values():
        if cat_data["count"] > 0:
            cat_data["avg_risk_score"] = round(cat_data["total_score"] / cat_data["count"], 1)

    mean_score = round(sum(scores) / len(scores), 1) if scores else 0.0
    max_score = max(scores) if scores else 0

    # Scanner coverage and caveats
    scanner_coverage = {sr.scanner_name: sr.status for sr in scan.scanner_runs}
    coverage_notes: List[str] = []

    if scan.status == "partial":
        coverage_notes.append("Scan completed with 'partial' status. One or more scanners failed or timed out.")

    for sr in scan.scanner_runs:
        if sr.status in ("failed", "unavailable", "timed_out"):
            coverage_notes.append(
                f"Scanner '{sr.scanner_name}' had status '{sr.status}' ({sr.error_message or 'execution error'}). Coverage for this tool is incomplete."
            )

    if not findings and scan.status == "completed":
        coverage_notes.append("Zero findings were detected across all configured scanners.")

    return RiskSummaryResponse(
        scan_id=scan_id,
        total_findings=len(findings),
        priority_distribution=priority_counts,
        severity_distribution=severity_counts,
        category_distribution=cat_stats,
        mean_risk_score=mean_score,
        max_risk_score=max_score,
        scanner_coverage=scanner_coverage,
        coverage_notes=coverage_notes,
    )


@router.get("/{scan_id}/comparison/{baseline_scan_id}", response_model=ScanComparisonResponse)
def compare_scans(
    scan_id: str,
    baseline_scan_id: str,
    db: Session = Depends(get_db),
) -> ScanComparisonResponse:
    """
    Compare a target scan against a baseline scan of the same repository lineage.
    Classifies findings into new, recurring, resolved, and changed states.
    Strictly prohibits cross-repository comparisons and prevents false resolution claims.
    """
    target_scan = db.scalars(select(Scan).where(Scan.id == scan_id)).first()
    if not target_scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Target scan record with ID '{scan_id}' not found",
        )

    baseline_scan = db.scalars(select(Scan).where(Scan.id == baseline_scan_id)).first()
    if not baseline_scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Baseline scan record with ID '{baseline_scan_id}' not found",
        )

    # Ensure findings are scored
    for f in (target_scan.findings or []):
        _ensure_finding_scores(f)
    for f in (baseline_scan.findings or []):
        _ensure_finding_scores(f)

    try:
        result = LifecycleService.compare_scans(db, target_scan, baseline_scan)
    except ScanComparabilityError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc

    return ScanComparisonResponse.model_validate(result.to_dict())


# ---------------------------------------------------------------------------
# Phase 5: AI-Assisted Remediation, Safe Fix Previews, and Reports
# ---------------------------------------------------------------------------


@router.post(
    "/{scan_id}/findings/{finding_id}/ai-remediation",
    response_model=RemediationProposalResponse,
    status_code=status.HTTP_200_OK,
    summary="Generate or retrieve AI-assisted explanation and remediation proposal",
)
async def generate_ai_remediation(
    scan_id: str,
    finding_id: str,
    payload: AIRemediationRequest = AIRemediationRequest(),
    db: Session = Depends(get_db),
) -> RemediationProposalResponse:
    """
    Generate structured, AI-assisted explanation and remediation guidance for a specific finding.
    If an AI provider is unavailable, automatically falls back to verified Phase 4 deterministic guidance.
    Enforces remote processing opt-in when configured with an external provider.
    """
    scan = db.scalars(select(Scan).where(Scan.id == scan_id)).first()
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan record with ID '{scan_id}' not found",
        )

    finding = db.scalars(select(Finding).where(Finding.id == finding_id)).first()
    if not finding or finding.scan_id != scan_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Finding with ID '{finding_id}' not found in scan '{scan_id}'",
        )

    proposal = await AIRemediationService.generate_or_get_remediation(
        db=db,
        scan=scan,
        finding=finding,
        allow_remote=payload.allow_remote,
    )

    return RemediationProposalResponse.model_validate(proposal)


@router.get(
    "/{scan_id}/findings/{finding_id}/ai-remediation",
    response_model=RemediationProposalResponse,
    summary="Get existing AI remediation proposal for finding",
)
def get_ai_remediation(
    scan_id: str,
    finding_id: str,
    db: Session = Depends(get_db),
) -> RemediationProposalResponse:
    """
    Retrieve previously generated remediation proposal for a finding.
    Returns 404 if no proposal has been generated yet.
    """
    scan = db.scalars(select(Scan).where(Scan.id == scan_id)).first()
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan record with ID '{scan_id}' not found",
        )

    finding = db.scalars(select(Finding).where(Finding.id == finding_id)).first()
    if not finding or finding.scan_id != scan_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Finding with ID '{finding_id}' not found in scan '{scan_id}'",
        )

    proposal = db.scalars(
        select(RemediationProposal).where(
            RemediationProposal.scan_id == scan_id,
            RemediationProposal.finding_id == finding_id,
        )
    ).first()

    if not proposal:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No remediation proposal has been generated for finding '{finding_id}'",
        )

    AIRemediationService.check_rescan_verification(db, proposal)
    return RemediationProposalResponse.model_validate(proposal)


@router.post(
    "/{scan_id}/findings/{finding_id}/fix-proposals",
    response_model=RemediationProposalResponse,
    status_code=status.HTTP_200_OK,
    summary="Generate proposed unified diff fix patch",
)
async def generate_fix_proposal(
    scan_id: str,
    finding_id: str,
    payload: AIPatchRequest = AIPatchRequest(),
    db: Session = Depends(get_db),
) -> RemediationProposalResponse:
    """
    Generate a proposed source code patch for an individual finding.
    The diff is strictly validated for path safety, syntax, and size before persisting.
    Never modifies original repository files.
    """
    scan = db.scalars(select(Scan).where(Scan.id == scan_id)).first()
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan record with ID '{scan_id}' not found",
        )

    finding = db.scalars(select(Finding).where(Finding.id == finding_id)).first()
    if not finding or finding.scan_id != scan_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Finding with ID '{finding_id}' not found in scan '{scan_id}'",
        )

    proposal = await AIRemediationService.generate_fix_proposal(
        db=db,
        scan=scan,
        finding=finding,
        allow_remote=payload.allow_remote,
    )

    return RemediationProposalResponse.model_validate(proposal)


@router.get(
    "/{scan_id}/findings/{finding_id}/fix-proposals",
    response_model=List[RemediationProposalResponse],
    summary="Get fix proposals for finding",
)
def list_fix_proposals(
    scan_id: str,
    finding_id: str,
    db: Session = Depends(get_db),
) -> List[RemediationProposalResponse]:
    """List all proposal records for finding."""
    proposals = db.scalars(
        select(RemediationProposal)
        .where(
            RemediationProposal.scan_id == scan_id,
            RemediationProposal.finding_id == finding_id,
        )
        .order_by(RemediationProposal.created_at.desc())
    ).all()

    for p in proposals:
        AIRemediationService.check_rescan_verification(db, p)

    return [RemediationProposalResponse.model_validate(p) for p in proposals]


@router.patch(
    "/{scan_id}/fix-proposals/{proposal_id}/status",
    response_model=RemediationProposalResponse,
    summary="Update remediation proposal lifecycle status",
)
def update_proposal_status(
    scan_id: str,
    proposal_id: str,
    payload: UpdateProposalStatusRequest,
    db: Session = Depends(get_db),
) -> RemediationProposalResponse:
    """
    Update the lifecycle status of a proposed remediation (e.g. 'reviewed', 'rejected', 'verification_pending').
    Enforces valid transition paths and authorization.
    """
    proposal = db.scalars(
        select(RemediationProposal).where(
            RemediationProposal.id == proposal_id,
            RemediationProposal.scan_id == scan_id,
        )
    ).first()

    if not proposal:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Proposal with ID '{proposal_id}' not found in scan '{scan_id}'",
        )

    updated = AIRemediationService.update_proposal_status(
        db=db,
        proposal=proposal,
        new_status=payload.status,
        user_notes=payload.user_notes,
    )

    return RemediationProposalResponse.model_validate(updated)


@router.get(
    "/{scan_id}/fix-proposals/{proposal_id}/download",
    summary="Download sanitized proposed patch file",
)
def download_patch(
    scan_id: str,
    proposal_id: str,
    db: Session = Depends(get_db),
) -> Response:
    """
    Download the unified diff patch file for manual application.
    Updates proposal state to 'downloaded'.
    """
    proposal = db.scalars(
        select(RemediationProposal).where(
            RemediationProposal.id == proposal_id,
            RemediationProposal.scan_id == scan_id,
        )
    ).first()

    if not proposal:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Proposal with ID '{proposal_id}' not found in scan '{scan_id}'",
        )

    if not proposal.diff_content or proposal.status == "validation_failed":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot download an invalid or empty patch.",
        )

    # Transition to downloaded
    if proposal.status in ("proposed", "reviewed"):
        proposal.status = "downloaded"
        proposal.updated_at = utc_now()
        db.commit()

    filename = f"vulnscope-fix-{proposal_id[:8]}.patch"
    return Response(
        content=proposal.diff_content,
        media_type="text/x-diff",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Cache-Control": "no-cache",
        },
    )


# --- Security Audit Report Routes ---


@router.get(
    "/{scan_id}/report",
    summary="Export security audit report (format: json, html, pdf)",
)
def get_security_report(
    scan_id: str,
    format: str = Query("json", description="Report format ('json', 'html', 'pdf')"),
    db: Session = Depends(get_db),
) -> Response:
    """
    Generate and export a security audit report for a completed or partial scan.
    Returns publication-ready reports in JSON, standalone HTML, or paginated PDF format.
    """
    scan = db.scalars(select(Scan).where(Scan.id == scan_id)).first()
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan record with ID '{scan_id}' not found",
        )

    clean_fmt = format.strip().lower()

    if clean_fmt == "json":
        report_data = ReportService.generate_json_report(scan, db)
        return Response(
            content=json.dumps(report_data, indent=2),
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="vulnscope-report-{scan_id[:8]}.json"'},
        )
    elif clean_fmt == "html":
        html_content = ReportService.generate_html_report(scan, db)
        return Response(
            content=html_content,
            media_type="text/html; charset=utf-8",
            headers={"Content-Disposition": f'inline; filename="vulnscope-report-{scan_id[:8]}.html"'},
        )
    elif clean_fmt == "pdf":
        pdf_bytes = ReportService.generate_pdf_report(scan, db)
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="vulnscope-report-{scan_id[:8]}.pdf"'},
        )
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported format '{format}'. Supported formats: 'json', 'html', 'pdf'.",
        )


@router.get("/{scan_id}/report/pdf", summary="Export security report as PDF")
def get_pdf_report(scan_id: str, db: Session = Depends(get_db)) -> Response:
    return get_security_report(scan_id=scan_id, format="pdf", db=db)


@router.get("/{scan_id}/report/html", summary="Export security report as HTML")
def get_html_report(scan_id: str, db: Session = Depends(get_db)) -> Response:
    return get_security_report(scan_id=scan_id, format="html", db=db)


@router.get("/{scan_id}/report/json", summary="Export security report as JSON")
def get_json_report(scan_id: str, db: Session = Depends(get_db)) -> Response:
    return get_security_report(scan_id=scan_id, format="json", db=db)

