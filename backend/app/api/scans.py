"""
Scans API router.
Manages scan record creation, listing, status retrieval, background scan execution,
and normalized findings querying.
"""

from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.models.finding import Finding
from app.models.repository import Repository
from app.models.scan import Scan
from app.schemas.finding import FindingResponse, FindingsListResponse
from app.schemas.scan import (
    ScanCreateRequest,
    ScanDetailResponse,
    ScanResponse,
    ScanRunResponse,
)
from app.services.scan_orchestrator import ScanOrchestratorError, scan_orchestrator

router = APIRouter(prefix="/scans", tags=["scans"])


def _calculate_findings_summary(findings: List[Finding]) -> dict:
    """Compute summary counts across categories and severities."""
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
    }
    for f in findings:
        cat = (f.category or "code").lower()
        if cat in summary:
            summary[cat] += 1
        sev = (f.severity or "medium").lower()
        if sev in summary:
            summary[sev] += 1
    return summary


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
    limit: int = Query(50, ge=1, le=500, description="Page limit"),
    offset: int = Query(0, ge=0, description="Page offset"),
    db: Session = Depends(get_db),
) -> FindingsListResponse:
    """
    List normalized findings for a specific scan with optional filtering and pagination.
    """
    # Verify scan exists
    scan_stmt = select(Scan).where(Scan.id == scan_id)
    scan = db.scalars(scan_stmt).first()
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan record with ID '{scan_id}' not found",
        )

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

    total = db.scalar(count_query) or 0
    items = db.scalars(base_query.order_by(Finding.created_at.asc()).offset(offset).limit(limit)).all()

    return FindingsListResponse(
        total=total,
        items=[FindingResponse.model_validate(f) for f in items],
        limit=limit,
        offset=offset,
    )
