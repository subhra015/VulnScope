"""
Scans API router.
Manages scan record creation, listing, and retrieval.
In Phase 1, only database records are created and retrieved;
no scanning execution occurs.
"""

from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.models.repository import Repository
from app.models.scan import Scan
from app.schemas.scan import (
    ScanCreateRequest,
    ScanResponse,
    ScanDetailResponse,
)

router = APIRouter(prefix="/scans", tags=["scans"])


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

    Phase 1 Foundation:
    - Creates a scan record with initial status 'created'.
    - Associates or creates a repository entry for metadata tracking.
    - Does NOT execute scanners or download source code.
    """
    # Find existing repository or create a new one for this project
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
    Retrieve details for a specific scan record by its ID.
    Returns HTTP 404 if the scan record does not exist.
    """
    stmt = select(Scan).where(Scan.id == scan_id)
    scan = db.scalars(stmt).first()

    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan record with ID '{scan_id}' not found",
        )

    return scan
