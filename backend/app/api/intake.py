"""
Source Intake API Router.
Handles secure acquisition and validation of source code targets:
- POST /api/intake/zip : Streaming multipart ZIP upload, validation, and isolated extraction.
- POST /api/intake/github : Public GitHub repository snapshot acquisition and validation.
"""

from pathlib import Path
import re
from typing import Optional
from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.session import get_db
from app.models.base import utc_now
from app.models.repository import Repository
from app.models.scan import Scan
from app.schemas.intake import GithubIntakeRequest
from app.schemas.scan import ScanResponse
from app.services.archive import (
    ArchiveError,
    ArchiveLimitError,
    ArchiveSecurityError,
    ArchiveValidationError,
    safe_archive_validator,
)
from app.services.github import (
    GithubError,
    GithubLimitError,
    GithubNetworkError,
    GithubNotFoundError,
    GithubRateLimitError,
    GithubSSRFError,
    GithubValidationError,
    github_intake_service,
    parse_and_validate_github_url,
    validate_git_ref,
)
from app.services.workspace import WorkspaceSecurityError, workspace_manager

router = APIRouter(prefix="/intake", tags=["intake"])


def _sanitize_project_name(name: Optional[str], fallback: str = "uploaded-project") -> str:
    """Sanitize user-provided project name or derive from archive filename."""
    if name:
        cleaned = re.sub(r"[^\w.\s-]", "_", name.strip())
        if cleaned:
            return cleaned[:255]
    fallback_clean = re.sub(r"[^\w.\s-]", "_", fallback.strip())
    return (fallback_clean or "project")[:255]


@router.post(
    "/zip",
    response_model=ScanResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Upload and validate a ZIP source archive",
)
async def intake_zip(
    file: UploadFile = File(..., description="Multipart ZIP archive file"),
    project_name: Optional[str] = Form(
        None,
        description="Optional project or repository name. Derived from filename if omitted.",
    ),
    db: Session = Depends(get_db),
) -> ScanResponse:
    """
    Acquire and validate a source code project via multipart ZIP upload.

    Security & Validation:
    - Streams directly to temporary storage with chunked byte limits.
    - Rejects zip bombs, traversal entries, symlinks, absolute paths, and excessive nesting.
    - Allocates an isolated, server-generated workspace.
    - Cleans up partial files and directories on any error.
    - Records intake lifecycle state: created -> ingesting -> ready (or failed).
    """
    # 1. Determine sanitized project name and reference
    original_filename = file.filename or "upload.zip"
    stem_name = Path(original_filename).stem or "archive"
    resolved_project_name = _sanitize_project_name(project_name, fallback=stem_name)

    # 2. Register Repository metadata
    repo_stmt = select(Repository).where(
        Repository.project_name == resolved_project_name,
        Repository.source_type == "zip",
    )
    repo = db.scalars(repo_stmt).first()
    if not repo:
        repo = Repository(
            project_name=resolved_project_name,
            source_type="zip",
            source_reference=original_filename,
        )
        db.add(repo)
        db.flush()

    # 3. Initialize Scan record with lifecycle: created -> ingesting
    scan = Scan(
        repository_id=repo.id,
        project_name=resolved_project_name,
        source_type="zip",
        source_reference=original_filename,
        status="created",  # Remains 'created' because security scan has not run
        intake_status="ingesting",
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    # 4. Allocate isolated workspace
    workspace_id = None
    try:
        workspace_id, workspace_path = workspace_manager.create_workspace()
        scan.workspace_id = workspace_id
        db.commit()
    except Exception as exc:
        scan.intake_status = "failed"
        scan.status = "failed"
        scan.error_summary = "Failed to provision secure temporary workspace."
        scan.completed_at = utc_now()
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to provision secure temporary workspace.",
        ) from exc

    temp_zip = workspace_path / "upload_temp.zip"
    source_target_dir = workspace_path / "source"

    try:
        # 5. Stream upload to disk with chunked byte enforcement
        total_uploaded = 0
        chunk_size = 64 * 1024

        with open(temp_zip, "wb") as f_out:
            while True:
                chunk = await file.read(chunk_size)
                if not chunk:
                    break
                chunk_len = len(chunk)
                total_uploaded += chunk_len

                if total_uploaded > settings.max_upload_size_bytes:
                    max_mb = settings.max_upload_size_bytes // (1024 * 1024)
                    raise ArchiveLimitError(
                        f"Uploaded ZIP file exceeds maximum allowed upload size limit of {max_mb} MB."
                    )

                f_out.write(chunk)

        # 6. Validate and extract archive into workspace/source
        safe_archive_validator.extract_and_validate(temp_zip, source_target_dir)

        # 7. Clean up the compressed archive after successful extraction
        if temp_zip.exists():
            temp_zip.unlink(missing_ok=True)

        # 8. Record intake success: status remains 'created' (scan pending), intake_status -> 'ready'
        scan.intake_status = "ready"
        scan.status = "created"
        scan.error_summary = None
        db.commit()
        db.refresh(scan)

        return scan

    except ArchiveLimitError as exc:
        _handle_intake_failure(db, scan, workspace_id, str(exc))
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=str(exc),
        ) from exc

    except (ArchiveSecurityError, ArchiveValidationError, ArchiveError) as exc:
        _handle_intake_failure(db, scan, workspace_id, str(exc))
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc

    except Exception as exc:
        sanitized_msg = "An unexpected error occurred during archive intake."
        _handle_intake_failure(db, scan, workspace_id, sanitized_msg)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=sanitized_msg,
        ) from exc


@router.post(
    "/github",
    response_model=ScanResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Acquire and validate a public GitHub repository snapshot",
)
def intake_github(
    payload: GithubIntakeRequest,
    db: Session = Depends(get_db),
) -> ScanResponse:
    """
    Acquire and validate a source code repository from public GitHub.

    Security & Validation:
    - Strictly enforces HTTPS and public github.com entry hosts.
    - Validates owner/repo and optional ref against path traversal and forbidden syntax.
    - Performs pre-flight SSRF and private-network checks for all requests and redirects.
    - Bounded streaming download with connection/read timeouts.
    - Validates archive contents using the identical SafeArchiveValidator logic.
    - Cleans up workspaces on failure and records lifecycle transitions honestly.
    """
    # 1. URL & ref syntax validation
    try:
        owner, repo_name = parse_and_validate_github_url(payload.repo_url)
        clean_ref = validate_git_ref(payload.ref)
    except GithubValidationError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        ) from exc

    resolved_project_name = _sanitize_project_name(payload.project_name, fallback=repo_name)
    source_reference = payload.repo_url if not clean_ref else f"{payload.repo_url}@{clean_ref}"

    # 2. Register Repository metadata
    repo_stmt = select(Repository).where(
        Repository.project_name == resolved_project_name,
        Repository.source_type == "github",
    )
    repo = db.scalars(repo_stmt).first()
    if not repo:
        repo = Repository(
            project_name=resolved_project_name,
            source_type="github",
            source_reference=source_reference,
        )
        db.add(repo)
        db.flush()
    elif repo.source_reference != source_reference:
        repo.source_reference = source_reference
        db.flush()

    # 3. Initialize Scan record with lifecycle: created -> ingesting
    scan = Scan(
        repository_id=repo.id,
        project_name=resolved_project_name,
        source_type="github",
        source_reference=source_reference,
        status="created",  # Remains 'created' because security scan has not run
        intake_status="ingesting",
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    # 4. Allocate isolated workspace
    workspace_id = None
    try:
        workspace_id, workspace_path = workspace_manager.create_workspace()
        scan.workspace_id = workspace_id
        db.commit()
    except Exception as exc:
        scan.intake_status = "failed"
        scan.status = "failed"
        scan.error_summary = "Failed to provision secure temporary workspace."
        scan.completed_at = utc_now()
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to provision secure temporary workspace.",
        ) from exc

    temp_snapshot_zip = workspace_path / "github_snapshot.zip"
    source_target_dir = workspace_path / "source"

    try:
        # 5. Acquire bounded repository snapshot from GitHub
        github_intake_service.download_snapshot(
            owner=owner,
            repo=repo_name,
            ref=clean_ref,
            destination_zip=temp_snapshot_zip,
        )

        # 6. Validate and extract archive using SafeArchiveValidator
        safe_archive_validator.extract_and_validate(temp_snapshot_zip, source_target_dir)

        # 7. Clean up the downloaded zip file after extraction
        if temp_snapshot_zip.exists():
            temp_snapshot_zip.unlink(missing_ok=True)

        # 8. Record intake success: status remains 'created' (scan pending), intake_status -> 'ready'
        scan.intake_status = "ready"
        scan.status = "created"
        scan.error_summary = None
        db.commit()
        db.refresh(scan)

        return scan

    except GithubSSRFError as exc:
        _handle_intake_failure(db, scan, workspace_id, str(exc))
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc

    except GithubNotFoundError as exc:
        _handle_intake_failure(db, scan, workspace_id, str(exc))
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        ) from exc

    except GithubRateLimitError as exc:
        _handle_intake_failure(db, scan, workspace_id, str(exc))
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=str(exc),
        ) from exc

    except GithubLimitError as exc:
        _handle_intake_failure(db, scan, workspace_id, str(exc))
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=str(exc),
        ) from exc

    except GithubNetworkError as exc:
        _handle_intake_failure(db, scan, workspace_id, str(exc))
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=str(exc),
        ) from exc

    except (ArchiveLimitError, ArchiveSecurityError, ArchiveValidationError, ArchiveError) as exc:
        _handle_intake_failure(db, scan, workspace_id, str(exc))
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc

    except GithubError as exc:
        _handle_intake_failure(db, scan, workspace_id, str(exc))
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc

    except Exception as exc:
        sanitized_msg = "An unexpected error occurred during GitHub repository intake."
        _handle_intake_failure(db, scan, workspace_id, sanitized_msg)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=sanitized_msg,
        ) from exc


def _handle_intake_failure(
    db: Session,
    scan: Scan,
    workspace_id: Optional[str],
    error_summary: str,
) -> None:
    """
    Guarantees clean rollback of workspace storage and records intake failure honestly in database.
    """
    if workspace_id:
        workspace_manager.cleanup_workspace(workspace_id)

    try:
        scan.intake_status = "failed"
        scan.status = "failed"
        scan.error_summary = error_summary
        scan.workspace_id = None
        scan.completed_at = utc_now()
        db.commit()
    except Exception:
        db.rollback()
