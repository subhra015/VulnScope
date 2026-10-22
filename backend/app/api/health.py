"""
Health check endpoint.
Provides API status and database connectivity check.
"""

from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.session import get_db
from app.schemas.health import HealthResponse

router = APIRouter(tags=["health"])


@router.get("/health", response_model=HealthResponse)
def get_health(db: Session = Depends(get_db)) -> HealthResponse:
    """
    Returns the operational status of the VulnScope backend
    and verifies active database connectivity.
    """
    db_status = "connected"
    try:
        db.execute(text("SELECT 1"))
    except Exception as exc:
        db_status = f"unreachable: {str(exc)}"

    return HealthResponse(
        status="healthy" if db_status == "connected" else "degraded",
        service="vulnscope-api",
        version=settings.app_version,
        database=db_status,
    )
