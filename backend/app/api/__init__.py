"""
API package containing endpoints for health and scans.
"""

from fastapi import APIRouter
from app.api import health, scans, intake

api_router = APIRouter()
api_router.include_router(health.router)
api_router.include_router(scans.router)
api_router.include_router(intake.router)

__all__ = ["api_router"]
