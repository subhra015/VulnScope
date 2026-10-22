"""
Pydantic schemas for the health endpoint.
"""

from pydantic import BaseModel, Field


class HealthResponse(BaseModel):
    status: str = Field(..., description="Operational status of the backend API")
    service: str = Field(..., description="Service identifier")
    version: str = Field(..., description="Application version")
    database: str = Field(..., description="Status of the database connection")
