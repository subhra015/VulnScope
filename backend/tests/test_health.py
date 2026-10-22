"""
Tests for /api/health endpoint.
"""

from fastapi.testclient import TestClient


def test_health_check_returns_healthy(client: TestClient):
    """GET /api/health returns HTTP 200 and expected health metadata."""
    response = client.get("/api/health")
    assert response.status_code == 200

    data = response.json()
    assert data["status"] == "healthy"
    assert data["service"] == "vulnscope-api"
    assert data["version"] == "0.1.0"
    assert data["database"] == "connected"


def test_root_endpoint_metadata(client: TestClient):
    """GET / returns project metadata and documentation paths."""
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert "VulnScope" in data["service"]
    assert "Phase 1" in data["phase"]
