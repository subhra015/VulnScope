"""
Tests for /api/scans endpoints.
"""

from fastapi.testclient import TestClient


def test_list_scans_initially_empty(client: TestClient):
    """GET /api/scans returns an empty list when no scans exist."""
    response = client.get("/api/scans")
    assert response.status_code == 200
    assert response.json() == []


def test_create_scan_success_github(client: TestClient):
    """POST /api/scans creates a new scan record with initial status 'created'."""
    payload = {
        "project_name": "vulnscope-core",
        "source_type": "github",
        "source_reference": "https://github.com/example/vulnscope-core",
    }
    response = client.post("/api/scans", json=payload)
    assert response.status_code == 201

    data = response.json()
    assert "id" in data
    assert data["id"] is not None
    assert data["project_name"] == "vulnscope-core"
    assert data["source_type"] == "github"
    assert data["source_reference"] == "https://github.com/example/vulnscope-core"
    assert data["status"] == "created"  # Honest initial status
    assert "created_at" in data
    assert data["started_at"] is None
    assert data["completed_at"] is None


def test_create_scan_success_zip(client: TestClient):
    """POST /api/scans successfully accepts zip source type."""
    payload = {
        "project_name": "legacy-app",
        "source_type": "zip",
        "source_reference": "legacy-app-v1.zip",
    }
    response = client.post("/api/scans", json=payload)
    assert response.status_code == 201
    data = response.json()
    assert data["project_name"] == "legacy-app"
    assert data["source_type"] == "zip"
    assert data["status"] == "created"


def test_create_scan_persisted(client: TestClient):
    """Newly created scan appears in GET /api/scans list."""
    payload = {
        "project_name": "service-alpha",
        "source_type": "github",
    }
    create_resp = client.post("/api/scans", json=payload)
    assert create_resp.status_code == 201
    scan_id = create_resp.json()["id"]

    list_resp = client.get("/api/scans")
    assert list_resp.status_code == 200
    scans = list_resp.json()
    assert len(scans) == 1
    assert scans[0]["id"] == scan_id
    assert scans[0]["project_name"] == "service-alpha"


def test_get_scan_by_id_success(client: TestClient):
    """GET /api/scans/{scan_id} retrieves the correct scan record and findings list."""
    payload = {
        "project_name": "service-beta",
        "source_type": "github",
    }
    create_resp = client.post("/api/scans", json=payload)
    scan_id = create_resp.json()["id"]

    get_resp = client.get(f"/api/scans/{scan_id}")
    assert get_resp.status_code == 200
    scan = get_resp.json()
    assert scan["id"] == scan_id
    assert scan["project_name"] == "service-beta"
    assert scan["status"] == "created"
    assert scan["findings"] == []  # No fake findings in Phase 1


def test_get_scan_unknown_id_returns_404(client: TestClient):
    """GET /api/scans/{scan_id} returns HTTP 404 for non-existent scan ID."""
    response = client.get("/api/scans/non-existent-scan-id-12345")
    assert response.status_code == 404
    data = response.json()
    assert "not found" in data["detail"].lower()


def test_create_scan_rejects_empty_project_name(client: TestClient):
    """POST /api/scans returns 422 when project_name is empty or whitespace."""
    response = client.post(
        "/api/scans",
        json={"project_name": "   ", "source_type": "github"},
    )
    assert response.status_code == 422
    data = response.json()
    assert "validation failed" in data["detail"].lower()


def test_create_scan_rejects_missing_fields(client: TestClient):
    """POST /api/scans returns 422 when required fields are missing."""
    response = client.post("/api/scans", json={})
    assert response.status_code == 422


def test_create_scan_rejects_invalid_source_type(client: TestClient):
    """POST /api/scans returns 422 for unsupported source types (e.g. ftp, s3)."""
    response = client.post(
        "/api/scans",
        json={"project_name": "my-app", "source_type": "svn"},
    )
    assert response.status_code == 422


def test_scans_ordering(client: TestClient):
    """GET /api/scans returns records ordered by creation time descending."""
    client.post("/api/scans", json={"project_name": "first", "source_type": "github"})
    client.post("/api/scans", json={"project_name": "second", "source_type": "github"})
    client.post("/api/scans", json={"project_name": "third", "source_type": "zip"})

    response = client.get("/api/scans")
    assert response.status_code == 200
    scans = response.json()
    assert len(scans) == 3
    # Check that the most recently created scan is first
    assert scans[0]["project_name"] == "third"
    assert scans[1]["project_name"] == "second"
    assert scans[2]["project_name"] == "first"
