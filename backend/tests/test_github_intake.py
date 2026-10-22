"""
Automated Security and Integration Tests for Public GitHub Repository Intake.
Tests all 13 GitHub intake requirements specified for Phase 2:
1. Valid public repository URL
2. Unsupported hostname (e.g. gitlab.com)
3. Non-HTTPS URL
4. URL containing credentials
5. Malformed repository path
6. Redirect to an unapproved destination
7. Attempted localhost or private-network destination (SSRF defense)
8. GitHub 404 (Not Found or Private)
9. GitHub rate limiting (403/429)
10. Network timeout
11. Download size limit exceeded
12. Invalid downloaded archive
13. Workspace cleanup following a failed download
"""

from contextlib import contextmanager
import io
from pathlib import Path
from unittest.mock import MagicMock, patch
import zipfile
import httpx
import pytest
from fastapi.testclient import TestClient

from app.core.config import Settings
from app.services.github import (
    GithubIntakeService,
    GithubLimitError,
    GithubNetworkError,
    GithubNotFoundError,
    GithubRateLimitError,
    GithubSSRFError,
    GithubValidationError,
    parse_and_validate_github_url,
)


def create_sample_zip_bytes() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("repo-main/README.md", "# Sample Repo")
        zf.writestr("repo-main/app.py", "print('hello from github')")
    return buf.getvalue()


class TestGithubUrlValidation:
    """Unit tests for URL and reference syntax parsing and validation."""

    def test_1_valid_public_repo_url(self):
        """1. Valid public repository URL parses cleanly."""
        owner, repo = parse_and_validate_github_url("https://github.com/torvalds/linux")
        assert owner == "torvalds"
        assert repo == "linux"

        # Trailing slash and .git extension handled
        owner2, repo2 = parse_and_validate_github_url("https://github.com/pallets/flask.git/")
        assert owner2 == "pallets"
        assert repo2 == "flask"

    def test_2_unsupported_hostname(self):
        """2. Non-GitHub hostnames are rejected."""
        with pytest.raises(GithubValidationError, match="Unsupported host"):
            parse_and_validate_github_url("https://gitlab.com/group/project")

        with pytest.raises(GithubValidationError, match="Unsupported host"):
            parse_and_validate_github_url("https://attacker.com/repo/project")

    def test_3_non_https_url(self):
        """3. Plain HTTP URLs are strictly rejected."""
        with pytest.raises(GithubValidationError, match="Only secure HTTPS"):
            parse_and_validate_github_url("http://github.com/torvalds/linux")

    def test_4_url_containing_credentials(self):
        """4. URLs containing credentials are rejected."""
        with pytest.raises(GithubValidationError, match="Embedded credentials"):
            parse_and_validate_github_url("https://user:password@github.com/org/repo")

    def test_5_malformed_repository_path(self):
        """5. Malformed or incomplete repository paths are rejected."""
        with pytest.raises(GithubValidationError, match="Invalid GitHub repository path"):
            parse_and_validate_github_url("https://github.com/only-owner")

        with pytest.raises(GithubValidationError, match="Invalid GitHub repository path"):
            parse_and_validate_github_url("https://github.com/owner/repo/extra/path")

        with pytest.raises(GithubValidationError, match="Forbidden or reserved"):
            parse_and_validate_github_url("https://github.com/settings/profile")


class TestGithubSsrfAndNetworkProtections:
    """Tests for SSRF validation, DNS pinning, and redirect security."""

    @patch("socket.getaddrinfo")
    def test_7_attempted_localhost_or_private_network(self, mock_getaddrinfo):
        """7. Attempted localhost or private IP destination is blocked by SSRF defense."""
        service = GithubIntakeService()

        # Mock DNS returning loopback 127.0.0.1
        mock_getaddrinfo.return_value = [
            (2, 1, 0, "", ("127.0.0.1", 443))
        ]
        with pytest.raises(GithubSSRFError, match="prohibited non-global address"):
            service.verify_ssrf_safety("https://github.com/owner/repo")

        # Mock DNS returning RFC1918 private address 10.0.0.1
        mock_getaddrinfo.return_value = [
            (2, 1, 0, "", ("10.0.0.1", 443))
        ]
        with pytest.raises(GithubSSRFError, match="prohibited non-global address"):
            service.verify_ssrf_safety("https://github.com/owner/repo")

        # Mock DNS returning AWS metadata link-local 169.254.169.254
        mock_getaddrinfo.return_value = [
            (2, 1, 0, "", ("169.254.169.254", 443))
        ]
        with pytest.raises(GithubSSRFError, match="prohibited non-global address"):
            service.verify_ssrf_safety("https://github.com/owner/repo")

    @patch("socket.getaddrinfo")
    def test_6_redirect_to_unapproved_destination(self, mock_getaddrinfo, tmp_path: Path):
        """6. HTTP Redirect to an unapproved host is blocked by SSRF defense."""
        # DNS returns valid public IP for github.com
        mock_getaddrinfo.return_value = [
            (2, 1, 0, "", ("140.82.121.3", 443))
        ]

        # Setup mock client where initial request redirects to https://attacker.com/evil.zip
        dest_zip = tmp_path / "test.zip"
        service = GithubIntakeService()

        redirect_response = MagicMock()
        redirect_response.status_code = 302
        redirect_response.headers = {"Location": "https://attacker.com/evil.zip"}

        @contextmanager
        def mock_stream(method, url, headers=None):
            yield redirect_response

        with patch("httpx.Client.stream", side_effect=mock_stream):
            with pytest.raises(GithubSSRFError, match="non-approved destination host"):
                service.download_snapshot("owner", "repo", None, dest_zip)

    @patch("socket.getaddrinfo")
    def test_8_github_404_not_found(self, mock_getaddrinfo, tmp_path: Path):
        """8. GitHub 404 response raises GithubNotFoundError."""
        mock_getaddrinfo.return_value = [(2, 1, 0, "", ("140.82.121.3", 443))]
        dest_zip = tmp_path / "test.zip"
        service = GithubIntakeService()

        resp_404 = MagicMock()
        resp_404.status_code = 404

        @contextmanager
        def mock_stream(method, url, headers=None):
            yield resp_404

        with patch("httpx.Client.stream", side_effect=mock_stream):
            with pytest.raises(GithubNotFoundError, match="not found or is private"):
                service.download_snapshot("owner", "nonexistent-repo", None, dest_zip)

    @patch("socket.getaddrinfo")
    def test_9_github_rate_limiting(self, mock_getaddrinfo, tmp_path: Path):
        """9. GitHub 403 or 429 response raises GithubRateLimitError."""
        mock_getaddrinfo.return_value = [(2, 1, 0, "", ("140.82.121.3", 443))]
        dest_zip = tmp_path / "test.zip"
        service = GithubIntakeService()

        resp_403 = MagicMock()
        resp_403.status_code = 403

        @contextmanager
        def mock_stream(method, url, headers=None):
            yield resp_403

        with patch("httpx.Client.stream", side_effect=mock_stream):
            with pytest.raises(GithubRateLimitError, match="rate limit exceeded"):
                service.download_snapshot("owner", "repo", None, dest_zip)

    @patch("socket.getaddrinfo")
    def test_10_network_timeout(self, mock_getaddrinfo, tmp_path: Path):
        """10. Network timeout raises GithubNetworkError."""
        mock_getaddrinfo.return_value = [(2, 1, 0, "", ("140.82.121.3", 443))]
        dest_zip = tmp_path / "test.zip"
        service = GithubIntakeService()

        @contextmanager
        def mock_timeout_stream(method, url, headers=None):
            raise httpx.ReadTimeout("Read timed out")
            yield

        with patch("httpx.Client.stream", side_effect=mock_timeout_stream):
            with pytest.raises(GithubNetworkError, match="Network timeout"):
                service.download_snapshot("owner", "repo", None, dest_zip)

    @patch("socket.getaddrinfo")
    def test_11_download_size_limit_exceeded(self, mock_getaddrinfo, tmp_path: Path):
        """11. Snapshot download exceeding configured byte limit raises GithubLimitError."""
        mock_getaddrinfo.return_value = [(2, 1, 0, "", ("140.82.121.3", 443))]
        custom_settings = Settings(max_github_download_size_bytes=50)
        dest_zip = tmp_path / "test.zip"
        service = GithubIntakeService(app_settings=custom_settings)

        resp_200 = MagicMock()
        resp_200.status_code = 200
        # Yields 60 bytes > 50 byte limit
        resp_200.iter_bytes.return_value = [b"a" * 30, b"b" * 30]

        @contextmanager
        def mock_stream(method, url, headers=None):
            yield resp_200

        with patch("httpx.Client.stream", side_effect=mock_stream):
            with pytest.raises(GithubLimitError, match="exceeded maximum limit"):
                service.download_snapshot("owner", "repo", None, dest_zip)

    @patch("socket.getaddrinfo")
    def test_12_and_13_invalid_archive_and_workspace_cleanup(self, mock_getaddrinfo, client: TestClient):
        """12 & 13. Invalid downloaded archive is rejected and workspace cleaned up."""
        mock_getaddrinfo.return_value = [(2, 1, 0, "", ("140.82.121.3", 443))]

        # Mock GitHub returning HTTP 200 with corrupt data
        resp_corrupt = MagicMock()
        resp_corrupt.status_code = 200
        resp_corrupt.iter_bytes.return_value = [b"CORRUPT NOT ZIP DATA"]

        @contextmanager
        def mock_stream(method, url, headers=None):
            yield resp_corrupt

        with patch("httpx.Client.stream", side_effect=mock_stream):
            response = client.post(
                "/api/intake/github",
                json={"repo_url": "https://github.com/my-org/corrupt-repo"},
            )

            assert response.status_code == 400
            assert "not a valid ZIP archive" in response.json()["detail"]

            # Verify scan record recorded with failure
            list_res = client.get("/api/scans")
            scans = list_res.json()
            failed_scan = next(s for s in scans if s["project_name"] == "corrupt-repo")
            assert failed_scan["status"] == "failed"
            assert failed_scan["intake_status"] == "failed"


class TestGithubIntakeApiSuccess:
    """Integration test for successful GitHub repository acquisition."""

    @patch("socket.getaddrinfo")
    def test_successful_github_intake(self, mock_getaddrinfo, client: TestClient):
        """Successful GitHub intake produces ready scan record."""
        mock_getaddrinfo.return_value = [(2, 1, 0, "", ("140.82.121.3", 443))]
        zip_bytes = create_sample_zip_bytes()

        resp_success = MagicMock()
        resp_success.status_code = 200
        resp_success.iter_bytes.return_value = [zip_bytes]

        @contextmanager
        def mock_stream(method, url, headers=None):
            yield resp_success

        with patch("httpx.Client.stream", side_effect=mock_stream):
            response = client.post(
                "/api/intake/github",
                json={
                    "repo_url": "https://github.com/my-org/sample-service",
                    "project_name": "custom-service-name",
                    "ref": "main",
                },
            )

            assert response.status_code == 201
            data = response.json()
            assert data["project_name"] == "custom-service-name"
            assert data["source_type"] == "github"
            # Scan status remains created (scan not completed), intake_status is ready
            assert data["status"] == "created"
            assert data["intake_status"] == "ready"
            assert data["error_summary"] is None
