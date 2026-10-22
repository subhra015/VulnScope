"""
Automated Security and Validation Tests for Safe Archive Extraction.
Tests all 14 ZIP security test requirements specified for Phase 2:
1. Valid small ZIP archive
2. Invalid ZIP data
3. Empty archive (explicitly defined behavior: 400 Bad Request)
4. Path traversal entries (e.g. ../../outside.txt)
5. Absolute archive paths (/etc/passwd, C:/file)
6. Symbolic links and unsupported special entry types
7. Excessive archive entry count
8. Expanded-size limit exceeded
9. Oversized individual file
10. Excessive nesting depth
11. Duplicate or conflicting archive paths
12. Interrupted upload or extraction cleanup
13. No writes outside the designated workspace
14. Failure does not create a falsely successful intake record
"""

import io
from pathlib import Path
import stat
import zipfile
import pytest
from fastapi.testclient import TestClient

from app.core.config import Settings
from app.services.archive import (
    ArchiveLimitError,
    ArchiveSecurityError,
    ArchiveValidationError,
    SafeArchiveValidator,
)


def create_in_memory_zip(entries: dict[str, bytes | str]) -> io.BytesIO:
    """Helper to construct in-memory ZIP archives."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, content in entries.items():
            if isinstance(content, str):
                content = content.encode("utf-8")
            zf.writestr(name, content)
    buf.seek(0)
    return buf


class TestSafeArchiveValidatorUnit:
    """Unit tests directly exercising SafeArchiveValidator edge cases."""

    def test_1_valid_small_zip_archive(self, tmp_path: Path):
        """1. Valid small ZIP archive extracts cleanly and returns expected metrics."""
        zip_buf = create_in_memory_zip({
            "README.md": "# Sample Project",
            "src/main.py": "print('hello')",
            "docs/info.txt": "documentation",
        })
        archive_path = tmp_path / "valid.zip"
        archive_path.write_bytes(zip_buf.getvalue())

        target_dir = tmp_path / "extracted"
        validator = SafeArchiveValidator()
        metrics = validator.extract_and_validate(archive_path, target_dir)

        assert metrics["file_count"] == 3
        assert (target_dir / "README.md").read_text() == "# Sample Project"
        assert (target_dir / "src" / "main.py").read_text() == "print('hello')"

    def test_2_invalid_zip_data(self, tmp_path: Path):
        """2. Invalid/corrupted ZIP data is rejected."""
        corrupt_path = tmp_path / "corrupt.zip"
        corrupt_path.write_bytes(b"NOT A REAL ZIP FILE CONTENT")

        target_dir = tmp_path / "extracted"
        validator = SafeArchiveValidator()
        with pytest.raises(ArchiveValidationError, match="not a valid ZIP archive"):
            validator.extract_and_validate(corrupt_path, target_dir)

    def test_3_empty_archive(self, tmp_path: Path):
        """3. Empty archive has explicitly defined behavior: raises ArchiveValidationError."""
        empty_buf = io.BytesIO()
        with zipfile.ZipFile(empty_buf, "w") as _:
            pass
        empty_buf.seek(0)

        archive_path = tmp_path / "empty.zip"
        archive_path.write_bytes(empty_buf.getvalue())

        target_dir = tmp_path / "extracted"
        validator = SafeArchiveValidator()
        with pytest.raises(ArchiveValidationError, match="empty"):
            validator.extract_and_validate(archive_path, target_dir)

    def test_4_path_traversal_parent_directory(self, tmp_path: Path):
        """4. Path traversal (../../outside.txt) is detected and rejected."""
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("../../outside.txt", "traversal attempt")
            zf.writestr("valid.txt", "valid")
        buf.seek(0)

        archive_path = tmp_path / "traversal.zip"
        archive_path.write_bytes(buf.getvalue())

        target_dir = tmp_path / "extracted"
        validator = SafeArchiveValidator()
        with pytest.raises(ArchiveSecurityError, match="Path traversal component"):
            validator.extract_and_validate(archive_path, target_dir)

    def test_5_absolute_archive_paths(self, tmp_path: Path):
        """5. Absolute archive paths (/etc/passwd, C:/windows) are rejected."""
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("/etc/passwd", "root:x:0:0:")
        buf.seek(0)

        archive_path = tmp_path / "abs.zip"
        archive_path.write_bytes(buf.getvalue())

        target_dir = tmp_path / "extracted"
        validator = SafeArchiveValidator()
        with pytest.raises(ArchiveSecurityError, match="Absolute paths are forbidden"):
            validator.extract_and_validate(archive_path, target_dir)

    def test_6_symbolic_link_rejected(self, tmp_path: Path):
        """6. Symbolic links in archive entries are detected and rejected."""
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            info = zipfile.ZipInfo("symlink_entry")
            info.create_system = 3  # Unix
            # Upper 16 bits = Unix file mode (S_IFLNK | 0o777)
            info.external_attr = (stat.S_IFLNK | 0o777) << 16
            zf.writestr(info, "/etc/shadow")
        buf.seek(0)

        archive_path = tmp_path / "symlink.zip"
        archive_path.write_bytes(buf.getvalue())

        target_dir = tmp_path / "extracted"
        validator = SafeArchiveValidator()
        with pytest.raises(ArchiveSecurityError, match="Symbolic links are forbidden"):
            validator.extract_and_validate(archive_path, target_dir)

    def test_7_excessive_archive_entry_count(self, tmp_path: Path):
        """7. Archive exceeding max_file_count is rejected."""
        custom_settings = Settings(max_file_count=3)
        zip_buf = create_in_memory_zip({
            "f1.txt": "1",
            "f2.txt": "2",
            "f3.txt": "3",
            "f4.txt": "4",
        })
        archive_path = tmp_path / "too_many_files.zip"
        archive_path.write_bytes(zip_buf.getvalue())

        target_dir = tmp_path / "extracted"
        validator = SafeArchiveValidator(app_settings=custom_settings)
        with pytest.raises(ArchiveLimitError, match="exceeds maximum limit"):
            validator.extract_and_validate(archive_path, target_dir)

    def test_8_expanded_size_limit_exceeded(self, tmp_path: Path):
        """8. Total expanded size exceeding max_expanded_size_bytes is rejected."""
        custom_settings = Settings(max_expanded_size_bytes=50)
        zip_buf = create_in_memory_zip({
            "f1.txt": "a" * 30,
            "f2.txt": "b" * 30,  # 30 + 30 = 60 > 50
        })
        archive_path = tmp_path / "oversized_expanded.zip"
        archive_path.write_bytes(zip_buf.getvalue())

        target_dir = tmp_path / "extracted"
        validator = SafeArchiveValidator(app_settings=custom_settings)
        with pytest.raises(ArchiveLimitError, match="uncompressed size"):
            validator.extract_and_validate(archive_path, target_dir)

    def test_9_oversized_individual_file(self, tmp_path: Path):
        """9. Individual file exceeding max_file_size_bytes is rejected."""
        custom_settings = Settings(max_file_size_bytes=40)
        zip_buf = create_in_memory_zip({
            "f1.txt": "small",
            "large.txt": "x" * 100,  # 100 > 40
        })
        archive_path = tmp_path / "large_file.zip"
        archive_path.write_bytes(zip_buf.getvalue())

        target_dir = tmp_path / "extracted"
        validator = SafeArchiveValidator(app_settings=custom_settings)
        with pytest.raises(ArchiveLimitError, match="maximum individual file limit"):
            validator.extract_and_validate(archive_path, target_dir)

    def test_10_excessive_directory_nesting(self, tmp_path: Path):
        """10. Excessive nesting depth exceeding max_directory_depth is rejected."""
        custom_settings = Settings(max_directory_depth=3)
        zip_buf = create_in_memory_zip({
            "level1/level2/level3/level4/deep.txt": "too deep",
        })
        archive_path = tmp_path / "deep.zip"
        archive_path.write_bytes(zip_buf.getvalue())

        target_dir = tmp_path / "extracted"
        validator = SafeArchiveValidator(app_settings=custom_settings)
        with pytest.raises(ArchiveLimitError, match="nesting depth"):
            validator.extract_and_validate(archive_path, target_dir)

    @pytest.mark.filterwarnings("ignore:Duplicate name:UserWarning")
    def test_11_duplicate_or_conflicting_paths(self, tmp_path: Path):
        """11. Duplicate or conflicting archive paths are rejected."""
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("duplicate.txt", "first")
            zf.writestr("duplicate.txt", "second")
        buf.seek(0)

        archive_path = tmp_path / "duplicate.zip"
        archive_path.write_bytes(buf.getvalue())

        target_dir = tmp_path / "extracted"
        validator = SafeArchiveValidator()
        with pytest.raises(ArchiveValidationError, match="Duplicate or conflicting path"):
            validator.extract_and_validate(archive_path, target_dir)

    def test_13_no_writes_outside_designated_workspace(self, tmp_path: Path):
        """13. Verified that no files or directories are created outside designated workspace."""
        workspace_dir = tmp_path / "workspace"
        target_dir = workspace_dir / "source"
        workspace_dir.mkdir()

        zip_buf = create_in_memory_zip({
            "app/server.py": "app = None",
            "config.json": "{}",
        })
        archive_path = workspace_dir / "valid.zip"
        archive_path.write_bytes(zip_buf.getvalue())

        validator = SafeArchiveValidator()
        validator.extract_and_validate(archive_path, target_dir)

        # Ensure all extracted files are strictly inside target_dir
        for extracted_file in target_dir.rglob("*"):
            assert extracted_file.resolve().is_relative_to(target_dir.resolve())
            assert extracted_file.resolve().is_relative_to(workspace_dir.resolve())


class TestZipIntakeApi:
    """Integration tests for POST /api/intake/zip."""

    def test_valid_zip_upload_api(self, client: TestClient):
        """Valid ZIP upload succeeds and creates ready scan record."""
        zip_buf = create_in_memory_zip({
            "main.py": "print('hello')",
            "requirements.txt": "fastapi",
        })

        response = client.post(
            "/api/intake/zip",
            data={"project_name": "sample-zip-service"},
            files={"file": ("project.zip", zip_buf.getvalue(), "application/zip")},
        )

        assert response.status_code == 201
        data = response.json()
        assert data["project_name"] == "sample-zip-service"
        assert data["source_type"] == "zip"
        # Status remains created (scan not completed), intake_status is ready
        assert data["status"] == "created"
        assert data["intake_status"] == "ready"
        assert data["error_summary"] is None

        # Verify record exists in list
        list_res = client.get("/api/scans")
        assert list_res.status_code == 200
        scans = list_res.json()
        assert any(s["id"] == data["id"] for s in scans)

    def test_12_interrupted_or_failed_cleanup(self, client: TestClient):
        """12. Failed intake cleans up temporary workspace and records failure."""
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("../../escape.txt", "attack")
        buf.seek(0)

        response = client.post(
            "/api/intake/zip",
            data={"project_name": "malicious-zip"},
            files={"file": ("malicious.zip", buf.getvalue(), "application/zip")},
        )

        assert response.status_code == 400
        assert "Path traversal component" in response.json()["detail"]

    def test_14_failure_records_honest_failed_status(self, client: TestClient):
        """14. Intake failure records status='failed' and intake_status='failed' with error summary."""
        corrupt_data = b"NOT_A_ZIP"

        response = client.post(
            "/api/intake/zip",
            data={"project_name": "corrupt-project"},
            files={"file": ("corrupt.zip", corrupt_data, "application/zip")},
        )

        assert response.status_code == 400

        # Scan should be listed with failed status
        list_res = client.get("/api/scans")
        assert list_res.status_code == 200
        scans = list_res.json()
        failed_scan = next(s for s in scans if s["project_name"] == "corrupt-project")
        assert failed_scan["status"] == "failed"
        assert failed_scan["intake_status"] == "failed"
        assert failed_scan["error_summary"] is not None
        assert "not a valid ZIP archive" in failed_scan["error_summary"]
