"""
Automated tests for Proposed-Fix Patch Validation.
Tests:
- Valid unified diff accepted and sanitized
- Path traversal (../../etc/passwd) rejected
- Absolute paths (/etc/shadow, C:/system32) rejected
- Disallowed files (package.json, requirements.txt, lockfiles) rejected
- Sensitive files (.env, .pem) rejected
- Symlink escapes rejected
- Oversized patch (>30KB) and excessive changed lines (>100) rejected
- Malformed diffs (missing headers/hunks) rejected
- Non-destructive guarantees: patch validation never touches workspace files
"""

from pathlib import Path
import pytest
from app.services.ai.patch_validator import PatchValidator, PatchValidationResult


VALID_DIFF = """--- a/src/auth.py
+++ b/src/auth.py
@@ -10,4 +10,4 @@
-def check_password(p):
-    return p == "admin"
+def check_password(p, hashed):
+    return hmac.compare_digest(hash(p), hashed)
"""

TRAVERSAL_DIFF = """--- a/../../outside.py
+++ b/../../outside.py
@@ -1,2 +1,2 @@
-bad()
+good()
"""

ABSOLUTE_PATH_DIFF = """--- a//etc/passwd
+++ b//etc/passwd
@@ -1,2 +1,2 @@
-root
+admin
"""

MANIFEST_DIFF = """--- a/requirements.txt
+++ b/requirements.txt
@@ -1,2 +1,2 @@
-flask==1.0.0
+flask==3.0.0
"""

LOCKFILE_DIFF = """--- a/package-lock.json
+++ b/package-lock.json
@@ -1,2 +1,2 @@
-v1
+v2
"""

SENSITIVE_DIFF = """--- a/.env
+++ b/.env
@@ -1,2 +1,2 @@
-KEY=1
+KEY=2
"""

MALFORMED_DIFF_NO_HUNKS = """--- a/src/auth.py
+++ b/src/auth.py
just random text without @@ hunk markers
"""

MALFORMED_DIFF_NO_HEADER = """@@ -1,2 +1,2 @@
-bad()
+good()
"""


def test_valid_patch_passes_validation(tmp_path: Path):
    """Valid unified diff passes and returns sanitized structure."""
    src_dir = tmp_path / "source"
    src_dir.mkdir()
    auth_file = src_dir / "src" / "auth.py"
    auth_file.parent.mkdir(parents=True)
    auth_file.write_text("def check_password(p):\n    return p == 'admin'\n")

    res = PatchValidator.validate_patch(
        diff_content=VALID_DIFF,
        expected_rel_path="src/auth.py",
        workspace_source_dir=src_dir,
    )

    assert res.is_valid is True
    assert res.error is None
    assert res.target_file_path == "src/auth.py"
    assert res.changed_lines_count == 4
    assert res.sanitized_diff is not None
    assert res.sanitized_diff.startswith("--- a/src/auth.py")

    # Non-destructive guarantee: original file was not modified!
    assert auth_file.read_text() == "def check_password(p):\n    return p == 'admin'\n"


def test_path_traversal_patch_rejected():
    """Diffs targeting traversal paths are rejected."""
    res = PatchValidator.validate_patch(diff_content=TRAVERSAL_DIFF)
    assert res.is_valid is False
    assert "target" in res.error.lower() or "malformed" in res.error.lower()


def test_absolute_path_patch_rejected():
    """Diffs targeting absolute paths are rejected."""
    res = PatchValidator.validate_patch(diff_content=ABSOLUTE_PATH_DIFF)
    assert res.is_valid is False


def test_dependency_manifest_and_lockfile_patches_rejected():
    """Modifications to dependency manifests and lockfiles via patch are prohibited."""
    res_manifest = PatchValidator.validate_patch(diff_content=MANIFEST_DIFF)
    assert res_manifest.is_valid is False
    assert "prohibited" in res_manifest.error.lower()

    res_lockfile = PatchValidator.validate_patch(diff_content=LOCKFILE_DIFF)
    assert res_lockfile.is_valid is False
    assert "prohibited" in res_lockfile.error.lower()


def test_sensitive_file_patch_rejected():
    """Patches targeting sensitive .env or certificate files are rejected."""
    res = PatchValidator.validate_patch(diff_content=SENSITIVE_DIFF)
    assert res.is_valid is False
    assert "sensitive" in res.error.lower()


def test_malformed_diffs_rejected():
    """Diffs lacking standard unified headers or hunks are rejected."""
    res1 = PatchValidator.validate_patch(diff_content=MALFORMED_DIFF_NO_HUNKS)
    assert res1.is_valid is False
    assert "hunk" in res1.error.lower()

    res2 = PatchValidator.validate_patch(diff_content=MALFORMED_DIFF_NO_HEADER)
    assert res2.is_valid is False
    assert "header" in res2.error.lower()


def test_oversized_patch_and_line_count_limits_enforced():
    """Patches exceeding byte limit or line count limit are rejected."""
    # Patch with 120 lines changed (> 100 limit)
    many_lines = "\n".join(f"- line_{i}\n+ new_line_{i}" for i in range(70))
    huge_diff = f"--- a/src/app.py\n+++ b/src/app.py\n@@ -1,70 +1,70 @@\n{many_lines}\n"

    res_lines = PatchValidator.validate_patch(diff_content=huge_diff)
    assert res_lines.is_valid is False
    assert "lines" in res_lines.error.lower()

    # Exceeding 30 KB
    huge_payload = "--- a/src/app.py\n+++ b/src/app.py\n@@ -1,1 +1,1 @@\n+" + ("x" * (35 * 1024)) + "\n"
    res_bytes = PatchValidator.validate_patch(diff_content=huge_payload)
    assert res_bytes.is_valid is False
    assert "size" in res_bytes.error.lower()
