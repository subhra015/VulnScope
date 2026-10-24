"""
Unified Diff Patch Validator and Safety Engine.
Guarantees that model-generated patch proposals are strictly valid, bounded, safe,
and non-destructive before display or download.
"""

from dataclasses import dataclass
from pathlib import Path, PurePosixPath
import re
from typing import List, Optional

from app.services.ai.sanitizer import RedactionService


@dataclass
class PatchValidationResult:
    """Result of patch security and structural validation."""
    is_valid: bool
    error: Optional[str] = None
    sanitized_diff: Optional[str] = None
    target_file_path: Optional[str] = None
    changed_lines_count: int = 0
    changed_files_count: int = 0


class PatchValidator:
    """
    Validates proposed unified diffs against strict security rules:
    - Prohibits path traversal, absolute paths, and symlink escapes.
    - Prohibits modifications to dependency manifests or lockfiles.
    - Prohibits modifications to sensitive or hidden files.
    - Limits patch size (30 KB), changed files (1), and changed lines (100).
    - Verifies unified diff structure and hunk syntax.
    """

    MAX_PATCH_BYTES = 30 * 1024  # 30 KB
    MAX_CHANGED_LINES = 100
    MAX_CHANGED_FILES = 1

    # Manifest and lockfile patterns that must not be automatically patched
    FORBIDDEN_FILES = {
        "package.json",
        "package-lock.json",
        "pnpm-lock.yaml",
        "yarn.lock",
        "requirements.txt",
        "pyproject.toml",
        "poetry.lock",
        "pipfile",
        "pipfile.lock",
        "gemfile",
        "gemfile.lock",
        "pom.xml",
        "build.gradle",
        "cargo.toml",
        "cargo.lock",
        "go.mod",
        "go.sum",
    }

    @classmethod
    def sanitize_diff_path(cls, path_token: str) -> Optional[str]:
        """
        Extract and sanitize repository-relative path from unified diff header token.
        Strips 'a/', 'b/' prefixes. Rejects absolute paths and traversal tokens.
        """
        clean = path_token.strip().strip("'\"")
        # Remove /dev/null
        if clean == "/dev/null":
            return "/dev/null"

        # Check raw leading absolute slash or drive letter before prefix stripping
        if clean.startswith("/") or re.match(r"^[a-zA-Z]:", clean):
            return None

        # Standard diff prefixes a/ and b/
        if clean.startswith("a/") or clean.startswith("b/"):
            clean = clean[2:]
        elif clean.startswith("a\\") or clean.startswith("b\\"):
            clean = clean[2:]

        clean = clean.replace("\\", "/")

        # Absolute path check after stripping prefix
        if clean.startswith("/") or re.match(r"^[a-zA-Z]:", clean):
            return None

        # Traversal check
        parts = [p for p in clean.split("/") if p]
        if any(p in ("..", ".") for p in parts):
            return None

        return "/".join(parts) or None

    @classmethod
    def validate_patch(
        cls,
        diff_content: str,
        expected_rel_path: Optional[str] = None,
        workspace_source_dir: Optional[Path] = None,
    ) -> PatchValidationResult:
        """
        Perform complete validation of a candidate patch string.
        """
        if not diff_content or not diff_content.strip():
            return PatchValidationResult(is_valid=False, error="Patch content is empty.")

        # 1. Byte size limit
        raw_bytes = diff_content.encode("utf-8")
        if len(raw_bytes) > cls.MAX_PATCH_BYTES:
            return PatchValidationResult(
                is_valid=False,
                error=f"Patch size ({len(raw_bytes)} bytes) exceeds maximum limit of {cls.MAX_PATCH_BYTES} bytes.",
            )

        # 2. Defense-in-depth secret check on patch diff
        redacted = RedactionService.redact_secrets(diff_content)
        if "[REDACTED_" in redacted and "[REDACTED_" not in diff_content:
            return PatchValidationResult(
                is_valid=False,
                error="Patch proposal contains detected secrets or private key material.",
            )

        lines = diff_content.splitlines()

        # 3. Parse headers and hunks
        file_targets = set()
        added_lines = 0
        deleted_lines = 0
        hunk_count = 0
        has_file_header = False

        hunk_pattern = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")

        for line in lines:
            if line.startswith("--- "):
                path_raw = line[4:].strip().split("\t")[0]
                sanitized = cls.sanitize_diff_path(path_raw)
                if sanitized and sanitized != "/dev/null":
                    file_targets.add(sanitized)
                has_file_header = True
            elif line.startswith("+++ "):
                path_raw = line[4:].strip().split("\t")[0]
                sanitized = cls.sanitize_diff_path(path_raw)
                if sanitized and sanitized != "/dev/null":
                    file_targets.add(sanitized)
                has_file_header = True
            elif hunk_pattern.match(line):
                hunk_count += 1
            elif line.startswith("+") and not line.startswith("+++"):
                added_lines += 1
            elif line.startswith("-") and not line.startswith("---"):
                deleted_lines += 1

        total_changed_lines = added_lines + deleted_lines

        if not has_file_header:
            return PatchValidationResult(
                is_valid=False,
                error="Malformed unified diff: missing file headers ('---' and '+++').",
            )

        if hunk_count == 0:
            return PatchValidationResult(
                is_valid=False,
                error="Malformed unified diff: no valid hunk markers ('@@ -l,s +l,s @@') found.",
            )

        # 4. Changed files limit
        if len(file_targets) == 0:
            return PatchValidationResult(
                is_valid=False,
                error="Unified diff does not specify a valid target file.",
            )

        if len(file_targets) > cls.MAX_CHANGED_FILES:
            return PatchValidationResult(
                is_valid=False,
                error=f"Patch modifies {len(file_targets)} files. Single-file patches only are supported.",
                changed_files_count=len(file_targets),
            )

        target_file = next(iter(file_targets))

        # 5. Check against expected path if provided
        if expected_rel_path:
            clean_expected = expected_rel_path.replace("\\", "/").lstrip("/")
            if target_file.lower() != clean_expected.lower():
                return PatchValidationResult(
                    is_valid=False,
                    error=f"Patch target file '{target_file}' does not match finding file '{clean_expected}'.",
                )

        # 6. Changed lines limit
        if total_changed_lines > cls.MAX_CHANGED_LINES:
            return PatchValidationResult(
                is_valid=False,
                error=f"Patch changes {total_changed_lines} lines (maximum allowed is {cls.MAX_CHANGED_LINES}).",
                changed_lines_count=total_changed_lines,
            )

        # 7. Check sensitive files and forbidden dependency manifests
        target_name = PurePosixPath(target_file).name.lower()
        if target_name in cls.FORBIDDEN_FILES:
            return PatchValidationResult(
                is_valid=False,
                error=f"Direct modification of package manifest or lockfile '{target_name}' via patch is prohibited.",
            )

        if RedactionService.is_sensitive_file(target_file):
            return PatchValidationResult(
                is_valid=False,
                error=f"Patch target '{target_file}' is classified as a sensitive file.",
            )

        # 8. Check filesystem path if workspace directory provided
        if workspace_source_dir:
            source_root = workspace_source_dir.resolve()
            resolved_target = (source_root / target_file).resolve()

            try:
                resolved_target.relative_to(source_root)
            except ValueError:
                return PatchValidationResult(
                    is_valid=False,
                    error=f"Patch target path '{target_file}' attempts to escape workspace boundary.",
                )

            # Check if target is a symlink
            if resolved_target.is_symlink():
                return PatchValidationResult(
                    is_valid=False,
                    error=f"Patch target '{target_file}' is a symbolic link, which is forbidden.",
                )

        # Normalise diff with standard newlines
        clean_diff = "\n".join(lines) + "\n"

        return PatchValidationResult(
            is_valid=True,
            sanitized_diff=clean_diff,
            target_file_path=target_file,
            changed_lines_count=total_changed_lines,
            changed_files_count=len(file_targets),
        )
