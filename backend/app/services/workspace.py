"""
Workspace Management Service.
Manages secure, isolated workspace directories for source acquisition and extraction.
Guarantees per-job isolation, strictly validates workspace identifiers against path
traversal, and safely cleans up ephemeral files.
"""

from datetime import datetime, timezone
import os
from pathlib import Path
import shutil
from typing import Optional, Tuple
import uuid

from app.core.config import settings


class WorkspaceSecurityError(Exception):
    """Raised when an invalid workspace ID or path traversal attempt is detected."""
    pass


class WorkspaceManager:
    """
    Manages isolated filesystem directories for individual intake jobs.
    """

    def __init__(self, base_dir: Optional[Path] = None):
        self.base_dir = (base_dir or settings.get_resolved_workspaces_dir()).resolve()
        self.base_dir.mkdir(parents=True, exist_ok=True)

    def validate_workspace_id(self, workspace_id: str) -> str:
        """
        Validate that workspace_id is a valid UUIDv4 string.
        Guarantees that workspace_id contains no path separators, parent traversal,
        or illegal filesystem characters.
        """
        if not workspace_id or not isinstance(workspace_id, str):
            raise WorkspaceSecurityError("Workspace identifier must be a non-empty string.")
        try:
            parsed = uuid.UUID(workspace_id.strip())
            # Return lowercase standard hyphenated UUID string
            return str(parsed)
        except (ValueError, TypeError, AttributeError) as exc:
            raise WorkspaceSecurityError(
                f"Invalid workspace identifier format: '{workspace_id}'."
            ) from exc

    def create_workspace(self) -> Tuple[str, Path]:
        """
        Allocate a new isolated workspace directory with a server-generated UUIDv4.
        Sets restrictive permissions (0o700) where supported.
        Returns a tuple of (workspace_id, workspace_path).
        """
        workspace_id = str(uuid.uuid4())
        workspace_path = (self.base_dir / workspace_id).resolve()

        # Strict containment check
        if not workspace_path.is_relative_to(self.base_dir) or workspace_path == self.base_dir:
            raise WorkspaceSecurityError("Resolved workspace path escaped designated base directory.")

        workspace_path.mkdir(parents=True, exist_ok=False)

        # Apply restrictive permissions on POSIX operating systems
        try:
            if hasattr(os, "chmod") and os.name != "nt":
                os.chmod(workspace_path, 0o700)
        except OSError:
            pass

        return workspace_id, workspace_path

    def get_workspace_path(self, workspace_id: str) -> Path:
        """
        Safely resolve the filesystem path for an existing workspace by UUID.
        """
        clean_id = self.validate_workspace_id(workspace_id)
        workspace_path = (self.base_dir / clean_id).resolve()

        if not workspace_path.is_relative_to(self.base_dir) or workspace_path == self.base_dir:
            raise WorkspaceSecurityError("Workspace path resolves outside designated base directory.")

        return workspace_path

    def get_source_dir(self, workspace_id: str) -> Path:
        """
        Return the dedicated 'source' subdirectory inside the workspace.
        """
        workspace_path = self.get_workspace_path(workspace_id)
        source_dir = (workspace_path / "source").resolve()
        if not source_dir.is_relative_to(workspace_path):
            raise WorkspaceSecurityError("Source directory resolves outside designated workspace.")
        return source_dir

    def cleanup_workspace(self, workspace_id: str) -> bool:
        """
        Safely delete an entire workspace and all its contents.
        Guarantees that the base directory itself or paths outside it are never deleted.
        """
        try:
            workspace_path = self.get_workspace_path(workspace_id)
        except WorkspaceSecurityError:
            return False

        if not workspace_path.is_relative_to(self.base_dir) or workspace_path == self.base_dir:
            return False

        if workspace_path.exists() and workspace_path.is_dir():
            shutil.rmtree(workspace_path, ignore_errors=True)
            return True
        return False

    def cleanup_stale_workspaces(self, max_age_hours: Optional[int] = None) -> int:
        """
        Housekeeping routine: removes orphaned or aged workspaces older than max_age_hours.
        Never touches databases, configuration files, or non-UUID directories.
        """
        retention = max_age_hours if max_age_hours is not None else settings.workspace_retention_hours
        if retention <= 0:
            return 0

        now = datetime.now(timezone.utc).timestamp()
        max_age_seconds = retention * 3600
        cleaned_count = 0

        if not self.base_dir.exists():
            return 0

        for entry in self.base_dir.iterdir():
            if not entry.is_dir():
                continue
            # Validate directory name is a valid UUID
            try:
                self.validate_workspace_id(entry.name)
            except WorkspaceSecurityError:
                continue

            try:
                mtime = entry.stat().st_mtime
                if (now - mtime) > max_age_seconds:
                    shutil.rmtree(entry, ignore_errors=True)
                    cleaned_count += 1
            except OSError:
                continue

        return cleaned_count


# Global singleton instance
workspace_manager = WorkspaceManager()
