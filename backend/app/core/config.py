"""
Application configuration loaded from environment variables.
Uses pydantic-settings so every field can be overridden via .env or the shell.
"""

import os
from pathlib import Path
from typing import List
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

# Root directory of the backend package (vulnscope/backend)
BACKEND_DIR = Path(__file__).resolve().parent.parent.parent
DEFAULT_DATA_DIR = BACKEND_DIR / "data"
DEFAULT_DB_FILE = DEFAULT_DATA_DIR / "vulnscope.db"
DEFAULT_WORKSPACES_DIR = DEFAULT_DATA_DIR / "workspaces"


class Settings(BaseSettings):
    # --- API metadata ---
    app_name: str = "VulnScope API"
    app_version: str = "0.1.0"
    debug: bool = False

    # --- CORS ---
    # Comma-separated list of allowed origins, e.g. "http://localhost:5173,http://127.0.0.1:5173"
    frontend_origin: str = "http://localhost:5173,http://127.0.0.1:5173"

    # --- Database ---
    # Default is a persistent SQLite database located in backend/data/vulnscope.db
    # Standard SQLite URL format: sqlite:///path/to/db
    database_url: str = Field(default=f"sqlite:///{DEFAULT_DB_FILE.as_posix()}")

    # --- Intake & Workspace Limits (Phase 2) ---
    # Base directory for extracted source code workspaces
    workspaces_dir: str = Field(default=f"{DEFAULT_WORKSPACES_DIR.as_posix()}")

    # Maximum allowed size for uploaded ZIP archive files (bytes). Default 50 MB
    max_upload_size_bytes: int = 50 * 1024 * 1024

    # Maximum allowed total uncompressed size for extracted archive (bytes). Default 150 MB
    max_expanded_size_bytes: int = 150 * 1024 * 1024

    # Maximum number of files and directories in archive. Default 2000
    max_file_count: int = 2000

    # Maximum allowed size for an individual uncompressed file in archive (bytes). Default 25 MB
    max_file_size_bytes: int = 25 * 1024 * 1024

    # Maximum allowed directory nesting depth in archive. Default 10
    max_directory_depth: int = 10

    # Maximum compression ratio (uncompressed_size / compressed_size) for bomb defense. Default 100.0
    max_compression_ratio: float = 100.0

    # HTTP timeouts for GitHub snapshot acquisition (seconds)
    github_connect_timeout_seconds: float = 10.0
    github_read_timeout_seconds: float = 30.0

    # Maximum allowed download size for GitHub snapshot (bytes). Default 50 MB
    max_github_download_size_bytes: int = 50 * 1024 * 1024

    # Maximum retention period in hours for completed workspaces before automatic cleanup (0 = disabled)
    workspace_retention_hours: int = 24

    model_config = SettingsConfigDict(
        env_file=str(BACKEND_DIR / ".env"),
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    @property
    def allowed_origins(self) -> List[str]:
        """Split the comma-separated origin string into a cleaned list."""
        return [o.strip() for o in self.frontend_origin.split(",") if o.strip()]

    def get_resolved_database_url(self) -> str:
        """
        Ensures any SQLite data directory is created if using a file path,
        and returns the database URL.
        """
        url = self.database_url
        if url.startswith("sqlite:///") and ":memory:" not in url:
            file_path_str = url.replace("sqlite:///", "", 1)
            db_path = Path(file_path_str)
            if not db_path.is_absolute():
                db_path = (BACKEND_DIR / db_path).resolve()
                url = f"sqlite:///{db_path.as_posix()}"
            # Ensure the directory exists
            db_path.parent.mkdir(parents=True, exist_ok=True)
        return url

    def get_resolved_workspaces_dir(self) -> Path:
        """
        Ensures the workspaces directory exists and returns its absolute path.
        """
        p = Path(self.workspaces_dir)
        if not p.is_absolute():
            p = (BACKEND_DIR / p).resolve()
        p.mkdir(parents=True, exist_ok=True)
        return p


# Shared singleton instance
settings = Settings()
