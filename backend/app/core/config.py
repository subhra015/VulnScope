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


# Shared singleton instance
settings = Settings()
