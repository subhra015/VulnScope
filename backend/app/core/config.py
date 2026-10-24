"""
Application configuration loaded from environment variables.
Uses pydantic-settings so every field can be overridden via .env or the shell.
"""

import os
from pathlib import Path
from typing import List, Optional
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

    # --- Real Security Scanners Engine (Phase 3) ---
    # Configurable paths to scanner binaries (default searches PATH and backend/tools/bin)
    semgrep_binary_path: str = Field(default="semgrep")
    gitleaks_binary_path: str = Field(default="gitleaks")
    osv_scanner_binary_path: str = Field(default="osv-scanner")

    # Scanner execution timeouts (seconds)
    semgrep_timeout_seconds: float = 120.0
    gitleaks_timeout_seconds: float = 60.0
    osv_scanner_timeout_seconds: float = 90.0

    # Output capture limit to prevent unbounded memory consumption (bytes) - default 20 MB
    max_scanner_output_bytes: int = 20 * 1024 * 1024

    # Maximum number of security scans that can run concurrently
    max_concurrent_scans: int = 2

    # Semgrep rules configuration (e.g. "p/default", "p/ci", "auto")
    semgrep_rules_config: str = "p/default"

    # --- Phase 5: AI-Assisted Remediation & Safe Fix Previews ---
    # Provider: "disabled", "ollama", "openai"
    ai_provider: str = Field(default="disabled")
    # Base URL for AI provider (e.g., "http://localhost:11434" for ollama or "https://api.openai.com/v1" for openai)
    ai_base_url: Optional[str] = None
    # Model name (e.g., "llama3", "codellama", "gpt-4o-mini")
    ai_model: str = Field(default="default")
    # API key for remote providers (strictly secret, never logged or exposed in API)
    ai_api_key: Optional[str] = None
    # Request timeout in seconds
    ai_timeout_seconds: float = 30.0
    # Maximum output token limit for AI response
    ai_max_output_tokens: int = 2000
    # Maximum bounded retry attempts for malformed responses
    ai_max_retries: int = 1
    # Require explicit user-visible opt-in before sending any source snippet to a remote provider
    ai_remote_opt_in_required: bool = True
    # Maximum lines around finding to include in source snippet (before + after)
    ai_max_snippet_lines: int = 20
    # Maximum bytes for source code snippet
    ai_max_snippet_bytes: int = 4096

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

    def resolve_scanner_binary(self, scanner_name: str) -> Optional[str]:
        """
        Resolves the executable path for a given scanner ('semgrep', 'gitleaks', 'osv-scanner').
        Checks configured setting, system PATH, local backend/tools/bin, and common script locations.
        Returns the resolved executable path as a string, or None if unavailable.
        """
        import shutil
        import sys

        configured_path: str = ""
        if scanner_name == "semgrep":
            configured_path = self.semgrep_binary_path
        elif scanner_name == "gitleaks":
            configured_path = self.gitleaks_binary_path
        elif scanner_name in ("osv-scanner", "osv"):
            configured_path = self.osv_scanner_binary_path

        # 1. Direct configured path if it exists as an actual file
        p = Path(configured_path)
        if not p.is_absolute():
            # Check relative to backend dir
            cand = (BACKEND_DIR / p).resolve()
            if cand.is_file() and os.access(cand, os.X_OK):
                return str(cand)
        elif p.is_file() and os.access(p, os.X_OK):
            return str(p)

        # 2. Check system PATH via shutil.which
        which_result = shutil.which(configured_path)
        if which_result:
            return which_result

        # Also try default tool name in PATH if configured path had an extension or custom name
        base_name = "osv-scanner" if scanner_name in ("osv", "osv-scanner") else scanner_name
        which_default = shutil.which(base_name)
        if which_default:
            return which_default

        # 3. Check backend/tools/bin/
        tools_bin = BACKEND_DIR / "tools" / "bin"
        for ext in ("", ".exe", ".cmd", ".bat"):
            cand = tools_bin / f"{base_name}{ext}"
            if cand.is_file() and os.access(cand, os.X_OK):
                return str(cand)

        # 4. Check current Python environment Scripts directory (e.g. for semgrep.exe)
        py_scripts = Path(sys.executable).parent / "Scripts"
        for ext in ("", ".exe"):
            cand = py_scripts / f"{base_name}{ext}"
            if cand.is_file() and os.access(cand, os.X_OK):
                return str(cand)

        return None

    def is_ai_enabled(self) -> bool:
        """Check if an active AI provider is configured."""
        return self.ai_provider.strip().lower() in ("ollama", "openai")

    def is_ai_remote(self) -> bool:
        """Check if current AI provider is an external/remote service."""
        return self.ai_provider.strip().lower() == "openai"

    def get_validated_ai_endpoint(self) -> str:
        """
        Validates AI provider configuration and returns a safe base URL.
        Enforces HTTPS for remote providers and restricts local providers to localhost/127.0.0.1.
        Raises ValueError if configuration is invalid or presents SSRF risk.
        """
        from urllib.parse import urlparse

        provider = self.ai_provider.strip().lower()
        if provider == "disabled":
            return ""

        if provider == "ollama":
            url = self.ai_base_url or "http://localhost:11434"
            parsed = urlparse(url)
            if parsed.scheme not in ("http", "https"):
                raise ValueError("Ollama base URL must use http or https scheme.")
            hostname = (parsed.hostname or "").lower()
            if hostname not in ("localhost", "127.0.0.1", "::1"):
                raise ValueError(
                    f"Local Ollama provider is restricted to loopback interfaces (localhost, 127.0.0.1). "
                    f"Invalid host: '{hostname}'"
                )
            return url.rstrip("/")

        if provider == "openai":
            url = self.ai_base_url or "https://api.openai.com/v1"
            parsed = urlparse(url)
            if parsed.scheme != "https":
                raise ValueError("Remote OpenAI provider base URL must use HTTPS scheme.")
            hostname = (parsed.hostname or "").lower()
            # Block internal metadata endpoints and link-local addresses
            if hostname in ("169.254.169.254", "metadata.google.internal", "instance-data"):
                raise ValueError("Access to cloud instance metadata services is forbidden.")
            return url.rstrip("/")

        raise ValueError(f"Unsupported AI provider '{self.ai_provider}'. Must be 'disabled', 'ollama', or 'openai'.")


# Shared singleton instance
settings = Settings()
