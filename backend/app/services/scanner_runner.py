"""
Safe Subprocess Runner for Security Scanners.
Enforces process isolation safeguards, bounded memory output limits,
strict timeouts, and environment scrubbing.
"""

from dataclasses import dataclass
import os
from pathlib import Path
import subprocess
import sys
import time
from typing import Dict, List, Optional

from app.core.config import BACKEND_DIR, settings


@dataclass
class ProcessExecutionResult:
    """Represents the raw execution outcome of an external scanner process."""
    returncode: int
    stdout: str
    stderr: str
    duration_seconds: float
    timed_out: bool = False
    error: Optional[str] = None


class ScannerRunner:
    """
    Executes external CLI scanner commands securely with resource constraints.
    """

    SAFE_ENV_VARS = {
        "PATH",
        "PATHEXT",
        "SYSTEMROOT",
        "SYSTEMDRIVE",
        "WINDIR",
        "COMSPEC",
        "TEMP",
        "TMP",
        "TMPDIR",
        "USERPROFILE",
        "HOME",
        "HOMEDRIVE",
        "HOMEPATH",
        "LOCALAPPDATA",
        "APPDATA",
        "LANG",
        "LC_ALL",
    }

    def __init__(self, output_limit_bytes: Optional[int] = None):
        self.output_limit_bytes = (
            output_limit_bytes if output_limit_bytes is not None else settings.max_scanner_output_bytes
        )

    def get_sanitized_env(self) -> Dict[str, str]:
        """
        Produce a sanitized environment dict containing only safe system variables.
        Explicitly excludes application secrets, database credentials, and API keys.
        """
        sanitized: Dict[str, str] = {}
        for key, value in os.environ.items():
            if key.upper() in self.SAFE_ENV_VARS:
                sanitized[key] = value
        # Ensure PATH includes python scripts dir if on Windows
        if sys.platform == "win32":
            py_scripts = str(Path(sys.executable).parent / "Scripts")
            tools_bin = str(BACKEND_DIR / "tools" / "bin")
            curr_path = sanitized.get("PATH", "")
            if py_scripts not in curr_path:
                curr_path = f"{py_scripts};{curr_path}"
            if tools_bin not in curr_path:
                curr_path = f"{tools_bin};{curr_path}"
            sanitized["PATH"] = curr_path
        return sanitized

    def run(
        self,
        args: List[str],
        timeout_seconds: float,
        cwd: Optional[Path] = None,
        extra_env: Optional[Dict[str, str]] = None,
    ) -> ProcessExecutionResult:
        """
        Execute an external tool with shell=False, bounded output, and timeout.
        """
        if not args:
            raise ValueError("Command arguments list cannot be empty.")

        env = self.get_sanitized_env()
        if extra_env:
            for k, v in extra_env.items():
                env[k] = v

        start_time = time.monotonic()
        timed_out = False
        error_msg = None
        stdout_text = ""
        stderr_text = ""

        try:
            # We enforce shell=False strictly
            proc = subprocess.Popen(
                args,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.DEVNULL,
                cwd=str(cwd) if cwd else None,
                env=env,
                shell=False,
                text=False,  # Read bytes first to enforce strict byte limits
            )

            try:
                stdout_bytes, stderr_bytes = proc.communicate(timeout=timeout_seconds)
            except subprocess.TimeoutExpired:
                timed_out = True
                proc.kill()
                stdout_bytes, stderr_bytes = proc.communicate()
                error_msg = f"Scanner process timed out after {timeout_seconds} seconds."

            duration = round(time.monotonic() - start_time, 3)

            # Enforce output length limit to prevent memory exhaustion
            if len(stdout_bytes) > self.output_limit_bytes:
                stdout_bytes = stdout_bytes[: self.output_limit_bytes]
            if len(stderr_bytes) > self.output_limit_bytes:
                stderr_bytes = stderr_bytes[: self.output_limit_bytes]

            stdout_text = stdout_bytes.decode("utf-8", errors="replace")
            stderr_text = stderr_bytes.decode("utf-8", errors="replace")

            return ProcessExecutionResult(
                returncode=proc.returncode if not timed_out else -1,
                stdout=stdout_text,
                stderr=stderr_text,
                duration_seconds=duration,
                timed_out=timed_out,
                error=error_msg,
            )

        except FileNotFoundError:
            duration = round(time.monotonic() - start_time, 3)
            return ProcessExecutionResult(
                returncode=-1,
                stdout="",
                stderr="",
                duration_seconds=duration,
                timed_out=False,
                error=f"Executable '{args[0]}' not found.",
            )
        except Exception as exc:
            duration = round(time.monotonic() - start_time, 3)
            return ProcessExecutionResult(
                returncode=-1,
                stdout="",
                stderr="",
                duration_seconds=duration,
                timed_out=False,
                error=f"Scanner execution error: {type(exc).__name__}",
            )


# Default runner instance
default_scanner_runner = ScannerRunner()
