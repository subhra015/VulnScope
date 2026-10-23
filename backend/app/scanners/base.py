"""
Base scanner interfaces and data structures.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class ScannerResult:
    """
    Standard result returned by a scanner adapter before normalization.
    """
    scanner_name: str
    status: str  # "completed", "failed", "unavailable", "timed_out"
    scanner_version: Optional[str] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    duration_seconds: float = 0.0
    raw_findings: List[Dict[str, Any]] = field(default_factory=list)
    error_message: Optional[str] = None

    @property
    def is_success(self) -> bool:
        return self.status == "completed"


class BaseScanner(ABC):
    """
    Abstract base class for security scanner tool adapters.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Name of the scanner (e.g. 'semgrep', 'gitleaks', 'osv-scanner')."""
        pass

    @property
    @abstractmethod
    def category(self) -> str:
        """Category of findings ('code', 'secret', 'dependency')."""
        pass

    @abstractmethod
    def is_available(self) -> bool:
        """Check whether the scanner binary is installed and executable."""
        pass

    @abstractmethod
    def get_version(self) -> Optional[str]:
        """Query and return the installed scanner version."""
        pass

    @abstractmethod
    def scan(self, target_dir: Path, scan_id: str, workspace_root: Optional[Path] = None) -> ScannerResult:
        """
        Execute the scanner on the target directory and return raw findings.
        `workspace_root` allows writing temporary artifacts outside the source tree.
        """
        pass
