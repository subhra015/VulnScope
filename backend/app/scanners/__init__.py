"""
VulnScope Scanners Package.
Provides adapters for external security scanners (Semgrep, Gitleaks, OSV-Scanner).
"""

from app.scanners.base import BaseScanner, ScannerResult
from app.scanners.semgrep import SemgrepScanner
from app.scanners.gitleaks import GitleaksScanner
from app.scanners.osv_scanner import OSVScanner

__all__ = [
    "BaseScanner",
    "ScannerResult",
    "SemgrepScanner",
    "GitleaksScanner",
    "OSVScanner",
]
