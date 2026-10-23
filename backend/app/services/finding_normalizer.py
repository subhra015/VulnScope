"""
Finding Normalization Service.
Transforms heterogeneous raw scanner outputs (Semgrep, Gitleaks, OSV-Scanner)
into a unified, sanitized, repository-relative finding schema.
"""

from dataclasses import dataclass
import hashlib
from pathlib import Path, PureWindowsPath, PurePosixPath
import re
from typing import Any, Dict, List, Optional, Set, Tuple


@dataclass
class NormalizedFindingData:
    """Normalized finding representation ready for persistence."""
    scan_id: str
    scanner_name: str
    category: str  # "code", "secret", "dependency"
    rule_id: str
    title: str
    description: str
    severity: str  # "critical", "high", "medium", "low", "info"
    confidence: Optional[str] = None
    file_path: Optional[str] = None
    start_line: Optional[int] = None
    end_line: Optional[int] = None
    package_name: Optional[str] = None
    package_version: Optional[str] = None
    ecosystem: Optional[str] = None
    fixed_version: Optional[str] = None
    redacted_evidence: Optional[str] = None
    remediation_guidance: Optional[str] = None
    advisory_url: Optional[str] = None
    finding_fingerprint: Optional[str] = None


class FindingNormalizer:
    """
    Normalizes and deduplicates findings from multiple security scanners.
    """

    @staticmethod
    def normalize_relative_path(raw_path: Optional[str], target_dir: Optional[Path] = None) -> Optional[str]:
        """
        Convert an arbitrary filesystem path into a safe, normalized, repository-relative path.
        Replaces Windows backslashes with forward slashes and removes traversal tokens.
        Never exposes server directory roots.
        """
        if not raw_path:
            return None

        clean = str(raw_path).replace("\\", "/").strip()

        # If target_dir provided, strip target_dir path prefix
        if target_dir:
            target_str = str(target_dir).replace("\\", "/").rstrip("/")
            if clean.lower().startswith(target_str.lower()):
                clean = clean[len(target_str) :].lstrip("/")

        # Strip drive letter if present (e.g. C:/ or D:/)
        clean = re.sub(r"^[a-zA-Z]:[/]?", "", clean)

        # Remove leading ./ or /
        clean = clean.lstrip("./").lstrip("/")

        # Protect against path traversal tokens
        parts = [p for p in clean.split("/") if p and p not in (".", "..")]
        result = "/".join(parts)
        return result or None

    @staticmethod
    def compute_fingerprint(
        scanner_name: str,
        rule_id: str,
        file_path: Optional[str],
        start_line: Optional[int] = None,
        package_name: Optional[str] = None,
        package_version: Optional[str] = None,
    ) -> str:
        """
        Generate a deterministic SHA-256 fingerprint for a finding.
        Used for stable identification and regression tracking across repeated scans.
        """
        tokens = [
            scanner_name.lower().strip(),
            rule_id.lower().strip(),
            (file_path or "").lower().strip(),
            str(start_line or ""),
            (package_name or "").lower().strip(),
            (package_version or "").lower().strip(),
        ]
        key = ":".join(tokens)
        return hashlib.sha256(key.encode("utf-8")).hexdigest()

    # --- Semgrep Normalization ---
    @classmethod
    def normalize_semgrep_finding(
        cls, raw: Dict[str, Any], scan_id: str, target_dir: Optional[Path] = None
    ) -> NormalizedFindingData:
        check_id = raw.get("check_id", "semgrep.rule")
        extra = raw.get("extra", {})
        metadata = extra.get("metadata", {})

        # Title and description
        msg = extra.get("message", "").strip() or check_id
        # Take first sentence or up to 200 chars for title
        title_line = msg.splitlines()[0] if msg else check_id
        title = title_line[:200]
        description = msg

        # File path and positions
        raw_path = raw.get("path")
        rel_path = cls.normalize_relative_path(raw_path, target_dir)

        start_info = raw.get("start", {})
        end_info = raw.get("end", {})
        start_line = start_info.get("line") if isinstance(start_info, dict) else None
        end_line = end_info.get("line") if isinstance(end_info, dict) else None

        # Severity mapping
        raw_sev = str(extra.get("severity", "")).upper()
        if raw_sev == "ERROR":
            severity = "high"
        elif raw_sev == "WARNING":
            severity = "medium"
        elif raw_sev == "INFO":
            severity = "low"
        else:
            severity = "medium"

        # Confidence
        raw_conf = metadata.get("confidence")
        confidence = str(raw_conf).lower() if raw_conf else None

        # Advisory URL / references
        advisory_url = None
        refs = metadata.get("references")
        if isinstance(refs, list) and refs:
            advisory_url = str(refs[0])
        elif isinstance(metadata.get("source"), str):
            advisory_url = str(metadata["source"])

        # Remediation
        guidance = None
        cwe = metadata.get("cwe")
        owasp = metadata.get("owasp")
        guidance_parts = []
        if cwe:
            guidance_parts.append(f"CWE: {', '.join(cwe) if isinstance(cwe, list) else cwe}")
        if owasp:
            guidance_parts.append(f"OWASP: {', '.join(owasp) if isinstance(owasp, list) else owasp}")
        if guidance_parts:
            guidance = " | ".join(guidance_parts)

        fingerprint = cls.compute_fingerprint("semgrep", check_id, rel_path, start_line)

        return NormalizedFindingData(
            scan_id=scan_id,
            scanner_name="semgrep",
            category="code",
            rule_id=check_id[:200],
            title=title,
            description=description,
            severity=severity,
            confidence=confidence,
            file_path=rel_path,
            start_line=start_line,
            end_line=end_line,
            remediation_guidance=guidance,
            advisory_url=advisory_url,
            finding_fingerprint=fingerprint,
        )

    # --- Gitleaks Normalization ---
    @classmethod
    def normalize_gitleaks_finding(
        cls, raw: Dict[str, Any], scan_id: str, target_dir: Optional[Path] = None
    ) -> NormalizedFindingData:
        rule_id = raw.get("RuleID", "generic-secret")
        rel_path = cls.normalize_relative_path(raw.get("File"), target_dir)
        start_line = raw.get("StartLine")
        end_line = raw.get("EndLine")

        title = f"Exposed Secret: {rule_id}"
        # Strictly generic description — NEVER include secret values
        description = "Potential exposed credential detected in source code."

        fingerprint = cls.compute_fingerprint("gitleaks", rule_id, rel_path, start_line)

        return NormalizedFindingData(
            scan_id=scan_id,
            scanner_name="gitleaks",
            category="secret",
            rule_id=str(rule_id)[:200],
            title=title[:255],
            description=description,
            severity="critical",
            confidence="high",
            file_path=rel_path,
            start_line=start_line,
            end_line=end_line,
            redacted_evidence="[REDACTED SECRET EVIDENCE]",
            remediation_guidance="Revoke this credential immediately, rotate all associated access tokens, and purge secret from history.",
            finding_fingerprint=fingerprint,
        )

    # --- OSV-Scanner Normalization ---
    @classmethod
    def normalize_osv_finding(
        cls, raw: Dict[str, Any], scan_id: str, target_dir: Optional[Path] = None
    ) -> NormalizedFindingData:
        vuln = raw.get("vuln", {})
        vuln_id = vuln.get("id", "UNKNOWN-VULN")
        pkg_name = raw.get("package_name", "unknown")
        pkg_version = raw.get("package_version", "")
        ecosystem = raw.get("ecosystem", "")
        rel_path = cls.normalize_relative_path(raw.get("source_path"), target_dir)

        # Aliases (e.g. CVE-2023-xxxx)
        aliases = vuln.get("aliases", [])
        primary_id = vuln_id
        if aliases and isinstance(aliases, list):
            # Prefer CVE as rule_id if available, but keep vuln_id
            for a in aliases:
                if str(a).upper().startswith("CVE-"):
                    primary_id = str(a)
                    break

        summary = vuln.get("summary", "")
        details = vuln.get("details", "")
        title = summary if summary else f"Vulnerability {primary_id} in {pkg_name}"
        if pkg_version:
            title += f" ({pkg_version})"
        title = title[:255]

        description = details if details else (summary or "Known vulnerability reported in dependency package.")

        # Severity determination: inspect database_specific or CVSS
        severity = "medium"
        db_spec = vuln.get("database_specific", {})
        if isinstance(db_spec, dict) and "severity" in db_spec:
            spec_sev = str(db_spec["severity"]).lower()
            if spec_sev in ("critical", "high", "medium", "low"):
                severity = spec_sev

        # Check CVSS if present
        vuln_severities = vuln.get("severity", [])
        if isinstance(vuln_severities, list):
            for s_entry in vuln_severities:
                score_str = s_entry.get("score") if isinstance(s_entry, dict) else None
                if score_str and "CVSS" in str(s_entry.get("type", "")):
                    val: Optional[float] = None
                    # First check for score in parentheses, e.g. "(7.5 High)" or "(7.5)"
                    paren_match = re.search(r"\(\s*(\d+(?:\.\d+)?)\b", str(score_str))
                    if paren_match:
                        val = float(paren_match.group(1))
                    else:
                        # Otherwise find floats, skipping the CVSS version prefix (e.g. CVSS:3.1/)
                        floats = re.findall(r"\b(\d+\.\d+)\b", str(score_str))
                        if len(floats) > 1 and str(score_str).startswith("CVSS:"):
                            # Skip the version number (e.g. 3.0, 3.1)
                            val = float(floats[-1])
                        elif floats:
                            val = float(floats[0])

                    if val is not None:
                        if val >= 9.0:
                            severity = "critical"
                        elif val >= 7.0:
                            severity = "high"
                        elif val >= 4.0:
                            severity = "medium"
                        else:
                            severity = "low"

        # Fixed version extraction
        fixed_version = None
        for aff in vuln.get("affected", []):
            for rng in aff.get("ranges", []):
                for event in rng.get("events", []):
                    if "fixed" in event:
                        fixed_version = str(event["fixed"])
                        break
                if fixed_version:
                    break
            if fixed_version:
                break

        # Advisory references
        advisory_url = None
        refs = vuln.get("references", [])
        if isinstance(refs, list) and refs:
            for r in refs:
                if isinstance(r, dict) and r.get("url"):
                    advisory_url = str(r["url"])
                    break

        remediation = None
        if fixed_version:
            remediation = f"Upgrade {pkg_name} to version {fixed_version} or later."
        else:
            remediation = f"No fixed version currently recorded for {pkg_name}."

        fingerprint = cls.compute_fingerprint(
            "osv-scanner", primary_id, rel_path, package_name=pkg_name, package_version=pkg_version
        )

        return NormalizedFindingData(
            scan_id=scan_id,
            scanner_name="osv-scanner",
            category="dependency",
            rule_id=primary_id[:200],
            title=title,
            description=description,
            severity=severity,
            confidence="high",
            file_path=rel_path,
            package_name=pkg_name[:255] if pkg_name else None,
            package_version=pkg_version[:100] if pkg_version else None,
            ecosystem=ecosystem[:100] if ecosystem else None,
            fixed_version=fixed_version[:100] if fixed_version else None,
            remediation_guidance=remediation,
            advisory_url=advisory_url,
            finding_fingerprint=fingerprint,
        )

    @classmethod
    def normalize_all(
        cls,
        scanner_results: List[Tuple[str, List[Dict[str, Any]]]],
        scan_id: str,
        target_dir: Optional[Path] = None,
    ) -> List[NormalizedFindingData]:
        """
        Normalize findings from all scanner runs, performing intra-scan deduplication
        based on fingerprint while preserving distinct rules and vulnerabilities.
        """
        seen_fingerprints: Set[str] = set()
        normalized_list: List[NormalizedFindingData] = []

        for scanner_name, raw_findings in scanner_results:
            for raw in raw_findings:
                finding: Optional[NormalizedFindingData] = None
                if scanner_name == "semgrep":
                    finding = cls.normalize_semgrep_finding(raw, scan_id, target_dir)
                elif scanner_name == "gitleaks":
                    finding = cls.normalize_gitleaks_finding(raw, scan_id, target_dir)
                elif scanner_name in ("osv-scanner", "osv"):
                    finding = cls.normalize_osv_finding(raw, scan_id, target_dir)

                if finding:
                    fp = finding.finding_fingerprint
                    if fp and fp in seen_fingerprints:
                        continue
                    if fp:
                        seen_fingerprints.add(fp)
                    normalized_list.append(finding)

        return normalized_list
