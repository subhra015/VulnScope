"""
VulnScope Finding Lifecycle and Scan Comparison Service.
Tracks finding evolution (new, recurring, resolved, changed) across comparable scans
while strictly preventing false resolution claims from partial or failed scanners.
"""

from dataclasses import asdict, dataclass, field
import logging
from typing import Any, Dict, List, Optional, Set, Tuple

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.finding import Finding
from app.models.scan import Scan
from app.models.scanner_run import ScannerRun

logger = logging.getLogger(__name__)


class ScanComparabilityError(Exception):
    """Raised when two scans cannot be safely or validly compared."""
    pass


@dataclass
class FindingChangeDetail:
    field: str
    old_value: Any
    new_value: Any


@dataclass
class ComparisonFindingItem:
    finding_id: str
    scan_id: str
    scanner_name: str
    category: Optional[str]
    rule_id: str
    title: str
    severity: str
    file_path: Optional[str]
    start_line: Optional[int]
    package_name: Optional[str]
    package_version: Optional[str]
    fixed_version: Optional[str]
    lifecycle_status: str  # "new", "recurring", "resolved", "changed", "unconfirmed"
    changes: List[FindingChangeDetail] = field(default_factory=list)
    risk_score: Optional[int] = None
    priority: Optional[str] = None


@dataclass
class ScanComparisonResult:
    scan_id: str
    baseline_scan_id: str
    repository_id: Optional[str]
    summary: Dict[str, int]  # new, recurring, resolved, changed, unconfirmed, total_target, total_baseline
    new_findings: List[ComparisonFindingItem]
    recurring_findings: List[ComparisonFindingItem]
    resolved_findings: List[ComparisonFindingItem]
    changed_findings: List[ComparisonFindingItem]
    unconfirmed_findings: List[ComparisonFindingItem]
    comparability_notes: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "baseline_scan_id": self.baseline_scan_id,
            "repository_id": self.repository_id,
            "summary": self.summary,
            "new_findings": [asdict(f) for f in self.new_findings],
            "recurring_findings": [asdict(f) for f in self.recurring_findings],
            "resolved_findings": [asdict(f) for f in self.resolved_findings],
            "changed_findings": [asdict(f) for f in self.changed_findings],
            "unconfirmed_findings": [asdict(f) for f in self.unconfirmed_findings],
            "comparability_notes": self.comparability_notes,
        }


class LifecycleService:
    """
    Manages finding lifecycle tracking and comparative scan diffs.
    """

    @classmethod
    def validate_comparability(cls, target_scan: Scan, baseline_scan: Scan) -> None:
        """
        Validate that target and baseline scans belong to the same lineage and are in eligible states.
        Raises ScanComparabilityError if invalid.
        """
        if target_scan.id == baseline_scan.id:
            raise ScanComparabilityError("A scan cannot be compared against itself.")

        # Lineage check: repository ID match or project name + source type match
        if target_scan.repository_id and baseline_scan.repository_id:
            if target_scan.repository_id != baseline_scan.repository_id:
                raise ScanComparabilityError(
                    f"Scans belong to different repositories ({target_scan.repository_id} vs {baseline_scan.repository_id}) and cannot be compared."
                )
        elif (
            target_scan.project_name.lower() != baseline_scan.project_name.lower()
            or target_scan.source_type.lower() != baseline_scan.source_type.lower()
        ):
            raise ScanComparabilityError(
                f"Scans belong to different projects ('{target_scan.project_name}' vs '{baseline_scan.project_name}') and cannot be compared."
            )

        # Status check
        if target_scan.status in ("created", "running", "queued"):
            raise ScanComparabilityError(
                f"Target scan '{target_scan.id}' is still in status '{target_scan.status}'. Scans must be completed before comparison."
            )

        if baseline_scan.status in ("created", "running", "queued"):
            raise ScanComparabilityError(
                f"Baseline scan '{baseline_scan.id}' is still in status '{baseline_scan.status}'. Scans must be completed before comparison."
            )

        if baseline_scan.status == "failed":
            raise ScanComparabilityError(
                f"Baseline scan '{baseline_scan.id}' failed. A failed scan cannot serve as an eligible baseline for lifecycle comparison."
            )

    @classmethod
    def find_latest_baseline(cls, db: Session, target_scan: Scan) -> Optional[Scan]:
        """
        Locate the most recent eligible completed/partial baseline scan for the same repository lineage.
        """
        stmt = (
            select(Scan)
            .where(
                Scan.id != target_scan.id,
                Scan.created_at < target_scan.created_at,
                Scan.status.in_(["completed", "partial"]),
            )
        )
        if target_scan.repository_id:
            stmt = stmt.where(Scan.repository_id == target_scan.repository_id)
        else:
            stmt = stmt.where(
                Scan.project_name == target_scan.project_name,
                Scan.source_type == target_scan.source_type,
            )

        stmt = stmt.order_by(Scan.created_at.desc()).limit(1)
        return db.scalars(stmt).first()

    @classmethod
    def _fallback_key(cls, finding: Finding) -> Tuple[str, str, str]:
        """
        Fallback matching tuple for finding identity when line numbers shift or path separators vary:
        - For dependency findings: (scanner_name, rule_id, package_name)
        - For code & secret findings: (scanner_name, rule_id, normalized_file_path)
        """
        s_name = (finding.scanner_name or "").lower().strip()
        r_id = (finding.rule_id or "").lower().strip()
        cat = (finding.category or "").lower().strip()

        if cat == "dependency" and finding.package_name:
            second_key = finding.package_name.lower().strip()
        else:
            second_key = (finding.file_path or "").lower().replace("\\", "/").strip()

        return (s_name, r_id, second_key)

    @classmethod
    def _detect_changes(cls, target: Finding, baseline: Finding) -> List[FindingChangeDetail]:
        """Detect meaningful attribute differences between matching findings."""
        changes: List[FindingChangeDetail] = []
        if (target.start_line or None) != (baseline.start_line or None):
            changes.append(FindingChangeDetail("start_line", baseline.start_line, target.start_line))
        if (target.severity or "").lower() != (baseline.severity or "").lower():
            changes.append(FindingChangeDetail("severity", baseline.severity, target.severity))
        if (target.package_version or "").lower() != (baseline.package_version or "").lower():
            changes.append(FindingChangeDetail("package_version", baseline.package_version, target.package_version))
        if (target.fixed_version or "").lower() != (baseline.fixed_version or "").lower():
            changes.append(FindingChangeDetail("fixed_version", baseline.fixed_version, target.fixed_version))
        if (target.title or "").strip() != (baseline.title or "").strip():
            changes.append(FindingChangeDetail("title", baseline.title, target.title))
        return changes

    @classmethod
    def _to_comparison_item(
        cls,
        finding: Finding,
        lifecycle_status: str,
        changes: Optional[List[FindingChangeDetail]] = None,
    ) -> ComparisonFindingItem:
        return ComparisonFindingItem(
            finding_id=finding.id,
            scan_id=finding.scan_id,
            scanner_name=finding.scanner_name,
            category=finding.category,
            rule_id=finding.rule_id,
            title=finding.title,
            severity=finding.severity,
            file_path=finding.file_path,
            start_line=finding.start_line,
            package_name=finding.package_name,
            package_version=finding.package_version,
            fixed_version=finding.fixed_version,
            lifecycle_status=lifecycle_status,
            changes=changes or [],
            risk_score=finding.risk_score,
            priority=finding.priority,
        )

    @classmethod
    def compare_scans(
        cls,
        db: Session,
        target_scan: Scan,
        baseline_scan: Scan,
    ) -> ScanComparisonResult:
        """
        Compare target scan against baseline scan and classify findings into lifecycle states:
        - new: in target, not in baseline
        - recurring: in target and baseline unchanged
        - changed: in target and baseline with modified attributes
        - resolved: in baseline, absent from target where scanner succeeded
        - unconfirmed: in baseline, absent from target BUT scanner was unavailable/failed
        """
        cls.validate_comparability(target_scan, baseline_scan)

        comparability_notes: List[str] = []

        # Coverage analysis from ScannerRun records
        target_runs: Dict[str, ScannerRun] = {
            sr.scanner_name.lower(): sr for sr in target_scan.scanner_runs
        }
        baseline_runs: Dict[str, ScannerRun] = {
            sr.scanner_name.lower(): sr for sr in baseline_scan.scanner_runs
        }

        # Check for partial scans or failed tools in target scan
        if target_scan.status == "partial":
            comparability_notes.append(
                "Target scan completed partially. Some scanners may have failed, which limits resolution claims."
            )

        successful_target_scanners: Set[str] = {
            name for name, run in target_runs.items() if run.status == "completed"
        }
        failed_or_missing_target_scanners: Set[str] = set()

        for name, run in baseline_runs.items():
            if run.status == "completed":
                t_run = target_runs.get(name)
                if not t_run or t_run.status != "completed":
                    failed_or_missing_target_scanners.add(name)
                    comparability_notes.append(
                        f"Scanner '{name}' completed in baseline but was {t_run.status if t_run else 'missing'} in target scan; "
                        "associated baseline findings cannot be confirmed as resolved."
                    )

        target_findings = target_scan.findings or []
        baseline_findings = baseline_scan.findings or []

        # Index baseline findings
        baseline_by_fp: Dict[str, Finding] = {}
        baseline_by_fallback: Dict[Tuple[str, str, str], Finding] = {}
        for b in baseline_findings:
            if b.finding_fingerprint:
                baseline_by_fp[b.finding_fingerprint] = b
            fallback = cls._fallback_key(b)
            if fallback not in baseline_by_fallback:
                baseline_by_fallback[fallback] = b

        matched_baseline_ids: Set[str] = set()

        new_items: List[ComparisonFindingItem] = []
        recurring_items: List[ComparisonFindingItem] = []
        changed_items: List[ComparisonFindingItem] = []
        resolved_items: List[ComparisonFindingItem] = []
        unconfirmed_items: List[ComparisonFindingItem] = []

        # Iterate target findings to find matches in baseline
        for tf in target_findings:
            match: Optional[Finding] = None

            # Primary match: deterministic fingerprint
            if tf.finding_fingerprint and tf.finding_fingerprint in baseline_by_fp:
                candidate = baseline_by_fp[tf.finding_fingerprint]
                if candidate.id not in matched_baseline_ids:
                    match = candidate

            # Fallback match: heuristic identity
            if not match:
                fallback = cls._fallback_key(tf)
                candidate = baseline_by_fallback.get(fallback)
                if candidate and candidate.id not in matched_baseline_ids:
                    match = candidate

            if match:
                matched_baseline_ids.add(match.id)
                changes = cls._detect_changes(tf, match)
                if changes:
                    changed_items.append(cls._to_comparison_item(tf, "changed", changes))
                else:
                    recurring_items.append(cls._to_comparison_item(tf, "recurring"))
            else:
                new_items.append(cls._to_comparison_item(tf, "new"))

        # Examine unmatched baseline findings
        for bf in baseline_findings:
            if bf.id in matched_baseline_ids:
                continue

            scanner = (bf.scanner_name or "").lower().strip()
            # If the scanner ran successfully in the target scan, the finding is safely resolved
            if scanner in successful_target_scanners:
                resolved_items.append(cls._to_comparison_item(bf, "resolved"))
            else:
                # If the scanner failed or was unavailable, we DO NOT falsely claim resolution!
                unconfirmed_items.append(cls._to_comparison_item(bf, "unconfirmed"))

        summary = {
            "new": len(new_items),
            "recurring": len(recurring_items),
            "resolved": len(resolved_items),
            "changed": len(changed_items),
            "unconfirmed": len(unconfirmed_items),
            "total_target": len(target_findings),
            "total_baseline": len(baseline_findings),
        }

        return ScanComparisonResult(
            scan_id=target_scan.id,
            baseline_scan_id=baseline_scan.id,
            repository_id=target_scan.repository_id,
            summary=summary,
            new_findings=new_items,
            recurring_findings=recurring_items,
            resolved_findings=resolved_items,
            changed_findings=changed_items,
            unconfirmed_findings=unconfirmed_items,
            comparability_notes=comparability_notes,
        )

    @classmethod
    def get_finding_lifecycle_status(
        cls,
        db: Session,
        target_scan: Scan,
        finding: Finding,
        baseline_scan: Optional[Scan] = None,
    ) -> str:
        """Get the lifecycle status of an individual finding relative to a baseline scan."""
        if not baseline_scan:
            baseline_scan = cls.find_latest_baseline(db, target_scan)

        if not baseline_scan:
            return "new"

        try:
            comparison = cls.compare_scans(db, target_scan, baseline_scan)
        except ScanComparabilityError:
            return "new"

        for item in comparison.new_findings:
            if item.finding_id == finding.id:
                return "new"
        for item in comparison.recurring_findings:
            if item.finding_id == finding.id:
                return "recurring"
        for item in comparison.changed_findings:
            if item.finding_id == finding.id:
                return "changed"

        return "new"
