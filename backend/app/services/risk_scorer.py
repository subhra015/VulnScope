"""
VulnScope Finding Risk Prioritization Engine.
Provides deterministic, explainable finding-risk scoring and priority classification.
"""

from dataclasses import asdict, dataclass, field
import re
from typing import Any, Dict, List, Optional


@dataclass
class ScoringFactor:
    """Represents a single input factor contributing to the final risk score."""
    name: str
    weight: float
    raw_score: float
    contribution: float
    description: str


@dataclass
class RiskExplanation:
    """Complete, transparent explanation for a finding's risk score."""
    score: int
    priority: str  # "critical", "high", "medium", "low"
    priority_label: str  # "Critical", "High", "Medium", "Low"
    factors: List[ScoringFactor]
    evidence: Dict[str, Any]
    reason: str
    missing_evidence: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "score": self.score,
            "priority": self.priority,
            "priority_label": self.priority_label,
            "factors": [asdict(f) for f in self.factors],
            "evidence": self.evidence,
            "reason": self.reason,
            "missing_evidence": self.missing_evidence,
        }


class RiskScorer:
    """
    Deterministic finding-risk prioritization engine.

    The model evaluates four weighted dimensions:
    1. Base Severity / CVSS (50%): Uses authoritative CVSS (0-10 scale -> 0-100) when available for
       dependencies to avoid double-counting. Otherwise maps scanner severity.
    2. Confidence / Tool Reliability (20%): Evaluates scanner confidence level.
    3. Category & Exploitability Signal (20%): Distinguishes exposed credentials, high-impact
       code vulnerability classes (e.g. injection, RCE, auth bypass), and unpatched dependencies.
    4. Context & Actionability (10%): Evaluates file/line precision and explicit asset context.
    """

    # High-impact vulnerability regex patterns for code findings
    HIGH_IMPACT_CODE_PATTERNS = re.compile(
        r"(sql[_-]?injection|command[_-]?injection|remote[_-]?code|rce|code[_-]?exec"
        r"|deserializ|unpickle|path[_-]?traversal|arbitrary[_-]?file|auth[_-]?bypass"
        r"|hardcoded[_-]?password|ssrf|open[_-]?redirect|taint)",
        re.IGNORECASE,
    )

    MEDIUM_IMPACT_CODE_PATTERNS = re.compile(
        r"(xss|cross[_-]?site|csrf|cors|cookie|crypto|cipher|hash|leak|info[_-]?disclosure)",
        re.IGNORECASE,
    )

    @classmethod
    def calculate_score(
        cls,
        severity: Optional[str],
        confidence: Optional[str] = None,
        category: Optional[str] = None,
        rule_id: Optional[str] = None,
        cvss_score: Optional[float] = None,
        file_path: Optional[str] = None,
        start_line: Optional[int] = None,
        package_name: Optional[str] = None,
        package_version: Optional[str] = None,
        fixed_version: Optional[str] = None,
        asset_context: Optional[Dict[str, Any]] = None,
    ) -> RiskExplanation:
        """
        Compute an explainable, bounded risk priority score between 0 and 100.
        Never relies on ungrounded assumptions or LLMs.
        """
        missing_evidence: List[str] = []
        factors: List[ScoringFactor] = []

        # Normalization of strings
        norm_sev = (severity or "").strip().lower()
        norm_conf = (confidence or "").strip().lower() if confidence else None
        norm_cat = (category or "").strip().lower() if category else None
        norm_rule = (rule_id or "").strip()

        # -------------------------------------------------------------
        # 1. Base Severity / CVSS Dimension (Weight: 0.50)
        # -------------------------------------------------------------
        base_weight = 0.50
        if cvss_score is not None and 0.0 <= cvss_score <= 10.0:
            # Scale CVSS (0-10) to 0-100 directly. Avoids double-counting scanner severity.
            base_score = float(cvss_score * 10.0)
            base_desc = f"CVSS v3 base score ({cvss_score:.1f}/10) used as authoritative base severity metric."
        else:
            if cvss_score is not None:
                missing_evidence.append(f"CVSS score '{cvss_score}' was out of bounds (0-10); falling back to scanner severity.")

            if norm_sev == "critical":
                base_score = 95.0
                base_desc = "Scanner classified finding severity as Critical."
            elif norm_sev == "high":
                base_score = 80.0
                base_desc = "Scanner classified finding severity as High."
            elif norm_sev == "medium":
                base_score = 50.0
                base_desc = "Scanner classified finding severity as Medium."
            elif norm_sev == "low":
                base_score = 25.0
                base_desc = "Scanner classified finding severity as Low."
            elif norm_sev == "info":
                base_score = 10.0
                base_desc = "Scanner classified finding severity as Informational."
            else:
                base_score = 50.0
                base_desc = "Scanner severity unspecified or unrecognized; applied conservative Medium baseline (50.0)."
                missing_evidence.append("Scanner-provided severity was missing or unrecognized; defaulted to Medium baseline.")

            if norm_cat == "dependency" and cvss_score is None:
                missing_evidence.append("No CVSS base score provided by scanner or advisory; evaluated using qualitative severity.")

        base_contrib = base_score * base_weight
        factors.append(ScoringFactor(
            name="Base Severity / CVSS",
            weight=base_weight,
            raw_score=round(base_score, 1),
            contribution=round(base_contrib, 2),
            description=base_desc,
        ))

        # -------------------------------------------------------------
        # 2. Confidence / Reliability Dimension (Weight: 0.20)
        # -------------------------------------------------------------
        conf_weight = 0.20
        if norm_conf == "high":
            conf_score = 95.0
            conf_desc = "High confidence rule/detection with high signal-to-noise ratio."
        elif norm_conf == "medium":
            conf_score = 70.0
            conf_desc = "Medium confidence detection reported by scanner."
        elif norm_conf == "low":
            conf_score = 40.0
            conf_desc = "Low confidence rule detection; potential false-positive margin."
        else:
            conf_score = 65.0
            conf_desc = "Scanner did not report confidence metric; applied conservative default (65.0)."
            missing_evidence.append("Confidence score not reported by scanner; defaulted to 65.0.")

        conf_contrib = conf_score * conf_weight
        factors.append(ScoringFactor(
            name="Detection Confidence",
            weight=conf_weight,
            raw_score=round(conf_score, 1),
            contribution=round(conf_contrib, 2),
            description=conf_desc,
        ))

        # -------------------------------------------------------------
        # 3. Category & Exploitability Signal Dimension (Weight: 0.20)
        # -------------------------------------------------------------
        cat_weight = 0.20
        if norm_cat == "secret":
            cat_score = 95.0
            cat_desc = "Secret / credential exposure carries immediate blast radius and credential abuse risk."
        elif norm_cat == "code":
            if cls.HIGH_IMPACT_CODE_PATTERNS.search(norm_rule):
                cat_score = 85.0
                cat_desc = f"High-impact vulnerability pattern detected ({norm_rule})."
            elif cls.MEDIUM_IMPACT_CODE_PATTERNS.search(norm_rule):
                cat_score = 65.0
                cat_desc = f"Moderate-impact code flaw detected ({norm_rule})."
            else:
                cat_score = 45.0
                cat_desc = "Standard code quality or security rule detection."
        elif norm_cat == "dependency":
            if not fixed_version:
                cat_score = 75.0
                cat_desc = "Dependency vulnerability currently has no verified upstream fixed version (unpatched)."
            else:
                cat_score = 60.0
                cat_desc = f"Dependency vulnerability with known fixed version ({fixed_version})."
        else:
            cat_score = 50.0
            cat_desc = "General security finding category."
            missing_evidence.append("Finding category was unspecified; neutral category baseline applied.")

        cat_contrib = cat_score * cat_weight
        factors.append(ScoringFactor(
            name="Category & Exploitability",
            weight=cat_weight,
            raw_score=round(cat_score, 1),
            contribution=round(cat_contrib, 2),
            description=cat_desc,
        ))

        # -------------------------------------------------------------
        # 4. Context & Actionability Dimension (Weight: 0.10)
        # -------------------------------------------------------------
        context_weight = 0.10
        context_score = 60.0  # Base neutral actionability
        context_notes = []

        if file_path and start_line is not None:
            context_score += 20.0
            context_notes.append("Pinpointed to exact source file and line number.")
        elif file_path:
            context_score += 10.0
            context_notes.append("Located within specific source file.")

        if package_name and package_version:
            context_score += 15.0
            context_notes.append(f"Identified package coordinates ({package_name}@{package_version}).")

        # Explicit asset/repository context (only if explicitly supplied)
        if asset_context and isinstance(asset_context, dict):
            if asset_context.get("is_public"):
                context_score += 5.0
                context_notes.append("Repository is marked public.")
            if asset_context.get("is_production"):
                context_score += 10.0
                context_notes.append("Target asset is flagged as production environment.")
        else:
            missing_evidence.append("No runtime environment or network-exposure metadata provided; neutral context applied.")

        # Clamp context score to 100
        context_score = max(0.0, min(100.0, context_score))
        context_desc = " ".join(context_notes) if context_notes else "General project context."

        context_contrib = context_score * context_weight
        factors.append(ScoringFactor(
            name="Context & Actionability",
            weight=context_weight,
            raw_score=round(context_score, 1),
            contribution=round(context_contrib, 2),
            description=context_desc,
        ))

        # -------------------------------------------------------------
        # Aggregate Final Score and Priority Label
        # -------------------------------------------------------------
        total_raw = sum(f.contribution for f in factors)
        final_score = int(round(max(0.0, min(100.0, total_raw))))

        if final_score >= 85:
            priority = "critical"
            priority_label = "Critical"
        elif final_score >= 70:
            priority = "high"
            priority_label = "High"
        elif final_score >= 40:
            priority = "medium"
            priority_label = "Medium"
        else:
            priority = "low"
            priority_label = "Low"

        # Human-readable reason
        if norm_cat == "secret":
            reason = f"Critical priority secret finding (score {final_score}/100) due to exposed credentials in code repository."
        elif cvss_score is not None:
            reason = f"{priority_label} priority dependency vulnerability (score {final_score}/100) driven by CVSS {cvss_score:.1f} base metric."
        else:
            reason = f"{priority_label} priority {norm_cat or 'security'} finding (score {final_score}/100) driven by scanner severity '{norm_sev or 'unknown'}'."

        evidence = {
            "scanner_severity": norm_sev or None,
            "confidence": norm_conf,
            "category": norm_cat,
            "rule_id": norm_rule or None,
            "cvss_score": cvss_score,
            "file_path": file_path,
            "start_line": start_line,
            "package_name": package_name,
            "package_version": package_version,
            "fixed_version": fixed_version,
        }

        return RiskExplanation(
            score=final_score,
            priority=priority,
            priority_label=priority_label,
            factors=factors,
            evidence=evidence,
            reason=reason,
            missing_evidence=missing_evidence,
        )

    @classmethod
    def score_finding(cls, finding: Any, asset_context: Optional[Dict[str, Any]] = None) -> RiskExplanation:
        """Helper to score a Finding model instance or dict-like finding object."""
        # Extract attributes from SQLAlchemy model or dict
        def get_attr(key: str, default: Any = None) -> Any:
            if isinstance(finding, dict):
                return finding.get(key, default)
            return getattr(finding, key, default)

        return cls.calculate_score(
            severity=get_attr("severity"),
            confidence=get_attr("confidence"),
            category=get_attr("category"),
            rule_id=get_attr("rule_id"),
            cvss_score=get_attr("cvss_score"),
            file_path=get_attr("file_path"),
            start_line=get_attr("start_line"),
            package_name=get_attr("package_name"),
            package_version=get_attr("package_version"),
            fixed_version=get_attr("fixed_version"),
            asset_context=asset_context,
        )
