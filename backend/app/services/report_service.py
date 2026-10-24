"""
Professional Security Report Generation Service.
Generates comprehensive, publication-ready security audit reports in JSON, HTML, and PDF formats.
Enforces strict secret redaction, HTML escaping, server path masking, and coverage caveat disclosures.
"""

from datetime import datetime, timezone
import html
import io
import json
from typing import Any, Dict, List, Optional
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.pdfgen import canvas
from reportlab.platypus import (
    HRFlowable,
    KeepTogether,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.finding import Finding
from app.models.remediation_proposal import RemediationProposal
from app.models.scan import Scan
from app.models.scanner_run import ScannerRun
from app.services.ai.sanitizer import RedactionService
from app.services.finding_normalizer import FindingNormalizer
from app.services.lifecycle_service import LifecycleService
from app.services.remediation_service import RemediationService
from app.services.risk_scorer import RiskScorer


class NumberedCanvas(canvas.Canvas):
    """
    Two-pass canvas to dynamically compute and render total page count
    along with running header and footer.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_decorations(num_pages)
            super().showPage()
        super().save()

    def draw_page_decorations(self, page_count: int):
        self.saveState()
        self.setFont("Helvetica", 8)
        self.setFillColor(colors.HexColor("#64748b"))

        # Running Header (pages > 1)
        if self._pageNumber > 1:
            self.drawString(54, 750, "VulnScope Security Audit Report")
            self.setStrokeColor(colors.HexColor("#e2e8f0"))
            self.setLineWidth(0.5)
            self.line(54, 744, 558, 744)

        # Running Footer
        page_str = f"Page {self._pageNumber} of {page_count}"
        self.drawRightString(558, 36, page_str)
        self.drawString(54, 36, "CONFIDENTIAL — FOR AUTHORIZED AUDIT USE ONLY")
        self.setStrokeColor(colors.HexColor("#e2e8f0"))
        self.setLineWidth(0.5)
        self.line(54, 46, 558, 46)

        self.restoreState()


class ReportService:
    """
    Service for generating security audit reports across multiple formats.
    """

    @classmethod
    def assemble_report_data(cls, scan: Scan, db: Session) -> Dict[str, Any]:
        """
        Assemble and sanitize all required scan, finding, scanner, and proposal metadata.
        """
        # Ensure finding scores
        findings: List[Finding] = scan.findings or []
        for f in findings:
            if f.risk_score is None:
                exp = RiskScorer.score_finding(f)
                f.risk_score = exp.score
                f.priority = exp.priority

        # Compute summary stats
        priority_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        category_counts = {"code": 0, "secret": 0, "dependency": 0}

        scores = []
        sanitized_findings = []
        for f in sorted(findings, key=lambda x: (x.risk_score or 0), reverse=True):
            p = (f.priority or "medium").lower()
            if p in priority_counts:
                priority_counts[p] += 1
            s = (f.severity or "medium").lower()
            if s in severity_counts:
                severity_counts[s] += 1
            cat = (f.category or "code").lower()
            if cat in category_counts:
                category_counts[cat] += 1

            score = f.risk_score if f.risk_score is not None else 50
            scores.append(score)

            # Get deterministic guidance
            det_guidance = RemediationService.get_guidance_for_finding(f)

            # Check if an AI proposal exists
            proposal = next((p for p in (scan.remediation_proposals or []) if p.finding_id == f.id), None)
            proposal_dict = None
            if proposal:
                proposal_dict = {
                    "id": proposal.id,
                    "status": proposal.status,
                    "provider": proposal.provider,
                    "model_name": proposal.model_name,
                    "explanation": RedactionService.redact_secrets(proposal.explanation),
                    "likely_root_cause": RedactionService.redact_secrets(proposal.likely_root_cause),
                    "potential_impact": RedactionService.redact_secrets(proposal.potential_impact),
                    "remediation_steps": [RedactionService.redact_secrets(s) for s in proposal.remediation_steps],
                    "secure_coding_pattern": RedactionService.redact_secrets(proposal.secure_coding_pattern) if proposal.secure_coding_pattern else None,
                    "patch_appropriate": proposal.patch_appropriate,
                    "change_summary": RedactionService.redact_secrets(proposal.change_summary) if proposal.change_summary else None,
                    "has_diff": bool(proposal.diff_content),
                    "is_verified": proposal.status == "verified_by_rescan",
                }

            # Normalize file path to prevent server directory exposure
            rel_path = FindingNormalizer.normalize_relative_path(f.file_path)

            sanitized_findings.append({
                "id": f.id,
                "title": RedactionService.redact_secrets(f.title),
                "description": RedactionService.redact_secrets(f.description),
                "rule_id": f.rule_id,
                "scanner_name": f.scanner_name,
                "category": f.category or "code",
                "severity": f.severity,
                "priority": f.priority or "medium",
                "risk_score": score,
                "file_path": rel_path,
                "start_line": f.start_line,
                "end_line": f.end_line,
                "package_name": f.package_name,
                "package_version": f.package_version,
                "fixed_version": f.fixed_version,
                "ecosystem": f.ecosystem,
                "advisory_url": f.advisory_url,
                "remediation_summary": RedactionService.redact_secrets(det_guidance.summary),
                "remediation_steps": [RedactionService.redact_secrets(s) for s in det_guidance.steps],
                "ai_proposal": proposal_dict,
            })

        mean_score = round(sum(scores) / len(scores), 1) if scores else 0.0
        max_score = max(scores) if scores else 0

        # Scanner runs
        scanner_runs_data = []
        coverage_limitations = []

        if scan.status == "partial":
            coverage_limitations.append("Scan completed with 'partial' status. One or more configured scanners failed or timed out.")
        elif scan.status == "failed":
            coverage_limitations.append("Scan completed with 'failed' status. Findings may be incomplete.")

        for sr in (scan.scanner_runs or []):
            duration = sr.duration_seconds
            scanner_runs_data.append({
                "scanner_name": sr.scanner_name,
                "status": sr.status,
                "version": sr.scanner_version or "N/A",
                "duration_seconds": duration,
                "findings_count": sr.findings_count,
                "error_message": sr.error_message,
            })
            if sr.status in ("failed", "unavailable", "timed_out"):
                coverage_limitations.append(
                    f"Scanner '{sr.scanner_name}' had status '{sr.status}' ({sr.error_message or 'execution error'}). Coverage for this tool is incomplete."
                )

        if not findings and scan.status == "completed":
            coverage_limitations.append(
                "Zero findings were detected across all configured scanners. Note: Zero findings does not imply complete immunity from vulnerabilities."
            )

        # Baseline comparison if available
        comparison_summary = None
        if scan.repository_id:
            earlier_scan = db.scalars(
                select(Scan)
                .where(
                    Scan.repository_id == scan.repository_id,
                    Scan.id != scan.id,
                    Scan.created_at < scan.created_at,
                    Scan.status.in_(["completed", "partial"]),
                )
                .order_by(Scan.created_at.desc())
            ).first()

            if earlier_scan:
                try:
                    comp_res = LifecycleService.compare_scans(db, scan, earlier_scan)
                    comparison_summary = {
                        "baseline_scan_id": earlier_scan.id,
                        "baseline_created_at": earlier_scan.created_at.isoformat(),
                        "new_count": comp_res.summary.get("new", 0),
                        "recurring_count": comp_res.summary.get("recurring", 0),
                        "resolved_count": comp_res.summary.get("resolved", 0),
                        "changed_count": comp_res.summary.get("changed", 0),
                        "unconfirmed_count": comp_res.summary.get("unconfirmed", 0),
                    }
                except Exception:
                    pass

        return {
            "report_title": "VulnScope Security Audit & Remediation Report",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "scan_id": scan.id,
            "project_name": RedactionService.redact_secrets(scan.project_name),
            "source_type": scan.source_type,
            "source_reference": RedactionService.redact_secrets(scan.source_reference or "N/A"),
            "scan_status": scan.status,
            "scan_created_at": scan.created_at.isoformat(),
            "scan_completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
            "error_summary": RedactionService.redact_secrets(scan.error_summary) if scan.error_summary else None,
            "total_findings": len(findings),
            "priority_distribution": priority_counts,
            "severity_distribution": severity_counts,
            "category_distribution": category_counts,
            "mean_risk_score": mean_score,
            "max_risk_score": max_score,
            "scanner_runs": scanner_runs_data,
            "coverage_limitations": coverage_limitations,
            "findings": sanitized_findings,
            "comparison": comparison_summary,
        }

    # -----------------------------------------------------------------------
    # JSON Report Generation
    # -----------------------------------------------------------------------
    @classmethod
    def generate_json_report(cls, scan: Scan, db: Session) -> Dict[str, Any]:
        """Generate structured, validated JSON security report."""
        return cls.assemble_report_data(scan, db)

    # -----------------------------------------------------------------------
    # HTML Report Generation
    # -----------------------------------------------------------------------
    @classmethod
    def generate_html_report(cls, scan: Scan, db: Session) -> str:
        """Generate self-contained, publication-ready, escaped HTML report."""
        data = cls.assemble_report_data(scan, db)

        def esc(val: Any) -> str:
            if val is None:
                return ""
            return html.escape(str(val))

        priority_colors = {
            "critical": "#dc2626",
            "high": "#ea580c",
            "medium": "#d97706",
            "low": "#2563eb",
        }

        # Render scanner rows
        scanner_rows = ""
        for sr in data["scanner_runs"]:
            status_color = "#16a34a" if sr["status"] == "completed" else "#dc2626"
            dur = f"{sr['duration_seconds']:.2f}s" if sr.get("duration_seconds") else "N/A"
            scanner_rows += f"""
            <tr>
              <td><strong>{esc(sr['scanner_name'])}</strong></td>
              <td><span style="color: {status_color}; font-weight: 600;">{esc(sr['status'])}</span></td>
              <td>{esc(sr['version'])}</td>
              <td>{esc(dur)}</td>
              <td>{esc(sr['findings_count'])}</td>
              <td style="color: #64748b; font-size: 12px;">{esc(sr['error_message'] or '-')}</td>
            </tr>
            """

        # Render findings items
        findings_html = ""
        for idx, f in enumerate(data["findings"], 1):
            p_color = priority_colors.get(f["priority"].lower(), "#64748b")
            loc_str = ""
            if f["file_path"]:
                loc_str = f"<code>{esc(f['file_path'])}</code>"
                if f["start_line"]:
                    loc_str += f" (Line {esc(f['start_line'])})"
            elif f["package_name"]:
                loc_str = f"Package: <code>{esc(f['package_name'])}</code> ({esc(f['package_version'] or 'unspecified')})"

            ai_html = ""
            if f.get("ai_proposal"):
                prop = f["ai_proposal"]
                verified_badge = (
                    '<span style="background: #dcfce7; color: #166534; padding: 2px 6px; border-radius: 4px; font-size: 11px;">Verified by Rescan</span>'
                    if prop["is_verified"]
                    else f'<span style="background: #fef3c7; color: #92400e; padding: 2px 6px; border-radius: 4px; font-size: 11px;">Status: {esc(prop["status"])} (Unverified Proposal)</span>'
                )

                ai_steps_html = "".join(f"<li>{esc(s)}</li>" for s in prop["remediation_steps"])
                ai_html = f"""
                <div style="margin-top: 12px; padding: 12px; background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 6px;">
                  <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                    <strong style="color: #0f172a; font-size: 13px;">AI-Assisted Remediation Proposal ({esc(prop['provider'])}/{esc(prop['model_name'])})</strong>
                    {verified_badge}
                  </div>
                  <p style="font-size: 13px; color: #334155; margin: 4px 0;"><strong>Root Cause:</strong> {esc(prop['likely_root_cause'])}</p>
                  <p style="font-size: 13px; color: #334155; margin: 4px 0;"><strong>Potential Impact:</strong> {esc(prop['potential_impact'])}</p>
                  <div style="margin-top: 6px;">
                    <strong style="font-size: 12px; color: #475569;">Recommended Steps:</strong>
                    <ol style="font-size: 12px; margin: 4px 0 4px 20px; color: #334155;">{ai_steps_html}</ol>
                  </div>
                  {f'<p style="font-size: 12px; color: #2563eb; margin-top: 6px;">Patch available: {esc(prop["change_summary"] or "Source code diff generated")}</p>' if prop.get("has_diff") else ''}
                  <p style="font-size: 11px; color: #94a3b8; margin-top: 6px; font-style: italic;">Note: Model-generated proposals must be reviewed by developers and validated by a subsequent security rescan.</p>
                </div>
                """

            steps_html = "".join(f"<li>{esc(s)}</li>" for s in f["remediation_steps"])

            findings_html += f"""
            <div style="margin-bottom: 24px; padding: 16px; background: #ffffff; border: 1px solid #e2e8f0; border-radius: 8px; box-shadow: 0 1px 2px rgba(0,0,0,0.05);">
              <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 8px;">
                <div>
                  <span style="display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 12px; font-weight: 700; color: #fff; background-color: {p_color}; margin-right: 8px;">
                    Priority: {esc(f['priority'].upper())} ({esc(f['risk_score'])}/100)
                  </span>
                  <span style="font-size: 12px; color: #64748b; text-transform: uppercase; font-weight: 600;">
                    {esc(f['scanner_name'])} • {esc(f['category'])} • Original Severity: {esc(f['severity'].upper())}
                  </span>
                  <h3 style="margin: 6px 0 2px 0; font-size: 16px; color: #0f172a;">#{idx}. {esc(f['title'])}</h3>
                  <div style="font-size: 12px; color: #475569; margin-bottom: 6px;">Rule ID: <code>{esc(f['rule_id'])}</code></div>
                </div>
              </div>
              <div style="font-size: 13px; color: #475569; margin-bottom: 8px;">{loc_str}</div>
              <p style="font-size: 13px; color: #334155; line-height: 1.5; margin-bottom: 12px;">{esc(f['description'])}</p>
              
              <div style="background: #f1f5f9; padding: 10px; border-radius: 6px;">
                <strong style="font-size: 12px; color: #1e293b;">Deterministic Remediation Guidance:</strong>
                <p style="font-size: 12px; color: #334155; margin: 4px 0 6px 0;">{esc(f['remediation_summary'])}</p>
                <ol style="font-size: 12px; margin: 0 0 0 18px; color: #334155;">{steps_html}</ol>
              </div>
              {ai_html}
            </div>
            """

        limitations_html = "".join(f"<li>{esc(l)}</li>" for l in data["coverage_limitations"])

        comparison_html = ""
        if data.get("comparison"):
            c = data["comparison"]
            comparison_html = f"""
            <div style="background: #f8fafc; border: 1px solid #cbd5e1; border-radius: 8px; padding: 16px; margin-bottom: 24px;">
              <h3 style="margin-top: 0; color: #0f172a; font-size: 16px;">Finding Lifecycle Evolution (vs Baseline {esc(c['baseline_scan_id'][:8])})</h3>
              <p style="font-size: 13px; color: #475569;">Compared against prior scan from {esc(c['baseline_created_at'])}:</p>
              <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(100px, 1fr)); gap: 12px; text-align: center;">
                <div style="background: #fff; padding: 8px; border-radius: 6px; border: 1px solid #e2e8f0;">
                  <div style="font-size: 20px; font-weight: 700; color: #dc2626;">{esc(c['new_count'])}</div>
                  <div style="font-size: 11px; color: #64748b;">New</div>
                </div>
                <div style="background: #fff; padding: 8px; border-radius: 6px; border: 1px solid #e2e8f0;">
                  <div style="font-size: 20px; font-weight: 700; color: #ea580c;">{esc(c['recurring_count'])}</div>
                  <div style="font-size: 11px; color: #64748b;">Recurring</div>
                </div>
                <div style="background: #fff; padding: 8px; border-radius: 6px; border: 1px solid #e2e8f0;">
                  <div style="font-size: 20px; font-weight: 700; color: #16a34a;">{esc(c['resolved_count'])}</div>
                  <div style="font-size: 11px; color: #64748b;">Resolved</div>
                </div>
                <div style="background: #fff; padding: 8px; border-radius: 6px; border: 1px solid #e2e8f0;">
                  <div style="font-size: 20px; font-weight: 700; color: #2563eb;">{esc(c['changed_count'])}</div>
                  <div style="font-size: 11px; color: #64748b;">Changed</div>
                </div>
              </div>
            </div>
            """

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>{esc(data['report_title'])} — {esc(data['project_name'])}</title>
  <style>
    body {{
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      line-height: 1.5;
      color: #0f172a;
      background: #f8fafc;
      margin: 0;
      padding: 32px;
    }}
    .container {{
      max-width: 1000px;
      margin: 0 auto;
      background: #ffffff;
      padding: 40px;
      border-radius: 12px;
      box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
    }}
    .header {{
      border-bottom: 2px solid #e2e8f0;
      padding-bottom: 20px;
      margin-bottom: 24px;
    }}
    h1 {{ margin: 0 0 8px 0; font-size: 24px; color: #0f172a; }}
    h2 {{ font-size: 18px; color: #1e293b; margin: 24px 0 12px 0; border-bottom: 1px solid #e2e8f0; padding-bottom: 6px; }}
    table {{ width: 100%; border-collapse: collapse; margin: 12px 0; font-size: 13px; }}
    th, td {{ padding: 10px 12px; text-align: left; border-bottom: 1px solid #e2e8f0; }}
    th {{ background: #f8fafc; font-weight: 600; color: #475569; }}
    code {{ background: #f1f5f9; padding: 2px 4px; border-radius: 4px; font-family: monospace; font-size: 12px; }}
    .badge {{ display: inline-block; padding: 4px 8px; border-radius: 4px; font-weight: 600; font-size: 12px; }}
    .summary-grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-bottom: 24px; }}
    .summary-box {{ background: #f8fafc; padding: 16px; border-radius: 8px; border: 1px solid #e2e8f0; text-align: center; }}
    .summary-num {{ font-size: 28px; font-weight: 700; }}
    .summary-label {{ font-size: 12px; color: #64748b; font-weight: 600; text-transform: uppercase; }}
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <div style="display: flex; justify-content: space-between; align-items: center;">
        <div>
          <h1>{esc(data['report_title'])}</h1>
          <div style="font-size: 14px; color: #64748b;">
            Project: <strong>{esc(data['project_name'])}</strong> • Scan ID: <code>{esc(data['scan_id'])}</code>
          </div>
        </div>
        <div style="text-align: right; font-size: 12px; color: #64748b;">
          <div>Generated: {esc(data['generated_at'][:19])} UTC</div>
          <div>Scan Completed: {esc(str(data['scan_completed_at'])[:19] if data.get('scan_completed_at') else 'In Progress')}</div>
        </div>
      </div>
    </div>

    <!-- Executive Risk Summary -->
    <div class="summary-grid">
      <div class="summary-box">
        <div class="summary-num" style="color: #0f172a;">{esc(data['total_findings'])}</div>
        <div class="summary-label">Total Findings</div>
      </div>
      <div class="summary-box">
        <div class="summary-num" style="color: #dc2626;">{esc(data['priority_distribution']['critical'])}</div>
        <div class="summary-label">Priority Critical</div>
      </div>
      <div class="summary-box">
        <div class="summary-num" style="color: #ea580c;">{esc(data['priority_distribution']['high'])}</div>
        <div class="summary-label">Priority High</div>
      </div>
      <div class="summary-box">
        <div class="summary-num" style="color: #2563eb;">{esc(data['mean_risk_score'])}</div>
        <div class="summary-label">Mean Risk Score</div>
      </div>
    </div>

    {comparison_html}

    <!-- Coverage Limitations & Disclaimers -->
    <div style="background: #fffbeb; border: 1px solid #fef3c7; border-left: 4px solid #f59e0b; border-radius: 6px; padding: 12px; margin-bottom: 24px;">
      <strong style="color: #92400e; font-size: 13px;">Important Audit Coverage Disclosures:</strong>
      <ul style="font-size: 12px; color: #78350f; margin: 4px 0 0 20px;">{limitations_html}</ul>
    </div>

    <!-- Scanner Runs Table -->
    <h2>Scanner Engine Execution Outcomes</h2>
    <table>
      <thead>
        <tr>
          <th>Scanner</th>
          <th>Status</th>
          <th>Version</th>
          <th>Duration</th>
          <th>Findings</th>
          <th>Notes</th>
        </tr>
      </thead>
      <tbody>
        {scanner_rows}
      </tbody>
    </table>

    <!-- Detailed Findings Catalog -->
    <h2>Security Findings & Remediation Proposals</h2>
    {findings_html if findings_html else '<p style="color: #64748b;">No security findings recorded for this scan.</p>'}
  </div>
</body>
</html>
"""

    # -----------------------------------------------------------------------
    # PDF Report Generation
    # -----------------------------------------------------------------------
    @classmethod
    def generate_pdf_report(cls, scan: Scan, db: Session) -> bytes:
        """
        Generate publication-quality PDF report using ReportLab with clean styling,
        proper flowable tables, and dynamic headers/footers.
        """
        data = cls.assemble_report_data(scan, db)
        buffer = io.BytesIO()

        # Letter size (612 x 792 pt), margins: 54 pt (0.75 in)
        doc = SimpleDocTemplate(
            buffer,
            pagesize=letter,
            leftMargin=54,
            rightMargin=54,
            topMargin=54,
            bottomMargin=54,
        )

        styles = getSampleStyleSheet()

        title_style = ParagraphStyle(
            "ReportTitle",
            parent=styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=20,
            leading=24,
            textColor=colors.HexColor("#0f172a"),
            spaceAfter=6,
        )

        subtitle_style = ParagraphStyle(
            "ReportSubtitle",
            parent=styles["Normal"],
            fontName="Helvetica",
            fontSize=10,
            leading=14,
            textColor=colors.HexColor("#64748b"),
            spaceAfter=14,
        )

        h2_style = ParagraphStyle(
            "Heading2Custom",
            parent=styles["Heading2"],
            fontName="Helvetica-Bold",
            fontSize=14,
            leading=18,
            textColor=colors.HexColor("#1e293b"),
            spaceBefore=14,
            spaceAfter=8,
        )

        body_style = ParagraphStyle(
            "BodyCustom",
            parent=styles["Normal"],
            fontName="Helvetica",
            fontSize=9,
            leading=13,
            textColor=colors.HexColor("#334155"),
            spaceAfter=4,
        )

        table_header_style = ParagraphStyle(
            "TableHeader",
            parent=styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=8,
            leading=10,
            textColor=colors.HexColor("#0f172a"),
        )

        table_cell_style = ParagraphStyle(
            "TableCell",
            parent=styles["Normal"],
            fontName="Helvetica",
            fontSize=8,
            leading=10,
            textColor=colors.HexColor("#334155"),
        )

        callout_style = ParagraphStyle(
            "Callout",
            parent=styles["Normal"],
            fontName="Helvetica-Oblique",
            fontSize=8,
            leading=11,
            textColor=colors.HexColor("#78350f"),
        )

        story = []

        # 1. Header Banner
        story.append(Paragraph(data["report_title"], title_style))
        proj_meta = f"Project: <b>{data['project_name']}</b> | Scan ID: <code>{data['scan_id'][:12]}...</code> | Generated: {data['generated_at'][:19]} UTC"
        story.append(Paragraph(proj_meta, subtitle_style))
        story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#e2e8f0"), spaceAfter=12))

        # 2. Executive Summary Metrics Table
        story.append(Paragraph("Executive Risk Summary", h2_style))
        summary_table_data = [
            [
                Paragraph("<b>Total Findings</b>", table_header_style),
                Paragraph("<b>Priority Critical</b>", table_header_style),
                Paragraph("<b>Priority High</b>", table_header_style),
                Paragraph("<b>Priority Medium</b>", table_header_style),
                Paragraph("<b>Priority Low</b>", table_header_style),
                Paragraph("<b>Mean Risk Score</b>", table_header_style),
            ],
            [
                Paragraph(str(data["total_findings"]), table_cell_style),
                Paragraph(str(data["priority_distribution"]["critical"]), table_cell_style),
                Paragraph(str(data["priority_distribution"]["high"]), table_cell_style),
                Paragraph(str(data["priority_distribution"]["medium"]), table_cell_style),
                Paragraph(str(data["priority_distribution"]["low"]), table_cell_style),
                Paragraph(f"{data['mean_risk_score']}/100", table_cell_style),
            ],
        ]

        summary_table = Table(summary_table_data, colWidths=[84] * 6)
        summary_table.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f8fafc")),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ])
        )
        story.append(summary_table)
        story.append(Spacer(1, 10))

        # 3. Limitations & Disclosures Callout
        limitations_text = "<b>Audit Coverage Limitations & Disclosures:</b><br/>" + "<br/>".join(
            f"• {lim}" for lim in data["coverage_limitations"]
        )
        limitations_table = Table(
            [[Paragraph(limitations_text, callout_style)]],
            colWidths=[504],
        )
        limitations_table.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#fef3c7")),
                ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#f59e0b")),
                ("TOPPADDING", (0, 0), (-1, -1), 8),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
                ("LEFTPADDING", (0, 0), (-1, -1), 10),
                ("RIGHTPADDING", (0, 0), (-1, -1), 10),
            ])
        )
        story.append(limitations_table)
        story.append(Spacer(1, 12))

        # 4. Scanner Engines Table
        story.append(Paragraph("Scanner Engine Execution Status", h2_style))
        scanner_table_data = [
            [
                Paragraph("<b>Scanner</b>", table_header_style),
                Paragraph("<b>Status</b>", table_header_style),
                Paragraph("<b>Version</b>", table_header_style),
                Paragraph("<b>Duration</b>", table_header_style),
                Paragraph("<b>Findings</b>", table_header_style),
                Paragraph("<b>Notes</b>", table_header_style),
            ]
        ]
        for sr in data["scanner_runs"]:
            dur = f"{sr['duration_seconds']:.2f}s" if sr.get("duration_seconds") else "N/A"
            scanner_table_data.append([
                Paragraph(sr["scanner_name"], table_cell_style),
                Paragraph(sr["status"], table_cell_style),
                Paragraph(sr["version"], table_cell_style),
                Paragraph(dur, table_cell_style),
                Paragraph(str(sr["findings_count"]), table_cell_style),
                Paragraph(sr["error_message"] or "Clean run", table_cell_style),
            ])

        scanner_table = Table(scanner_table_data, colWidths=[90, 70, 70, 60, 54, 160])
        scanner_table.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f8fafc")),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ])
        )
        story.append(scanner_table)
        story.append(Spacer(1, 14))

        # 5. Detailed Findings Section
        story.append(Paragraph("Security Findings & Verified Guidance", h2_style))

        if not data["findings"]:
            story.append(Paragraph("No security findings were detected in this scan.", body_style))
        else:
            for idx, f in enumerate(data["findings"], 1):
                p_text = f"<b>Priority: {f['priority'].upper()} ({f['risk_score']}/100)</b> | {f['scanner_name'].upper()} | Severity: {f['severity'].upper()}"
                f_title = f"#{idx}. {f['title']}"

                loc = ""
                if f["file_path"]:
                    loc = f"File: <code>{f['file_path']}</code>"
                    if f["start_line"]:
                        loc += f" (Line {f['start_line']})"
                elif f["package_name"]:
                    loc = f"Dependency: <code>{f['package_name']}</code> ({f['package_version'] or 'unspecified'})"

                rem_summary = f"<b>Remediation Guidance:</b> {f['remediation_summary']}"
                steps_text = "<br/>".join(f"• {s}" for s in f["remediation_steps"])

                finding_elements = [
                    Paragraph(f_title, ParagraphStyle("FTitle", parent=styles["Normal"], fontName="Helvetica-Bold", fontSize=11, leading=14, textColor=colors.HexColor("#0f172a"))),
                    Paragraph(p_text, ParagraphStyle("FSub", parent=styles["Normal"], fontName="Helvetica", fontSize=8, leading=11, textColor=colors.HexColor("#64748b"))),
                    Paragraph(loc, body_style) if loc else Spacer(1, 1),
                    Paragraph(f["description"], body_style),
                    Paragraph(rem_summary, body_style),
                    Paragraph(steps_text, ParagraphStyle("FSteps", parent=styles["Normal"], fontName="Helvetica", fontSize=8, leading=11, textColor=colors.HexColor("#1e293b"))),
                ]

                # If AI proposal present
                if f.get("ai_proposal"):
                    prop = f["ai_proposal"]
                    ai_title = f"<b>AI Remediation Suggestion ({prop['provider']}/{prop['model_name']}) — Status: {prop['status']}</b>"
                    ai_body = f"Impact: {prop['potential_impact']}<br/>Root Cause: {prop['likely_root_cause']}"
                    finding_elements.extend([
                        Spacer(1, 4),
                        Paragraph(ai_title, ParagraphStyle("AITitle", parent=styles["Normal"], fontName="Helvetica-Bold", fontSize=8, leading=11, textColor=colors.HexColor("#2563eb"))),
                        Paragraph(ai_body, ParagraphStyle("AIBody", parent=styles["Normal"], fontName="Helvetica-Oblique", fontSize=8, leading=10, textColor=colors.HexColor("#475569"))),
                    ])

                finding_elements.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#cbd5e1"), spaceBefore=6, spaceAfter=8))
                story.append(KeepTogether(finding_elements))

        # Build PDF with dynamic NumberedCanvas
        doc.build(story, canvasmaker=NumberedCanvas)
        return buffer.getvalue()
