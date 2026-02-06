"""
Markdown Report Templates

Renders report data structures into well-formatted Markdown documents
suitable for conversion to PDF, HTML, or direct consumption.
"""

from __future__ import annotations

from typing import Any

from reporting.generators.technical_report import TechnicalReport, TechnicalFinding
from reporting.generators.executive_summary import ExecutiveSummary
from reporting.generators.remediation_report import RemediationReport
from reporting.generators.compliance_report import ComplianceReport


class MarkdownTemplates:
    """Renders reports to Markdown format."""

    # ---- Executive Summary ---------------------------------------------------
    @staticmethod
    def render_executive_summary(summary: ExecutiveSummary) -> str:
        lines = [
            f"# {summary.title}",
            "",
            f"**Assessment Date:** {summary.assessment_date}",
            f"**Target:** {summary.target}",
            f"**Risk Rating:** {summary.risk_rating} ({summary.risk_score}/10.0)",
            "",
            "## Executive Summary",
            "",
            summary.executive_narrative,
            "",
            "## Findings Overview",
            "",
            "| Severity | Count |",
            "|----------|-------|",
            f"| Critical | {summary.critical_findings} |",
            f"| High | {summary.high_findings} |",
            f"| Medium | {summary.medium_findings} |",
            f"| Low | {summary.low_findings} |",
            f"| **Total** | **{summary.total_findings}** |",
            "",
            "## Attack Surface",
            "",
        ]

        for label, count in summary.attack_surface.items():
            lines.append(f"- **{label}:** {count}")

        lines.extend([
            "",
            "## Recommendations",
            "",
        ])
        for idx, rec in enumerate(summary.recommendations, 1):
            lines.append(f"{idx}. {rec}")

        if summary.top_vulnerabilities:
            lines.extend([
                "",
                "## Top Vulnerabilities",
                "",
                "| # | Name | Severity | Target |",
                "|---|------|----------|--------|",
            ])
            for idx, v in enumerate(summary.top_vulnerabilities, 1):
                lines.append(
                    f"| {idx} | {v.get('name', '')} | {v.get('severity', '')} "
                    f"| {v.get('target', '')} |"
                )

        lines.append("")
        return "\n".join(lines)

    # ---- Technical Report ----------------------------------------------------
    @staticmethod
    def render_technical_report(report: TechnicalReport) -> str:
        lines = [
            f"# {report.title}",
            "",
            f"**Generated:** {report.generated_at}",
            f"**Target:** {report.target}",
            "",
            "## Methodology",
            "",
            report.methodology,
            "",
            "## Summary Statistics",
            "",
            f"- **Total Findings:** {report.stats.get('total_findings', 0)}",
            f"  - Critical: {report.stats.get('critical', 0)}",
            f"  - High: {report.stats.get('high', 0)}",
            f"  - Medium: {report.stats.get('medium', 0)}",
            f"  - Low: {report.stats.get('low', 0)}",
            f"- **Hosts Discovered:** {report.stats.get('total_hosts', 0)}",
            f"- **Services Identified:** {report.stats.get('total_services', 0)}",
            f"- **Attack Paths Found:** {report.stats.get('attack_paths_found', 0)}",
            "",
            "---",
            "",
            "## Detailed Findings",
            "",
        ]

        for idx, finding in enumerate(report.findings, 1):
            lines.extend(MarkdownTemplates._render_finding(idx, finding))

        if report.hosts:
            lines.extend([
                "---",
                "",
                "## Host Enumeration",
                "",
                "| Hostname | IPs | Ports |",
                "|----------|-----|-------|",
            ])
            for h in report.hosts[:50]:
                ips = ", ".join(h.get("ips", [])[:5])
                ports_list = h.get("ports", [])
                ports = ", ".join(str(p.get("port", "")) for p in ports_list[:10]) if isinstance(ports_list, list) else ""
                lines.append(f"| {h.get('hostname', '')} | {ips} | {ports} |")

        if report.technologies:
            lines.extend([
                "",
                "## Technologies Detected",
                "",
                "| Technology | Version | Category |",
                "|------------|---------|----------|",
            ])
            for t in report.technologies[:30]:
                lines.append(
                    f"| {t.get('name', '')} | {t.get('version', 'N/A')} "
                    f"| {t.get('category', 'N/A')} |"
                )

        lines.append("")
        return "\n".join(lines)

    @staticmethod
    def _render_finding(idx: int, finding: TechnicalFinding) -> list[str]:
        sev_badge = finding.severity.upper()
        lines = [
            f"### {idx}. [{sev_badge}] {finding.title}",
            "",
        ]

        if finding.cve_id:
            lines.append(f"**CVE:** {finding.cve_id}")
        if finding.cvss_score is not None:
            lines.append(f"**CVSS:** {finding.cvss_score}")
        if finding.epss_probability is not None:
            lines.append(f"**EPSS:** {finding.epss_probability:.2%}")
        if finding.affected_asset:
            lines.append(f"**Affected:** {finding.affected_asset}")

        lines.append("")

        if finding.description:
            lines.extend([
                "**Description:**",
                finding.description,
                "",
            ])

        if finding.reproduction_steps:
            lines.append("**Reproduction Steps:**")
            for step_idx, step in enumerate(finding.reproduction_steps, 1):
                lines.append(f"{step_idx}. {step}")
            lines.append("")

        if finding.remediation:
            lines.extend([
                "**Remediation:**",
                finding.remediation,
                "",
            ])

        if finding.references:
            lines.append("**References:**")
            for ref in finding.references:
                lines.append(f"- {ref}")
            lines.append("")

        return lines

    # ---- Remediation Report --------------------------------------------------
    @staticmethod
    def render_remediation_report(report: RemediationReport) -> str:
        lines = [
            f"# {report.title}",
            "",
            f"**Generated:** {report.generated_at}",
            "",
            "## Summary",
            "",
            f"- **Total Items:** {report.summary.get('total_items', 0)}",
            f"  - P1 (Critical): {report.summary.get('p1', 0)}",
            f"  - P2 (High): {report.summary.get('p2', 0)}",
            f"  - P3 (Medium): {report.summary.get('p3', 0)}",
            f"  - P4 (Low): {report.summary.get('p4', 0)}",
            f"- **Quick Wins:** {report.summary.get('quick_wins', 0)}",
            "",
        ]

        if report.quick_wins:
            lines.extend([
                "## Quick Wins",
                "",
                "These items have high security impact with low implementation effort:",
                "",
            ])
            for qw in report.quick_wins:
                lines.append(f"- {qw}")
            lines.append("")

        lines.extend([
            "---",
            "",
            "## Remediation Items",
            "",
        ])

        for item in report.items:
            lines.extend([
                f"### [{item.priority}] {item.title}",
                "",
                f"**Severity:** {item.severity}  |  "
                f"**Effort:** {item.estimated_effort}  |  "
                f"**SLA:** {item.sla_days} days",
                "",
            ])

            if item.affected_assets:
                lines.append(f"**Affected:** {', '.join(item.affected_assets[:5])}")

            if item.cve_id:
                lines.append(f"**CVE:** {item.cve_id}")

            if item.remediation_steps:
                lines.append("")
                lines.append("**Remediation Steps:**")
                for s_idx, step in enumerate(item.remediation_steps, 1):
                    lines.append(f"{s_idx}. {step}")

            if item.verification_steps:
                lines.append("")
                lines.append("**Verification:**")
                for v_idx, vstep in enumerate(item.verification_steps, 1):
                    lines.append(f"{v_idx}. {vstep}")

            lines.append("")

        return "\n".join(lines)

    # ---- Compliance Report ---------------------------------------------------
    @staticmethod
    def render_compliance_report(report: ComplianceReport) -> str:
        lines = [
            f"# {report.title}",
            "",
            f"**Generated:** {report.generated_at}",
            f"**Frameworks Assessed:** {', '.join(report.frameworks_assessed)}",
            f"**Overall Compliance:** {report.overall_compliance}%",
            "",
            "## Framework Summaries",
            "",
            "| Framework | Controls | Compliant | Non-Compliant | Partial | Not Tested | Compliance % |",
            "|-----------|----------|-----------|---------------|---------|------------|-------------|",
        ]

        for s in report.framework_summaries:
            lines.append(
                f"| {s.framework} | {s.total_controls} | {s.compliant} | "
                f"{s.non_compliant} | {s.partial} | {s.not_tested} | "
                f"{s.compliance_percentage}% |"
            )

        for s in report.framework_summaries:
            if s.critical_gaps:
                lines.extend([
                    "",
                    f"### {s.framework} — Critical Gaps",
                    "",
                ])
                for gap in s.critical_gaps:
                    lines.append(f"- {gap}")

        lines.extend([
            "",
            "## Detailed Control Mappings",
            "",
        ])

        # Group by framework
        by_fw: dict[str, list[Any]] = {}
        for m in report.mappings:
            by_fw.setdefault(m.framework, []).append(m)

        for fw, mappings in by_fw.items():
            lines.extend([
                f"### {fw}",
                "",
                "| Control | Title | Status | Findings |",
                "|---------|-------|--------|----------|",
            ])
            for m in mappings:
                finding_count = len(m.finding_ids) if m.finding_ids else 0
                status_icon = {
                    "compliant": "PASS",
                    "non_compliant": "FAIL",
                    "partial": "PARTIAL",
                    "not_tested": "N/T",
                }.get(m.status, m.status)
                lines.append(
                    f"| {m.control_id} | {m.control_title} | "
                    f"{status_icon} | {finding_count} |"
                )
            lines.append("")

        if report.recommendations:
            lines.extend([
                "## Recommendations",
                "",
            ])
            for idx, rec in enumerate(report.recommendations, 1):
                lines.append(f"{idx}. {rec}")
            lines.append("")

        return "\n".join(lines)
