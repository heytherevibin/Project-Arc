"""
Report generators for different report types.

Provides:
- Executive Summary: High-level risk overview for leadership
- Technical Report: Detailed findings with reproduction steps
- Remediation Report: Prioritised remediation plan with effort estimates
- Compliance Report: Framework compliance gap analysis
- Report Builder: Orchestrator that composes data for all formats
"""

from reporting.generators.executive_summary import ExecutiveSummaryGenerator, ExecutiveSummary
from reporting.generators.technical_report import TechnicalReportGenerator, TechnicalReport
from reporting.generators.remediation_report import RemediationReportGenerator, RemediationReport
from reporting.generators.compliance_report import ComplianceReportGenerator, ComplianceReport
from reporting.generators.report_builder import ReportBuilder, ReportData

__all__ = [
    "ExecutiveSummaryGenerator",
    "ExecutiveSummary",
    "TechnicalReportGenerator",
    "TechnicalReport",
    "RemediationReportGenerator",
    "RemediationReport",
    "ComplianceReportGenerator",
    "ComplianceReport",
    "ReportBuilder",
    "ReportData",
]
