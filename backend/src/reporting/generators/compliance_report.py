"""
Compliance Report Generator

Maps penetration test findings to compliance frameworks
(PCI-DSS, HIPAA, SOC2, NIST, ISO 27001, CIS) and generates
compliance gap analysis reports.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from core.logging import get_logger
from graph.client import Neo4jClient

logger = get_logger(__name__)


@dataclass
class ComplianceMapping:
    """Mapping of a finding to a compliance control."""
    framework: str       # e.g. "PCI-DSS"
    control_id: str      # e.g. "6.5.1"
    control_title: str
    finding_ids: list[str] = field(default_factory=list)
    status: str = "non_compliant"   # "compliant" | "non_compliant" | "partial" | "not_tested"
    evidence: str = ""
    remediation: str = ""


@dataclass
class FrameworkSummary:
    """Summary of compliance posture for a single framework."""
    framework: str
    total_controls: int
    compliant: int
    non_compliant: int
    partial: int
    not_tested: int
    compliance_percentage: float
    critical_gaps: list[str] = field(default_factory=list)


@dataclass
class ComplianceReport:
    """Full compliance report across multiple frameworks."""
    title: str
    project_id: str
    generated_at: str
    frameworks_assessed: list[str] = field(default_factory=list)
    framework_summaries: list[FrameworkSummary] = field(default_factory=list)
    mappings: list[ComplianceMapping] = field(default_factory=list)
    overall_compliance: float = 0.0
    recommendations: list[str] = field(default_factory=list)


class ComplianceReportGenerator:
    """
    Maps pentest findings to compliance controls and generates
    gap-analysis reports.
    """

    # ---- Compliance framework control mappings --------------------------------
    # Maps vulnerability categories → framework controls
    FRAMEWORK_CONTROLS: dict[str, dict[str, dict[str, str]]] = {
        "PCI-DSS": {
            "sql_injection": {
                "id": "6.5.1",
                "title": "Injection flaws, particularly SQL injection",
                "remediation": "Use parameterised queries and input validation",
            },
            "xss": {
                "id": "6.5.7",
                "title": "Cross-site scripting (XSS)",
                "remediation": "Implement output encoding and CSP headers",
            },
            "weak_crypto": {
                "id": "4.1",
                "title": "Use strong cryptography and security protocols",
                "remediation": "Upgrade to TLS 1.2+ and use strong cipher suites",
            },
            "default_credentials": {
                "id": "2.1",
                "title": "Always change vendor-supplied defaults",
                "remediation": "Change all default passwords and remove unnecessary accounts",
            },
            "outdated_software": {
                "id": "6.2",
                "title": "Protect all system components from known vulnerabilities",
                "remediation": "Apply vendor patches within one month of release",
            },
            "access_control": {
                "id": "7.1",
                "title": "Limit access to system components to authorised individuals",
                "remediation": "Implement role-based access control and least privilege",
            },
            "logging": {
                "id": "10.2",
                "title": "Implement automated audit trails",
                "remediation": "Enable comprehensive logging and monitoring",
            },
            "network_segmentation": {
                "id": "1.3",
                "title": "Prohibit direct public access between internet and CDE",
                "remediation": "Implement proper network segmentation and firewall rules",
            },
        },
        "HIPAA": {
            "access_control": {
                "id": "164.312(a)(1)",
                "title": "Access Control — Unique user identification",
                "remediation": "Implement unique user IDs and access controls",
            },
            "encryption": {
                "id": "164.312(a)(2)(iv)",
                "title": "Encryption and decryption",
                "remediation": "Encrypt ePHI in transit and at rest",
            },
            "audit_controls": {
                "id": "164.312(b)",
                "title": "Audit controls",
                "remediation": "Implement mechanisms to record and examine activity",
            },
            "integrity": {
                "id": "164.312(c)(1)",
                "title": "Integrity controls",
                "remediation": "Implement electronic mechanisms to corroborate ePHI integrity",
            },
            "transmission_security": {
                "id": "164.312(e)(1)",
                "title": "Transmission security",
                "remediation": "Implement technical security measures for ePHI in transit",
            },
        },
        "NIST-800-53": {
            "access_control": {
                "id": "AC-2",
                "title": "Account Management",
                "remediation": "Implement comprehensive account management procedures",
            },
            "vulnerability_management": {
                "id": "RA-5",
                "title": "Vulnerability Scanning",
                "remediation": "Implement regular vulnerability scanning and remediation",
            },
            "configuration_management": {
                "id": "CM-6",
                "title": "Configuration Settings",
                "remediation": "Establish and enforce security configuration settings",
            },
            "incident_response": {
                "id": "IR-4",
                "title": "Incident Handling",
                "remediation": "Implement incident handling capability and procedures",
            },
            "system_integrity": {
                "id": "SI-2",
                "title": "Flaw Remediation",
                "remediation": "Identify, report, and correct information system flaws",
            },
        },
        "ISO-27001": {
            "access_control": {
                "id": "A.9.1",
                "title": "Business requirements of access control",
                "remediation": "Establish access control policy based on business requirements",
            },
            "cryptography": {
                "id": "A.10.1",
                "title": "Cryptographic controls",
                "remediation": "Develop and implement a policy on the use of cryptographic controls",
            },
            "operations_security": {
                "id": "A.12.6",
                "title": "Technical vulnerability management",
                "remediation": "Establish a vulnerability management process",
            },
            "communications_security": {
                "id": "A.13.1",
                "title": "Network security management",
                "remediation": "Manage and control networks to protect information in systems",
            },
        },
        "CIS": {
            "inventory": {
                "id": "CIS-1",
                "title": "Inventory and Control of Enterprise Assets",
                "remediation": "Maintain accurate inventory of all enterprise assets",
            },
            "software_inventory": {
                "id": "CIS-2",
                "title": "Inventory and Control of Software Assets",
                "remediation": "Maintain inventory of authorised software and track changes",
            },
            "data_protection": {
                "id": "CIS-3",
                "title": "Data Protection",
                "remediation": "Develop processes and technical controls to classify and protect data",
            },
            "secure_configuration": {
                "id": "CIS-4",
                "title": "Secure Configuration of Assets and Software",
                "remediation": "Establish and maintain secure configuration standards",
            },
            "account_management": {
                "id": "CIS-5",
                "title": "Account Management",
                "remediation": "Manage credentials and access for user and admin accounts",
            },
            "vulnerability_management": {
                "id": "CIS-7",
                "title": "Continuous Vulnerability Management",
                "remediation": "Continuously acquire, assess, and remediate vulnerabilities",
            },
        },
    }

    # Vulnerability name keywords → compliance category mapping
    VULN_CATEGORY_MAP: dict[str, list[str]] = {
        "sql_injection": ["sql", "injection", "sqli"],
        "xss": ["xss", "cross-site", "script"],
        "weak_crypto": ["ssl", "tls", "crypto", "cipher", "certificate", "https"],
        "default_credentials": ["default", "credential", "password", "admin"],
        "outdated_software": ["outdated", "version", "upgrade", "eol", "deprecated"],
        "access_control": ["access", "auth", "privilege", "permission", "rbac"],
        "encryption": ["encrypt", "decrypt", "plaintext", "cleartext"],
        "logging": ["log", "audit", "monitor", "trace"],
        "network_segmentation": ["segment", "firewall", "network", "port"],
        "configuration_management": ["config", "misconfigur", "hardening"],
        "vulnerability_management": ["vuln", "patch", "update"],
        "integrity": ["integrity", "tamper", "modify"],
        "transmission_security": ["transit", "transport", "wire"],
        "inventory": ["inventory", "asset", "discovery"],
        "data_protection": ["data", "leak", "exfil", "sensitive"],
    }

    def __init__(self, neo4j_client: Neo4jClient) -> None:
        self._client = neo4j_client

    async def generate(
        self,
        project_id: str,
        frameworks: list[str] | None = None,
    ) -> ComplianceReport:
        """Generate compliance report for specified frameworks."""
        frameworks = frameworks or list(self.FRAMEWORK_CONTROLS.keys())
        logger.info("Generating compliance report", project_id=project_id, frameworks=frameworks)

        vulns = await self._get_vulnerabilities(project_id)

        # Categorise vulnerabilities
        categorised = self._categorise_vulns(vulns)

        # Build mappings for each framework
        all_mappings: list[ComplianceMapping] = []
        framework_summaries: list[FrameworkSummary] = []

        for fw in frameworks:
            if fw not in self.FRAMEWORK_CONTROLS:
                continue
            mappings, summary = self._assess_framework(fw, categorised, vulns)
            all_mappings.extend(mappings)
            framework_summaries.append(summary)

        # Overall compliance
        total_controls = sum(s.total_controls for s in framework_summaries)
        total_compliant = sum(s.compliant for s in framework_summaries)
        overall = round((total_compliant / max(total_controls, 1)) * 100.0, 1)

        recommendations = self._generate_recommendations(framework_summaries, all_mappings)

        report = ComplianceReport(
            title=f"Compliance Gap Analysis — Project {project_id}",
            project_id=project_id,
            generated_at=datetime.now(timezone.utc).isoformat(),
            frameworks_assessed=frameworks,
            framework_summaries=framework_summaries,
            mappings=all_mappings,
            overall_compliance=overall,
            recommendations=recommendations,
        )

        logger.info(
            "Compliance report generated",
            project_id=project_id,
            overall_compliance=overall,
            frameworks=len(framework_summaries),
        )
        return report

    # ---- data fetchers -------------------------------------------------------
    async def _get_vulnerabilities(self, project_id: str) -> list[dict[str, Any]]:
        result = await self._client.execute_read(
            """
            MATCH (v:Vulnerability {project_id: $pid})
            OPTIONAL MATCH (v)-[:ASSOCIATED_CVE]->(c:CVE)
            RETURN v.vulnerability_id AS id, v.name AS name,
                   v.severity AS severity, v.template_id AS template_id,
                   v.description AS description,
                   c.cve_id AS cve_id
            ORDER BY CASE v.severity
                WHEN 'critical' THEN 0 WHEN 'high' THEN 1
                WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4
            END
            """,
            {"pid": project_id},
        )
        return [dict(r) for r in result]

    # ---- classification & assessment -----------------------------------------
    def _categorise_vulns(
        self,
        vulns: list[dict[str, Any]],
    ) -> dict[str, list[dict[str, Any]]]:
        """Map each vulnerability to compliance categories."""
        categorised: dict[str, list[dict[str, Any]]] = {}

        for vuln in vulns:
            name_lower = (
                (vuln.get("name", "") + " " + vuln.get("template_id", "") +
                 " " + vuln.get("description", ""))
            ).lower()

            matched = False
            for category, keywords in self.VULN_CATEGORY_MAP.items():
                if any(kw in name_lower for kw in keywords):
                    categorised.setdefault(category, []).append(vuln)
                    matched = True

            if not matched:
                categorised.setdefault("vulnerability_management", []).append(vuln)

        return categorised

    def _assess_framework(
        self,
        framework: str,
        categorised: dict[str, list[dict[str, Any]]],
        all_vulns: list[dict[str, Any]],
    ) -> tuple[list[ComplianceMapping], FrameworkSummary]:
        """Assess compliance for a single framework."""
        controls = self.FRAMEWORK_CONTROLS[framework]
        mappings: list[ComplianceMapping] = []
        compliant = 0
        non_compliant = 0
        partial = 0
        not_tested = 0
        critical_gaps: list[str] = []

        for category, control in controls.items():
            related_vulns = categorised.get(category, [])
            finding_ids = [v.get("id", "") for v in related_vulns]

            if not related_vulns:
                status = "not_tested"
                not_tested += 1
            elif any(v.get("severity") in ("critical", "high") for v in related_vulns):
                status = "non_compliant"
                non_compliant += 1
                critical_gaps.append(f"{control['id']}: {control['title']}")
            elif related_vulns:
                status = "partial"
                partial += 1
            else:
                status = "compliant"
                compliant += 1

            mappings.append(ComplianceMapping(
                framework=framework,
                control_id=control["id"],
                control_title=control["title"],
                finding_ids=finding_ids,
                status=status,
                remediation=control.get("remediation", ""),
            ))

        total = len(controls)
        pct = round((compliant / max(total, 1)) * 100.0, 1)

        summary = FrameworkSummary(
            framework=framework,
            total_controls=total,
            compliant=compliant,
            non_compliant=non_compliant,
            partial=partial,
            not_tested=not_tested,
            compliance_percentage=pct,
            critical_gaps=critical_gaps,
        )

        return mappings, summary

    @staticmethod
    def _generate_recommendations(
        summaries: list[FrameworkSummary],
        mappings: list[ComplianceMapping],
    ) -> list[str]:
        recs: list[str] = []

        # Framework-level recommendations
        for s in summaries:
            if s.non_compliant > 0:
                recs.append(
                    f"{s.framework}: {s.non_compliant} non-compliant controls require "
                    f"immediate attention ({s.compliance_percentage}% compliant)"
                )
            if s.critical_gaps:
                recs.append(
                    f"{s.framework} critical gaps: {', '.join(s.critical_gaps[:3])}"
                )

        # General recommendations
        non_compliant_mappings = [m for m in mappings if m.status == "non_compliant"]
        if non_compliant_mappings:
            recs.append(
                f"Total of {len(non_compliant_mappings)} non-compliant controls across "
                f"all frameworks — develop a remediation roadmap."
            )

        recs.append("Schedule re-assessment after remediation to verify compliance improvement.")
        return recs
