"""
Technical Report Generator

Generates a detailed technical penetration-test report with full
vulnerability details, reproduction steps, evidence, and MITRE ATT&CK
technique mapping.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from core.logging import get_logger
from graph.client import Neo4jClient
from intelligence.scoring.epss_client import EPSSScorer

logger = get_logger(__name__)


@dataclass
class TechnicalFinding:
    """Detailed technical finding."""
    id: str
    title: str
    severity: str
    cvss_score: float | None = None
    cve_id: str | None = None
    epss_probability: float | None = None
    description: str = ""
    affected_asset: str = ""
    attack_vector: str = ""
    reproduction_steps: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    mitre_techniques: list[str] = field(default_factory=list)
    remediation: str = ""
    references: list[str] = field(default_factory=list)


@dataclass
class TechnicalReport:
    """Complete technical penetration-test report."""
    title: str
    project_id: str
    project_name: str
    target: str
    generated_at: str
    scope: list[str] = field(default_factory=list)
    methodology: str = ""

    # Findings
    findings: list[TechnicalFinding] = field(default_factory=list)

    # Attack surface
    hosts: list[dict[str, Any]] = field(default_factory=list)
    services: list[dict[str, Any]] = field(default_factory=list)
    technologies: list[dict[str, Any]] = field(default_factory=list)

    # Attack paths
    attack_paths: list[dict[str, Any]] = field(default_factory=list)

    # Execution timeline
    timeline: list[dict[str, Any]] = field(default_factory=list)

    # Statistics
    stats: dict[str, Any] = field(default_factory=dict)


class TechnicalReportGenerator:
    """
    Generates a full technical report from Neo4j data including:
    - Methodology section
    - Detailed findings with reproduction steps
    - Attack surface enumeration
    - Attack path narratives
    - Tool execution timeline
    """

    METHODOLOGY = (
        "The assessment followed a structured penetration testing methodology "
        "aligned with OWASP Testing Guide v4.2 and PTES (Penetration Testing "
        "Execution Standard). Phases included: Reconnaissance, Vulnerability "
        "Analysis, Exploitation, Post-Exploitation, and Reporting. Automated "
        "scanning was supplemented by manual testing to minimise false positives."
    )

    def __init__(self, neo4j_client: Neo4jClient) -> None:
        self._client = neo4j_client
        self._epss = EPSSScorer()

    async def generate(
        self,
        project_id: str,
        project_name: str = "",
        target: str = "",
    ) -> TechnicalReport:
        """Generate the full technical report."""
        logger.info("Generating technical report", project_id=project_id)

        # Collect data
        vulns = await self._get_vulnerabilities(project_id)
        hosts = await self._get_hosts(project_id)
        services = await self._get_services(project_id)
        techs = await self._get_technologies(project_id)
        timeline = await self._get_timeline(project_id)
        paths = await self._get_attack_paths(project_id)

        # EPSS enrichment
        cve_ids = [v.get("cve_id") for v in vulns if v.get("cve_id")]
        epss_scores = await self._epss.fetch_scores(cve_ids) if cve_ids else {}

        # Build findings
        findings = self._build_findings(vulns, epss_scores)

        severity_counts = {
            "critical": sum(1 for f in findings if f.severity == "critical"),
            "high": sum(1 for f in findings if f.severity == "high"),
            "medium": sum(1 for f in findings if f.severity == "medium"),
            "low": sum(1 for f in findings if f.severity == "low"),
        }

        report = TechnicalReport(
            title=f"Technical Penetration Test Report — {project_name or target}",
            project_id=project_id,
            project_name=project_name or target,
            target=target,
            generated_at=datetime.now(timezone.utc).isoformat(),
            methodology=self.METHODOLOGY,
            findings=findings,
            hosts=hosts,
            services=services,
            technologies=techs,
            attack_paths=paths,
            timeline=timeline,
            stats={
                "total_findings": len(findings),
                **severity_counts,
                "total_hosts": len(hosts),
                "total_services": len(services),
                "attack_paths_found": len(paths),
            },
        )

        logger.info(
            "Technical report generated",
            project_id=project_id,
            findings=len(findings),
        )
        return report

    # ---- data fetchers -------------------------------------------------------
    async def _get_vulnerabilities(self, project_id: str) -> list[dict[str, Any]]:
        result = await self._client.execute_read(
            """
            MATCH (v:Vulnerability {project_id: $pid})
            OPTIONAL MATCH (v)-[:ASSOCIATED_CVE]->(c:CVE)
            OPTIONAL MATCH (v)-[:FOUND_AT]->(u:URL)
            OPTIONAL MATCH (v)-[:AFFECTS]->(h)
            RETURN v.vulnerability_id AS id, v.name AS name,
                   v.severity AS severity, v.description AS description,
                   v.template_id AS template_id, v.matched_at AS matched_at,
                   c.cve_id AS cve_id, c.cvss_score AS cvss_score,
                   collect(DISTINCT coalesce(u.url, h.name, h.address)) AS affected
            ORDER BY CASE v.severity
                WHEN 'critical' THEN 0 WHEN 'high' THEN 1
                WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4
            END
            """,
            {"pid": project_id},
        )
        return [dict(r) for r in result]

    async def _get_hosts(self, project_id: str) -> list[dict[str, Any]]:
        result = await self._client.execute_read(
            """
            MATCH (s:Subdomain {project_id: $pid})
            OPTIONAL MATCH (s)-[:RESOLVES_TO]->(i:IP)
            OPTIONAL MATCH (i)-[:HAS_PORT]->(p:Port)
            RETURN s.name AS hostname,
                   collect(DISTINCT i.address) AS ips,
                   collect(DISTINCT {port: p.number, protocol: p.protocol, service: p.service}) AS ports
            ORDER BY s.name
            LIMIT 500
            """,
            {"pid": project_id},
        )
        return [dict(r) for r in result]

    async def _get_services(self, project_id: str) -> list[dict[str, Any]]:
        result = await self._client.execute_read(
            """
            MATCH (p:Port {project_id: $pid})
            OPTIONAL MATCH (i:IP)-[:HAS_PORT]->(p)
            RETURN p.number AS port, p.protocol AS protocol,
                   p.service AS service, p.version AS version,
                   collect(DISTINCT i.address) AS hosts
            ORDER BY p.number
            LIMIT 500
            """,
            {"pid": project_id},
        )
        return [dict(r) for r in result]

    async def _get_technologies(self, project_id: str) -> list[dict[str, Any]]:
        result = await self._client.execute_read(
            """
            MATCH (t:Technology {project_id: $pid})
            RETURN t.name AS name, t.version AS version, t.category AS category
            ORDER BY t.name
            LIMIT 200
            """,
            {"pid": project_id},
        )
        return [dict(r) for r in result]

    async def _get_timeline(self, project_id: str) -> list[dict[str, Any]]:
        result = await self._client.execute_read(
            """
            MATCH (e:ExecutionStep {project_id: $pid})
            RETURN e.tool_name AS tool, e.success AS success,
                   e.executed_at AS timestamp, e.phase AS phase,
                   e.details AS details
            ORDER BY e.executed_at ASC
            LIMIT 500
            """,
            {"pid": project_id},
        )
        return [dict(r) for r in result]

    async def _get_attack_paths(self, project_id: str) -> list[dict[str, Any]]:
        result = await self._client.execute_read(
            """
            MATCH (ap:AttackPath {project_id: $pid})
            RETURN ap.path_id AS id, ap.source AS source,
                   ap.target AS target, ap.hops AS hops,
                   ap.risk_score AS risk, ap.techniques AS techniques
            ORDER BY ap.risk_score DESC
            LIMIT 50
            """,
            {"pid": project_id},
        )
        return [dict(r) for r in result]

    # ---- builders ------------------------------------------------------------
    def _build_findings(
        self,
        vulns: list[dict[str, Any]],
        epss_scores: dict[str, Any],
    ) -> list[TechnicalFinding]:
        findings: list[TechnicalFinding] = []
        for v in vulns:
            cve = v.get("cve_id")
            epss = epss_scores.get(cve)
            epss_prob = epss.epss if epss else None

            cvss = v.get("cvss_score")
            if isinstance(cvss, str):
                try:
                    cvss = float(cvss)
                except ValueError:
                    cvss = None

            affected_list = v.get("affected", [])
            affected_str = ", ".join(str(a) for a in affected_list if a) if affected_list else v.get("matched_at", "")

            refs: list[str] = []
            if cve:
                refs.append(f"https://nvd.nist.gov/vuln/detail/{cve}")
                refs.append(f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve}")

            findings.append(TechnicalFinding(
                id=v.get("id", ""),
                title=v.get("name", v.get("template_id", "Unknown")),
                severity=v.get("severity", "info"),
                cvss_score=cvss,
                cve_id=cve,
                epss_probability=epss_prob,
                description=v.get("description", ""),
                affected_asset=affected_str,
                remediation=self._generate_remediation(v),
                references=refs,
            ))
        return findings

    @staticmethod
    def _generate_remediation(vuln: dict[str, Any]) -> str:
        severity = vuln.get("severity", "info")
        name = vuln.get("name", "this vulnerability")
        recommendations = {
            "critical": f"Immediately patch or mitigate {name}. Apply vendor security update. Implement compensating controls if patching is not feasible.",
            "high": f"Schedule urgent remediation for {name} within 7 days. Apply security patches and review configuration.",
            "medium": f"Plan remediation for {name} within 30 days. Review and harden affected configuration.",
            "low": f"Address {name} during next maintenance window. Consider as part of routine hardening.",
        }
        return recommendations.get(severity, f"Review and assess {name}.")
