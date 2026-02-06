"""
Report Builder

Orchestrates report generation by collecting data from Neo4j,
running EPSS scoring, mapping to MITRE ATT&CK, and generating
multiple report formats.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from core.logging import get_logger
from graph.client import Neo4jClient
from intelligence.mitre.attack_mapper import MITREAttackMapper
from intelligence.scoring.epss_client import EPSSScorer

logger = get_logger(__name__)


@dataclass
class ReportData:
    """Collected data for report generation."""
    project_id: str
    project_name: str
    target: str
    scan_ids: list[str]
    generated_at: str

    # Summary stats
    total_hosts: int = 0
    total_subdomains: int = 0
    total_ports: int = 0
    total_urls: int = 0
    total_vulns: int = 0
    total_critical: int = 0
    total_high: int = 0
    total_medium: int = 0
    total_low: int = 0

    # Detailed findings
    vulnerabilities: list[dict[str, Any]] = field(default_factory=list)
    hosts: list[dict[str, Any]] = field(default_factory=list)
    technologies: list[dict[str, Any]] = field(default_factory=list)

    # MITRE ATT&CK
    attack_narrative: dict[str, Any] | None = None
    techniques_used: list[dict[str, Any]] = field(default_factory=list)

    # Risk scoring
    risk_score: float = 0.0
    epss_scores: dict[str, Any] = field(default_factory=dict)

    # Remediation
    remediation_plan: list[dict[str, Any]] = field(default_factory=list)


class ReportBuilder:
    """
    Orchestrates report generation from Neo4j data.
    """

    def __init__(self, neo4j_client: Neo4jClient) -> None:
        self._client = neo4j_client
        self._mitre = MITREAttackMapper(neo4j_client)
        self._epss = EPSSScorer()

    async def build(self, project_id: str, scan_ids: list[str] | None = None) -> ReportData:
        """Build report data by collecting all relevant information."""
        logger.info("Building report", project_id=project_id)

        # Get project info
        project = await self._get_project(project_id)

        # Get scan info
        if not scan_ids:
            scan_ids = await self._get_scan_ids(project_id)

        # Collect data in parallel
        vulns = await self._get_vulnerabilities(project_id)
        hosts = await self._get_hosts(project_id)
        techs = await self._get_technologies(project_id)
        stats = await self._get_stats(project_id)

        # EPSS scoring for CVEs
        cve_ids = [v.get("cve_id") for v in vulns if v.get("cve_id")]
        epss_scores = await self._epss.fetch_scores(cve_ids) if cve_ids else {}

        # Prioritize vulnerabilities
        if vulns and epss_scores:
            prioritized = self._epss.prioritize(vulns, epss_scores)
            vulns = [p.vulnerability for p in prioritized]

        # MITRE ATT&CK narrative
        execution_trace = await self._get_execution_trace(project_id)
        narrative = self._mitre.generate_narrative(execution_trace) if execution_trace else None

        # Build remediation plan
        remediation = self._build_remediation(vulns)

        # Calculate overall risk
        risk = self._calculate_risk(vulns, stats)

        report = ReportData(
            project_id=project_id,
            project_name=project.get("name", "Unknown"),
            target=project.get("target", ""),
            scan_ids=scan_ids,
            generated_at=datetime.now(timezone.utc).isoformat(),
            total_hosts=stats.get("hosts", 0),
            total_subdomains=stats.get("subdomains", 0),
            total_ports=stats.get("ports", 0),
            total_urls=stats.get("urls", 0),
            total_vulns=len(vulns),
            total_critical=sum(1 for v in vulns if v.get("severity") == "critical"),
            total_high=sum(1 for v in vulns if v.get("severity") == "high"),
            total_medium=sum(1 for v in vulns if v.get("severity") == "medium"),
            total_low=sum(1 for v in vulns if v.get("severity") == "low"),
            vulnerabilities=vulns,
            hosts=hosts,
            technologies=techs,
            attack_narrative=narrative.__dict__ if narrative else None,
            risk_score=risk,
            epss_scores={k: v.__dict__ for k, v in epss_scores.items()},
            remediation_plan=remediation,
        )

        logger.info(
            "Report built",
            project_id=project_id,
            vulns=report.total_vulns,
            risk=report.risk_score,
        )
        return report

    async def _get_project(self, project_id: str) -> dict[str, Any]:
        result = await self._client.execute_read(
            "MATCH (p:Project {project_id: $pid}) RETURN p",
            {"pid": project_id},
        )
        return dict(result[0]["p"]) if result else {"name": "Unknown", "target": ""}

    async def _get_scan_ids(self, project_id: str) -> list[str]:
        result = await self._client.execute_read(
            "MATCH (s:Scan {project_id: $pid}) RETURN s.scan_id AS id ORDER BY s.started_at DESC",
            {"pid": project_id},
        )
        return [r["id"] for r in result]

    async def _get_vulnerabilities(self, project_id: str) -> list[dict[str, Any]]:
        result = await self._client.execute_read(
            """
            MATCH (v:Vulnerability {project_id: $pid})
            OPTIONAL MATCH (v)-[:ASSOCIATED_CVE]->(c:CVE)
            RETURN v.vulnerability_id AS id,
                   v.name AS name,
                   v.severity AS severity,
                   v.template_id AS template_id,
                   v.matched_at AS matched_at,
                   v.description AS description,
                   c.cve_id AS cve_id,
                   c.cvss_score AS cvss_score
            ORDER BY CASE v.severity
                WHEN 'critical' THEN 0
                WHEN 'high' THEN 1
                WHEN 'medium' THEN 2
                WHEN 'low' THEN 3
                ELSE 4
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
            RETURN s.name AS subdomain,
                   collect(DISTINCT i.address) AS ips,
                   collect(DISTINCT p.number) AS ports
            LIMIT 500
            """,
            {"pid": project_id},
        )
        return [dict(r) for r in result]

    async def _get_technologies(self, project_id: str) -> list[dict[str, Any]]:
        result = await self._client.execute_read(
            """
            MATCH (t:Technology {project_id: $pid})
            OPTIONAL MATCH (u:URL)-[:USES_TECHNOLOGY]->(t)
            RETURN t.name AS name,
                   t.version AS version,
                   collect(DISTINCT u.url) AS urls
            LIMIT 200
            """,
            {"pid": project_id},
        )
        return [dict(r) for r in result]

    async def _get_stats(self, project_id: str) -> dict[str, int]:
        result = await self._client.execute_read(
            """
            MATCH (n {project_id: $pid})
            WITH labels(n)[0] AS label
            WHERE label IN ['Subdomain','IP','Port','URL','Vulnerability']
            RETURN label, count(*) AS cnt
            """,
            {"pid": project_id},
        )
        label_map = {"Subdomain": "subdomains", "IP": "hosts", "Port": "ports",
                      "URL": "urls", "Vulnerability": "vulns"}
        return {label_map.get(r["label"], r["label"]): r["cnt"] for r in result}

    async def _get_execution_trace(self, project_id: str) -> list[dict[str, Any]]:
        result = await self._client.execute_read(
            """
            MATCH (e:ExecutionStep {project_id: $pid})
            RETURN e.tool_name AS tool_name,
                   e.success AS success,
                   e.executed_at AS executed_at
            ORDER BY e.executed_at ASC
            """,
            {"pid": project_id},
        )
        return [dict(r) for r in result]

    @staticmethod
    def _build_remediation(vulns: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Generate remediation recommendations from vulnerabilities."""
        remediation: list[dict[str, Any]] = []
        seen_templates: set[str] = set()

        for vuln in vulns:
            template = vuln.get("template_id", "")
            if template in seen_templates:
                continue
            seen_templates.add(template)

            severity = vuln.get("severity", "info")
            priority_map = {"critical": "P1", "high": "P2", "medium": "P3", "low": "P4"}

            remediation.append({
                "vulnerability": vuln.get("name", template),
                "severity": severity,
                "priority": priority_map.get(severity, "P5"),
                "affected": vuln.get("matched_at", ""),
                "recommendation": f"Remediate {vuln.get('name', template)} - {severity} severity",
                "cve": vuln.get("cve_id"),
            })

        return remediation

    @staticmethod
    def _calculate_risk(vulns: list[dict[str, Any]], stats: dict[str, int]) -> float:
        """Calculate composite risk score 0-100."""
        if not vulns:
            return 0.0

        severity_weights = {"critical": 10, "high": 7, "medium": 4, "low": 1}
        vuln_score = sum(severity_weights.get(v.get("severity", "info"), 0) for v in vulns)

        # Normalize: max reasonable score
        max_score = len(vulns) * 10
        normalized = min((vuln_score / max(max_score, 1)) * 100, 100)

        return round(normalized, 1)
