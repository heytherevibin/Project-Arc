"""
Executive Summary Generator

Generates a high-level executive summary of the penetration test
including risk overview, critical findings, and business impact.
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
class ExecutiveSummary:
    """Executive summary report data."""
    title: str
    project_name: str
    target: str
    assessment_date: str
    risk_rating: str  # "Critical" | "High" | "Medium" | "Low"
    risk_score: float  # 0-10

    total_findings: int
    critical_findings: int
    high_findings: int
    medium_findings: int
    low_findings: int

    attack_surface: dict[str, int]  # hosts, ports, urls, services
    top_vulnerabilities: list[dict[str, Any]]
    mitre_coverage: dict[str, Any]
    recommendations: list[str]
    executive_narrative: str


class ExecutiveSummaryGenerator:
    """Generates executive summary from Neo4j data."""

    def __init__(self, neo4j_client: Neo4jClient) -> None:
        self._client = neo4j_client

    async def generate(
        self,
        project_id: str,
        project_name: str = "",
        target: str = "",
    ) -> ExecutiveSummary:
        """Generate executive summary for a project."""
        # Fetch vulnerability counts by severity
        severity_counts = await self._get_severity_counts(project_id)
        total = sum(severity_counts.values())
        critical = severity_counts.get("critical", 0)
        high = severity_counts.get("high", 0)
        medium = severity_counts.get("medium", 0)
        low = severity_counts.get("low", 0)

        # Fetch attack surface stats
        attack_surface = await self._get_attack_surface(project_id)

        # Top vulnerabilities
        top_vulns = await self._get_top_vulns(project_id)

        # Calculate risk rating
        risk_score, risk_rating = self._calculate_risk(critical, high, medium, low, attack_surface)

        # Generate recommendations
        recommendations = self._generate_recommendations(
            critical, high, medium, top_vulns, attack_surface
        )

        # Generate narrative
        narrative = self._generate_narrative(
            target, risk_rating, total, critical, high, attack_surface
        )

        return ExecutiveSummary(
            title=f"Penetration Test Report - {project_name or target}",
            project_name=project_name or target,
            target=target,
            assessment_date=datetime.now(timezone.utc).strftime("%Y-%m-%d"),
            risk_rating=risk_rating,
            risk_score=risk_score,
            total_findings=total,
            critical_findings=critical,
            high_findings=high,
            medium_findings=medium,
            low_findings=low,
            attack_surface=attack_surface,
            top_vulnerabilities=top_vulns,
            mitre_coverage={},
            recommendations=recommendations,
            executive_narrative=narrative,
        )

    async def _get_severity_counts(self, project_id: str) -> dict[str, int]:
        result = await self._client.execute_read(
            """
            MATCH (v:Vulnerability {project_id: $pid})
            RETURN v.severity AS severity, count(v) AS cnt
            """,
            {"pid": project_id},
        )
        return {r["severity"]: r["cnt"] for r in result if r["severity"]}

    async def _get_attack_surface(self, project_id: str) -> dict[str, int]:
        result = await self._client.execute_read(
            """
            MATCH (n {project_id: $pid})
            WITH labels(n)[0] AS label, count(n) AS cnt
            WHERE label IN ['Subdomain','IP','Port','URL','Service','Technology','Endpoint']
            RETURN label, cnt
            """,
            {"pid": project_id},
        )
        return {r["label"]: r["cnt"] for r in result}

    async def _get_top_vulns(self, project_id: str, limit: int = 10) -> list[dict[str, Any]]:
        result = await self._client.execute_read(
            """
            MATCH (v:Vulnerability {project_id: $pid})
            RETURN v.name AS name, v.severity AS severity,
                   v.template_id AS template_id, v.matched_at AS target,
                   v.description AS description
            ORDER BY CASE v.severity
                WHEN 'critical' THEN 0
                WHEN 'high' THEN 1
                WHEN 'medium' THEN 2
                WHEN 'low' THEN 3
                ELSE 4
            END
            LIMIT $limit
            """,
            {"pid": project_id, "limit": limit},
        )
        return [dict(r) for r in result]

    @staticmethod
    def _calculate_risk(
        critical: int, high: int, medium: int, low: int,
        attack_surface: dict[str, int],
    ) -> tuple[float, str]:
        # Weighted score
        score = min(10.0, (critical * 3.0 + high * 1.5 + medium * 0.5 + low * 0.1))
        # Boost by attack surface size
        hosts = attack_surface.get("Subdomain", 0) + attack_surface.get("IP", 0)
        if hosts > 100:
            score = min(10.0, score + 1.0)

        if score >= 8.0 or critical > 0:
            return round(score, 1), "Critical"
        if score >= 6.0 or high > 2:
            return round(score, 1), "High"
        if score >= 3.0 or medium > 5:
            return round(score, 1), "Medium"
        return round(score, 1), "Low"

    @staticmethod
    def _generate_recommendations(
        critical: int, high: int, medium: int,
        top_vulns: list[dict], attack_surface: dict,
    ) -> list[str]:
        recs: list[str] = []
        if critical > 0:
            recs.append(f"URGENT: Remediate {critical} critical vulnerability(ies) immediately.")
        if high > 0:
            recs.append(f"Address {high} high-severity finding(s) within 7 days.")
        if medium > 0:
            recs.append(f"Plan remediation for {medium} medium-severity finding(s) within 30 days.")
        if attack_surface.get("Port", 0) > 50:
            recs.append("Reduce attack surface: review and close unnecessary open ports.")
        recs.append("Implement continuous vulnerability scanning.")
        recs.append("Conduct follow-up assessment after remediation.")
        return recs

    @staticmethod
    def _generate_narrative(
        target: str, risk_rating: str, total: int,
        critical: int, high: int, attack_surface: dict,
    ) -> str:
        hosts = attack_surface.get("Subdomain", 0) + attack_surface.get("IP", 0)
        return (
            f"The penetration test of {target} identified {total} total findings "
            f"across {hosts} discovered hosts. The overall risk rating is {risk_rating}. "
            f"{critical} critical and {high} high severity vulnerabilities require "
            f"immediate attention. A comprehensive remediation plan should be developed "
            f"and implemented within the next 30 days."
        )
