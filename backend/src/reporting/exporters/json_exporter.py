"""
JSON Exporter

Exports the full penetration test report as structured JSON
for API consumption and integration with other tools.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from core.logging import get_logger
from graph.client import Neo4jClient
from reporting.generators.executive_summary import ExecutiveSummaryGenerator

logger = get_logger(__name__)


class JSONExporter:
    """Exports full report as structured JSON."""

    def __init__(self, neo4j_client: Neo4jClient) -> None:
        self._client = neo4j_client

    async def export(self, project_id: str, target: str = "") -> dict[str, Any]:
        """Generate full JSON report."""
        summary_gen = ExecutiveSummaryGenerator(self._client)
        summary = await summary_gen.generate(project_id, target=target)

        # Fetch detailed data
        vulns = await self._fetch_vulns(project_id)
        hosts = await self._fetch_hosts(project_id)
        scan_history = await self._fetch_scans(project_id)

        report = {
            "meta": {
                "tool": "Arc",
                "version": "0.1.0",
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "project_id": project_id,
                "target": target,
            },
            "executive_summary": {
                "risk_rating": summary.risk_rating,
                "risk_score": summary.risk_score,
                "total_findings": summary.total_findings,
                "severity_breakdown": {
                    "critical": summary.critical_findings,
                    "high": summary.high_findings,
                    "medium": summary.medium_findings,
                    "low": summary.low_findings,
                },
                "attack_surface": summary.attack_surface,
                "narrative": summary.executive_narrative,
                "recommendations": summary.recommendations,
            },
            "vulnerabilities": vulns,
            "hosts": hosts,
            "scan_history": scan_history,
        }

        logger.info("JSON export complete", project_id=project_id)
        return report

    async def export_json(self, project_id: str, target: str = "") -> str:
        """Export as pretty-printed JSON string."""
        return json.dumps(await self.export(project_id, target), indent=2, default=str)

    async def _fetch_vulns(self, project_id: str) -> list[dict[str, Any]]:
        result = await self._client.execute_read(
            """
            MATCH (v:Vulnerability {project_id: $pid})
            RETURN v.vulnerability_id AS id, v.name AS name,
                   v.severity AS severity, v.template_id AS template,
                   v.matched_at AS target, v.description AS description,
                   v.evidence AS evidence, v.cve_id AS cve
            ORDER BY CASE v.severity
                WHEN 'critical' THEN 0 WHEN 'high' THEN 1
                WHEN 'medium' THEN 2 ELSE 3 END
            """,
            {"pid": project_id},
        )
        return [dict(r) for r in result]

    async def _fetch_hosts(self, project_id: str) -> list[dict[str, Any]]:
        result = await self._client.execute_read(
            """
            MATCH (s:Subdomain {project_id: $pid})
            OPTIONAL MATCH (s)-[:RESOLVES_TO]->(i:IP)
            OPTIONAL MATCH (i)-[:HAS_PORT]->(p:Port)
            RETURN s.name AS subdomain,
                   collect(DISTINCT i.address) AS ips,
                   collect(DISTINCT p.number) AS ports
            LIMIT 200
            """,
            {"pid": project_id},
        )
        return [dict(r) for r in result]

    async def _fetch_scans(self, project_id: str) -> list[dict[str, Any]]:
        result = await self._client.execute_read(
            """
            MATCH (s:Scan {project_id: $pid})
            RETURN s.scan_id AS id, s.status AS status,
                   s.scan_type AS type, s.target AS target,
                   s.started_at AS started, s.completed_at AS completed,
                   s.findings_count AS findings
            ORDER BY s.started_at DESC
            LIMIT 50
            """,
            {"pid": project_id},
        )
        return [dict(r) for r in result]
