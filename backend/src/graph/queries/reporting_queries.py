"""
Reporting Queries

Predefined Cypher queries for report generation: findings summaries,
host inventory, remediation items, timeline events, and MITRE coverage.
"""

from __future__ import annotations

from typing import Any

from core.logging import get_logger
from graph.client import Neo4jClient

logger = get_logger(__name__)


class ReportingQueries:
    """
    Pre-built Cypher queries for generating Arc penetration test reports.
    """

    def __init__(self, client: Neo4jClient) -> None:
        self._client = client

    # ------------------------------------------------------------------
    # Findings Summary
    # ------------------------------------------------------------------

    async def get_findings_summary(
        self,
        project_id: str,
    ) -> dict[str, Any]:
        """
        Get a summary of all findings: total vulnerabilities by severity,
        total hosts, credentials found, etc.
        """
        query = """
        MATCH (v:Vulnerability {project_id: $project_id})
        WITH
            count(v) AS total_vulns,
            sum(CASE WHEN v.severity = 'critical' THEN 1 ELSE 0 END) AS critical,
            sum(CASE WHEN v.severity = 'high' THEN 1 ELSE 0 END) AS high,
            sum(CASE WHEN v.severity = 'medium' THEN 1 ELSE 0 END) AS medium,
            sum(CASE WHEN v.severity = 'low' THEN 1 ELSE 0 END) AS low,
            sum(CASE WHEN v.severity = 'info' THEN 1 ELSE 0 END) AS info
        OPTIONAL MATCH (h:Host {project_id: $project_id})
        WITH total_vulns, critical, high, medium, low, info,
             count(DISTINCT h) AS total_hosts
        OPTIONAL MATCH (c:Credential {project_id: $project_id})
        RETURN total_vulns, critical, high, medium, low, info,
               total_hosts,
               count(DISTINCT c) AS total_credentials
        """
        records = await self._client.execute_read(query, {"project_id": project_id})
        if records:
            return dict(records[0])
        return {
            "total_vulns": 0, "critical": 0, "high": 0,
            "medium": 0, "low": 0, "info": 0,
            "total_hosts": 0, "total_credentials": 0,
        }

    # ------------------------------------------------------------------
    # Host Inventory
    # ------------------------------------------------------------------

    async def get_host_inventory(
        self,
        project_id: str,
        limit: int = 200,
    ) -> list[dict[str, Any]]:
        """Get complete host inventory with service and vuln counts."""
        query = """
        MATCH (h:Host {project_id: $project_id})
        OPTIONAL MATCH (h)-[:HAS_VULN]->(v:Vulnerability)
        OPTIONAL MATCH (h)-[:RUNS_SERVICE]->(s:Service)
        OPTIONAL MATCH (h)-[:HAS_PORT]->(p:Port)
        RETURN h.hostname AS hostname,
               h.ip AS ip,
               h.os AS os,
               count(DISTINCT v) AS vuln_count,
               count(DISTINCT s) AS service_count,
               count(DISTINCT p) AS port_count,
               collect(DISTINCT v.severity) AS vuln_severities
        ORDER BY vuln_count DESC
        LIMIT $limit
        """
        records = await self._client.execute_read(
            query, {"project_id": project_id, "limit": limit},
        )
        return [dict(r) for r in records]

    # ------------------------------------------------------------------
    # Remediation Items
    # ------------------------------------------------------------------

    async def get_remediation_items(
        self,
        project_id: str,
        min_severity: str = "medium",
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """
        Get remediation items: vulnerabilities with affected hosts,
        sorted by severity and CVSS.
        """
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        threshold = severity_order.get(min_severity.lower(), 2)
        allowed = [s for s, v in severity_order.items() if v <= threshold]

        query = """
        MATCH (v:Vulnerability {project_id: $project_id})
        WHERE v.severity IN $severities
        OPTIONAL MATCH (h:Host)-[:HAS_VULN]->(v)
        WITH v, collect(DISTINCT h.hostname) AS affected_hosts
        RETURN v.vuln_id AS vuln_id,
               v.name AS name,
               v.severity AS severity,
               v.cvss_score AS cvss_score,
               v.cve_id AS cve_id,
               v.description AS description,
               v.remediation AS remediation,
               affected_hosts,
               size(affected_hosts) AS affected_count
        ORDER BY v.cvss_score DESC
        LIMIT $limit
        """
        records = await self._client.execute_read(
            query,
            {"project_id": project_id, "severities": allowed, "limit": limit},
        )
        return [dict(r) for r in records]

    # ------------------------------------------------------------------
    # Timeline
    # ------------------------------------------------------------------

    async def get_timeline(
        self,
        project_id: str | None = None,
        session_id: str | None = None,
        limit: int = 200,
    ) -> list[dict[str, Any]]:
        """Get timeline of all agent events for the engagement."""
        filters: list[str] = []
        params: dict[str, Any] = {"limit": limit}

        if project_id:
            filters.append("e.project_id = $project_id")
            params["project_id"] = project_id
        if session_id:
            filters.append("e.session_id = $session_id")
            params["session_id"] = session_id

        where = " AND ".join(filters) if filters else "TRUE"

        query = f"""
        MATCH (e:EpisodicEvent)
        WHERE {where}
        RETURN e.event_id AS event_id,
               e.timestamp AS timestamp,
               e.agent_id AS agent_id,
               e.tool_name AS tool_name,
               e.success AS success,
               e.session_id AS session_id
        ORDER BY e.timestamp ASC
        LIMIT $limit
        """
        records = await self._client.execute_read(query, params)
        return [dict(r) for r in records]

    # ------------------------------------------------------------------
    # MITRE Coverage
    # ------------------------------------------------------------------

    async def get_mitre_coverage(
        self,
        project_id: str | None = None,
        session_id: str | None = None,
    ) -> list[dict[str, Any]]:
        """
        Get MITRE ATT&CK technique coverage from recorded events.
        Extracts technique_id from events that have one recorded.
        """
        filters: list[str] = ["e.technique_id IS NOT NULL"]
        params: dict[str, Any] = {}

        if project_id:
            filters.append("e.project_id = $project_id")
            params["project_id"] = project_id
        if session_id:
            filters.append("e.session_id = $session_id")
            params["session_id"] = session_id

        where = " AND ".join(filters)

        query = f"""
        MATCH (e:EpisodicEvent)
        WHERE {where}
        RETURN e.technique_id AS technique_id,
               e.technique_name AS technique_name,
               e.tactic AS tactic,
               count(e) AS usage_count,
               collect(DISTINCT e.tool_name) AS tools_used,
               any(ev IN collect(e) WHERE ev.success = true) AS any_success
        ORDER BY usage_count DESC
        """
        records = await self._client.execute_read(query, params)
        return [dict(r) for r in records]
