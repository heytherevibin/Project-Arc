"""
Attack Queries

Library of predefined Cypher queries for attack analysis.
Provides structured methods for querying the attack surface,
vulnerabilities, exploit chains, lateral movement, and credential reuse.
"""

from __future__ import annotations

from typing import Any

from core.logging import get_logger
from graph.client import Neo4jClient

logger = get_logger(__name__)


class AttackQueries:
    """
    Pre-built Cypher queries for attack analysis against the
    Arc Neo4j knowledge graph.
    """

    def __init__(self, client: Neo4jClient) -> None:
        self._client = client

    # ------------------------------------------------------------------
    # Attack Surface
    # ------------------------------------------------------------------

    async def get_attack_surface(
        self,
        project_id: str,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """Get the full attack surface: hosts, ports, services."""
        query = """
        MATCH (h:Host {project_id: $project_id})
        OPTIONAL MATCH (h)-[:RUNS_SERVICE]->(s:Service)
        OPTIONAL MATCH (h)-[:HAS_PORT]->(p:Port)
        RETURN h.hostname AS hostname,
               h.ip AS ip,
               h.os AS os,
               collect(DISTINCT {port: p.number, protocol: p.protocol}) AS ports,
               collect(DISTINCT {service: s.name, version: s.version}) AS services
        LIMIT $limit
        """
        records = await self._client.execute_read(
            query, {"project_id": project_id, "limit": limit},
        )
        return [dict(r) for r in records]

    # ------------------------------------------------------------------
    # Vulnerability queries
    # ------------------------------------------------------------------

    async def get_vulns_by_host(
        self,
        host_id: str,
        min_severity: str | None = None,
    ) -> list[dict[str, Any]]:
        """Get vulnerabilities for a specific host."""
        severity_filter = ""
        params: dict[str, Any] = {"host_id": host_id}

        if min_severity:
            severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
            threshold = severity_order.get(min_severity.lower(), 4)
            allowed = [s for s, v in severity_order.items() if v <= threshold]
            severity_filter = "AND v.severity IN $allowed_severities"
            params["allowed_severities"] = allowed

        query = f"""
        MATCH (h:Host {{node_id: $host_id}})-[:HAS_VULN]->(v:Vulnerability)
        WHERE TRUE {severity_filter}
        RETURN v.vuln_id AS vuln_id,
               v.name AS name,
               v.severity AS severity,
               v.cvss_score AS cvss_score,
               v.cve_id AS cve_id,
               v.description AS description
        ORDER BY v.cvss_score DESC
        """
        records = await self._client.execute_read(query, params)
        return [dict(r) for r in records]

    # ------------------------------------------------------------------
    # Exploit Chains
    # ------------------------------------------------------------------

    async def get_exploit_chains(
        self,
        project_id: str,
        max_depth: int = 4,
        limit: int = 20,
    ) -> list[dict[str, Any]]:
        """
        Find multi-hop exploit chains:
        Vulnerability → Host → Credential → Host → ...
        """
        query = f"""
        MATCH path = (v:Vulnerability)<-[:HAS_VULN]-(h1:Host)
                      -[:HAS_CREDENTIAL]->(c:Credential)
                      -[:GRANTS_ACCESS]->(h2:Host)
        WHERE h1.project_id = $project_id
              AND h1 <> h2
        RETURN v.name AS vuln_name,
               v.severity AS severity,
               h1.hostname AS source_host,
               c.username AS credential,
               h2.hostname AS target_host,
               length(path) AS chain_length
        ORDER BY v.cvss_score DESC
        LIMIT $limit
        """
        records = await self._client.execute_read(
            query, {"project_id": project_id, "limit": limit},
        )
        return [dict(r) for r in records]

    # ------------------------------------------------------------------
    # Lateral Movement
    # ------------------------------------------------------------------

    async def get_lateral_movement_options(
        self,
        source_host_id: str,
        max_depth: int = 3,
    ) -> list[dict[str, Any]]:
        """
        Find lateral movement options from a compromised host.
        """
        query = f"""
        MATCH (source:Host {{node_id: $host_id}})
        MATCH path = (source)-[:HAS_CREDENTIAL|CAN_REACH|GRANTS_ACCESS*1..{max_depth}]->(target:Host)
        WHERE source <> target
        RETURN target.hostname AS target_host,
               target.ip AS target_ip,
               target.os AS target_os,
               [r IN relationships(path) | type(r)] AS path_types,
               length(path) AS hops
        ORDER BY hops ASC
        LIMIT 20
        """
        records = await self._client.execute_read(query, {"host_id": source_host_id})
        return [dict(r) for r in records]

    # ------------------------------------------------------------------
    # Credential Reuse
    # ------------------------------------------------------------------

    async def get_credential_reuse(
        self,
        project_id: str,
        limit: int = 20,
    ) -> list[dict[str, Any]]:
        """
        Find credentials that grant access to multiple hosts
        (credential reuse / shared credentials).
        """
        query = """
        MATCH (c:Credential)-[:GRANTS_ACCESS]->(h:Host)
        WHERE h.project_id = $project_id
        WITH c, collect(h) AS hosts, count(h) AS host_count
        WHERE host_count > 1
        RETURN c.username AS username,
               c.credential_type AS type,
               host_count,
               [h IN hosts | h.hostname] AS accessible_hosts
        ORDER BY host_count DESC
        LIMIT $limit
        """
        records = await self._client.execute_read(
            query, {"project_id": project_id, "limit": limit},
        )
        return [dict(r) for r in records]

    # ------------------------------------------------------------------
    # High-Value Targets
    # ------------------------------------------------------------------

    async def get_high_value_targets(
        self,
        project_id: str,
        limit: int = 20,
    ) -> list[dict[str, Any]]:
        """
        Identify high-value targets: hosts with most connections,
        critical vulnerabilities, or admin access.
        """
        query = """
        MATCH (h:Host {project_id: $project_id})
        OPTIONAL MATCH (h)-[:HAS_VULN]->(v:Vulnerability)
        WHERE v.severity IN ['critical', 'high']
        OPTIONAL MATCH (h)<-[:ADMIN_TO]-(admin)
        WITH h,
             count(DISTINCT v) AS critical_vulns,
             count(DISTINCT admin) AS admin_count
        RETURN h.hostname AS hostname,
               h.ip AS ip,
               h.os AS os,
               critical_vulns,
               admin_count,
               critical_vulns + admin_count AS score
        ORDER BY score DESC
        LIMIT $limit
        """
        records = await self._client.execute_read(
            query, {"project_id": project_id, "limit": limit},
        )
        return [dict(r) for r in records]
