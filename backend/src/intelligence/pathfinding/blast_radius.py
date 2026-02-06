"""
Blast Radius Calculator

Given a compromised node, performs BFS/DFS through the Neo4j graph
to find all reachable assets — hosts, users, data, and critical
infrastructure — providing a comprehensive blast-radius assessment.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from core.logging import get_logger
from graph.client import Neo4jClient

logger = get_logger(__name__)


@dataclass
class BlastRadius:
    """Result of a blast-radius calculation."""
    source_node: str
    reachable_hosts: list[dict[str, Any]]
    reachable_users: list[dict[str, Any]]
    critical_assets_at_risk: list[dict[str, Any]]
    data_at_risk: list[dict[str, Any]]
    total_reachable: int = 0
    max_depth: int = 0
    risk_score: float = 0.0


class BlastRadiusCalculator:
    """
    Calculates the blast radius from a compromised node.

    Uses Neo4j variable-length path queries to traverse the attack
    graph and identify all assets that could be impacted if a
    particular host or account is compromised.
    """

    # Default max traversal depth
    DEFAULT_MAX_DEPTH = 6

    # Node labels considered critical assets
    CRITICAL_LABELS = {"DomainController", "DatabaseServer", "CertificateAuthority", "FileServer"}

    def __init__(self, client: Neo4jClient) -> None:
        self._client = client

    async def calculate(
        self,
        source_id: str,
        source_type: str = "Host",
        max_depth: int | None = None,
        project_id: str | None = None,
    ) -> BlastRadius:
        """
        Calculate the blast radius from a compromised node.

        Parameters
        ----------
        source_id   : identifier of the compromised node
        source_type : node label (Host, ADUser, etc.)
        max_depth   : max hops from the source
        project_id  : optional project scope
        """
        depth = max_depth or self.DEFAULT_MAX_DEPTH

        # Find all reachable hosts
        hosts = await self._find_reachable_hosts(source_id, source_type, depth, project_id)

        # Find all reachable users/identities
        users = await self._find_reachable_users(source_id, source_type, depth, project_id)

        # Find critical assets at risk
        critical = await self._find_critical_assets(source_id, source_type, depth, project_id)

        # Find data stores at risk
        data = await self._find_data_at_risk(source_id, source_type, depth, project_id)

        total = len(hosts) + len(users) + len(critical) + len(data)

        # Calculate risk score based on reach
        risk_score = self._compute_risk_score(hosts, users, critical, data)

        result = BlastRadius(
            source_node=source_id,
            reachable_hosts=hosts,
            reachable_users=users,
            critical_assets_at_risk=critical,
            data_at_risk=data,
            total_reachable=total,
            max_depth=depth,
            risk_score=risk_score,
        )

        logger.info(
            "Blast radius calculated",
            source=source_id,
            total_reachable=total,
            critical=len(critical),
            risk_score=risk_score,
        )

        return result

    # ------------------------------------------------------------------
    # Sub-queries
    # ------------------------------------------------------------------

    async def _find_reachable_hosts(
        self,
        source_id: str,
        source_type: str,
        depth: int,
        project_id: str | None,
    ) -> list[dict[str, Any]]:
        project_filter = "AND h.project_id = $project_id" if project_id else ""
        query = f"""
        MATCH (source:{source_type} {{node_id: $source_id}})
        MATCH path = (source)-[*1..{depth}]->(h:Host)
        WHERE source <> h {project_filter}
        RETURN DISTINCT h.node_id AS node_id,
               h.hostname AS hostname,
               h.ip AS ip,
               length(path) AS distance
        ORDER BY distance ASC
        """
        params: dict[str, Any] = {"source_id": source_id}
        if project_id:
            params["project_id"] = project_id

        records = await self._client.execute_read(query, params)
        return [dict(r) for r in records]

    async def _find_reachable_users(
        self,
        source_id: str,
        source_type: str,
        depth: int,
        project_id: str | None,
    ) -> list[dict[str, Any]]:
        project_filter = "AND u.project_id = $project_id" if project_id else ""
        query = f"""
        MATCH (source:{source_type} {{node_id: $source_id}})
        MATCH path = (source)-[*1..{depth}]->(u)
        WHERE (u:ADUser OR u:AzureUser OR u:User)
              AND source <> u {project_filter}
        RETURN DISTINCT u.node_id AS node_id,
               u.username AS username,
               u.display_name AS display_name,
               labels(u) AS labels,
               length(path) AS distance
        ORDER BY distance ASC
        """
        params: dict[str, Any] = {"source_id": source_id}
        if project_id:
            params["project_id"] = project_id

        records = await self._client.execute_read(query, params)
        return [dict(r) for r in records]

    async def _find_critical_assets(
        self,
        source_id: str,
        source_type: str,
        depth: int,
        project_id: str | None,
    ) -> list[dict[str, Any]]:
        labels_union = " OR ".join(f"c:{label}" for label in self.CRITICAL_LABELS)
        project_filter = "AND c.project_id = $project_id" if project_id else ""
        query = f"""
        MATCH (source:{source_type} {{node_id: $source_id}})
        MATCH path = (source)-[*1..{depth}]->(c)
        WHERE ({labels_union}) AND source <> c {project_filter}
        RETURN DISTINCT c.node_id AS node_id,
               c.hostname AS hostname,
               labels(c) AS labels,
               length(path) AS distance
        ORDER BY distance ASC
        """
        params: dict[str, Any] = {"source_id": source_id}
        if project_id:
            params["project_id"] = project_id

        records = await self._client.execute_read(query, params)
        return [dict(r) for r in records]

    async def _find_data_at_risk(
        self,
        source_id: str,
        source_type: str,
        depth: int,
        project_id: str | None,
    ) -> list[dict[str, Any]]:
        project_filter = "AND d.project_id = $project_id" if project_id else ""
        query = f"""
        MATCH (source:{source_type} {{node_id: $source_id}})
        MATCH path = (source)-[*1..{depth}]->(d)
        WHERE (d:Database OR d:FileShare OR d:S3Bucket OR d:DataStore)
              AND source <> d {project_filter}
        RETURN DISTINCT d.node_id AS node_id,
               d.name AS name,
               labels(d) AS labels,
               length(path) AS distance
        ORDER BY distance ASC
        """
        params: dict[str, Any] = {"source_id": source_id}
        if project_id:
            params["project_id"] = project_id

        records = await self._client.execute_read(query, params)
        return [dict(r) for r in records]

    # ------------------------------------------------------------------
    # Risk scoring
    # ------------------------------------------------------------------

    @staticmethod
    def _compute_risk_score(
        hosts: list[dict[str, Any]],
        users: list[dict[str, Any]],
        critical: list[dict[str, Any]],
        data: list[dict[str, Any]],
    ) -> float:
        """
        Compute a normalised risk score (0-10) based on blast radius.
        """
        host_score = min(3.0, len(hosts) * 0.3)
        user_score = min(2.0, len(users) * 0.2)
        critical_score = min(3.0, len(critical) * 1.0)
        data_score = min(2.0, len(data) * 0.5)

        return min(10.0, host_score + user_score + critical_score + data_score)
