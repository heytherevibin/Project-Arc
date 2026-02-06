"""
Vulnerability Chain GDS Projection

Creates a GDS projection focused on vulnerability exploitation chains:
Vulnerability → Host → Credential → Host.  Used for discovering
multi-hop exploit chains and lateral movement paths via vulnerabilities.
"""

from __future__ import annotations

from core.logging import get_logger
from graph.client import Neo4jClient

logger = get_logger(__name__)


class VulnChainProjection:
    """
    GDS projection for vulnerability exploitation chains.

    Nodes: Vulnerability, Host, Credential, Service
    Relationships: HAS_VULN, CAN_EXPLOIT, GRANTS_ACCESS,
                   HAS_CREDENTIAL, CAN_REACH
    """

    def __init__(self, client: Neo4jClient) -> None:
        self._client = client

    def _name(self, project_id: str) -> str:
        return f"vuln_chain_{project_id}"

    async def exists(self, project_id: str) -> bool:
        """Check if the projection exists."""
        result = await self._client.execute_read(
            "CALL gds.graph.exists($name) YIELD exists RETURN exists",
            {"name": self._name(project_id)},
        )
        return bool(result and result[0].get("exists"))

    async def drop(self, project_id: str) -> None:
        """Drop the projection if it exists."""
        if await self.exists(project_id):
            await self._client.execute_write(
                "CALL gds.graph.drop($name)",
                {"name": self._name(project_id)},
            )
            logger.info("Dropped vuln chain projection", project_id=project_id)

    async def create(self, project_id: str) -> str:
        """
        Create the vulnerability chain GDS projection.

        Returns the projection name.
        """
        name = self._name(project_id)

        # Drop existing first
        await self.drop(project_id)

        query = """
        CALL gds.graph.project.cypher(
            $name,
            'MATCH (n)
             WHERE (n:Vulnerability OR n:Host OR n:Credential OR n:Service)
                   AND n.project_id = $project_id
             RETURN id(n) AS id, labels(n) AS labels',
            'MATCH (a)-[r]->(b)
             WHERE type(r) IN [
                "HAS_VULN", "CAN_EXPLOIT", "GRANTS_ACCESS",
                "HAS_CREDENTIAL", "CAN_REACH", "RUNS_SERVICE"
             ]
             AND a.project_id = $project_id
             AND b.project_id = $project_id
             RETURN id(a) AS source, id(b) AS target, type(r) AS type',
            {parameters: {project_id: $project_id}}
        )
        YIELD graphName, nodeCount, relationshipCount
        RETURN graphName, nodeCount, relationshipCount
        """

        result = await self._client.execute_write(
            query, {"name": name, "project_id": project_id},
        )

        if result:
            row = result[0]
            logger.info(
                "Vuln chain projection created",
                name=name,
                nodes=row.get("nodeCount"),
                rels=row.get("relationshipCount"),
            )
        else:
            logger.info("Vuln chain projection created", name=name)

        return name
