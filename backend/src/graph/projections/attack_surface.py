"""
Attack Surface GDS Projection

Creates and manages a GDS graph projection for attack path discovery
across the full attack surface (hosts, vulnerabilities, credentials).
"""

from core.logging import get_logger
from graph.client import Neo4jClient

logger = get_logger(__name__)


class AttackSurfaceProjection:
    """
    GDS projection for the attack surface graph.

    Nodes: IP, Host, ADComputer, ADUser, Credential, Vulnerability
    Relationships: CAN_REACH, CAN_EXPLOIT, LEADS_TO, HAS_ACCESS,
                   MEMBER_OF, ADMIN_TO, GRANTS_ACCESS
    """

    def __init__(self, client: Neo4jClient) -> None:
        self.client = client

    def _name(self, project_id: str) -> str:
        return f"attack_surface_{project_id}"

    async def exists(self, project_id: str) -> bool:
        """Check if the projection already exists."""
        result = await self.client.execute_read(
            "CALL gds.graph.exists($name) YIELD exists RETURN exists",
            {"name": self._name(project_id)},
        )
        return bool(result and result[0].get("exists"))

    async def drop(self, project_id: str) -> None:
        """Drop the projection if it exists."""
        if await self.exists(project_id):
            await self.client.execute_write(
                "CALL gds.graph.drop($name)",
                {"name": self._name(project_id)},
            )
            logger.info("Dropped attack surface projection", project_id=project_id)

    async def create(self, project_id: str) -> str:
        """
        Create (or recreate) the attack surface GDS projection.

        Returns the projection name.
        """
        name = self._name(project_id)

        # Drop stale projection
        await self.drop(project_id)

        # Use Cypher projection for flexibility
        await self.client.execute_write(
            """
            CALL gds.graph.project.cypher(
                $name,
                // --- Node query ---
                '
                MATCH (n)
                WHERE n.project_id = $project_id
                  AND (n:IP OR n:Subdomain OR n:ADComputer OR n:ADUser
                       OR n:Credential OR n:Vulnerability OR n:Port)
                RETURN id(n) AS id,
                       labels(n) AS labels,
                       coalesce(n.criticality, 0.5)   AS criticality,
                       coalesce(n.compromised, false)  AS compromised
                ',
                // --- Relationship query ---
                '
                MATCH (s)-[r]->(t)
                WHERE s.project_id = $project_id
                  AND t.project_id = $project_id
                  AND type(r) IN [
                      "CAN_REACH","CAN_EXPLOIT","LEADS_TO","HAS_ACCESS",
                      "RESOLVES_TO","HAS_PORT","HAS_VULNERABILITY",
                      "MEMBER_OF","ADMIN_TO","CAN_RDPINTO","GRANTS_ACCESS"
                  ]
                RETURN id(s) AS source,
                       id(t) AS target,
                       type(r)   AS type,
                       coalesce(r.cost, r.difficulty, 0.5) AS cost
                ',
                {project_id: $project_id}
            )
            """,
            {"name": name, "project_id": project_id},
        )

        logger.info("Created attack surface projection", name=name, project_id=project_id)
        return name

    async def node_count(self, project_id: str) -> int:
        """Return node count of the projected graph."""
        name = self._name(project_id)
        if not await self.exists(project_id):
            return 0
        result = await self.client.execute_read(
            "CALL gds.graph.list() YIELD graphName, nodeCount "
            "WHERE graphName = $name RETURN nodeCount",
            {"name": name},
        )
        return result[0]["nodeCount"] if result else 0
