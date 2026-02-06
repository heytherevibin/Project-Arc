"""
Identity Graph GDS Projection

Creates and manages a GDS graph projection focused on Active Directory
and Azure AD identity relationships (BloodHound-style).
"""

from core.logging import get_logger
from graph.client import Neo4jClient

logger = get_logger(__name__)


class IdentityGraphProjection:
    """
    GDS projection for the identity attack graph.

    Nodes: ADUser, ADGroup, ADComputer, ADGPO, ADOU
    Relationships: MEMBER_OF, ADMIN_TO, CAN_RDPINTO, CAN_PSREMOTE,
                   GENERIC_ALL, GENERIC_WRITE, WRITE_DACL, WRITE_OWNER,
                   FORCE_CHANGE_PASSWORD, ADD_MEMBER, OWNS,
                   HAS_SPN_TO, ALLOWED_TO_DELEGATE, HAS_SESSION, CAN_ENROLL
    """

    IDENTITY_REL_TYPES = [
        "MEMBER_OF", "ADMIN_TO", "CAN_RDPINTO", "CAN_PSREMOTE", "EXECUTE_DCOM",
        "GENERIC_ALL", "GENERIC_WRITE", "WRITE_DACL", "WRITE_OWNER",
        "FORCE_CHANGE_PASSWORD", "ADD_MEMBER", "OWNS",
        "HAS_SPN_TO", "ALLOWED_TO_DELEGATE", "ALLOWED_TO_ACT",
        "HAS_SESSION", "CAN_ENROLL", "ENABLES_AUTH_AS",
        "GPO_EDIT", "APPLIES_TO", "CONTAINS",
    ]

    def __init__(self, client: Neo4jClient) -> None:
        self.client = client

    def _name(self, project_id: str) -> str:
        return f"identity_graph_{project_id}"

    async def exists(self, project_id: str) -> bool:
        result = await self.client.execute_read(
            "CALL gds.graph.exists($name) YIELD exists RETURN exists",
            {"name": self._name(project_id)},
        )
        return bool(result and result[0].get("exists"))

    async def drop(self, project_id: str) -> None:
        if await self.exists(project_id):
            await self.client.execute_write(
                "CALL gds.graph.drop($name)",
                {"name": self._name(project_id)},
            )
            logger.info("Dropped identity graph projection", project_id=project_id)

    async def create(self, project_id: str) -> str:
        """Create (or recreate) the identity GDS projection."""
        name = self._name(project_id)
        await self.drop(project_id)

        rel_type_list = ", ".join(f'"{r}"' for r in self.IDENTITY_REL_TYPES)

        await self.client.execute_write(
            f"""
            CALL gds.graph.project.cypher(
                $name,
                '
                MATCH (n)
                WHERE n.project_id = $project_id
                  AND (n:ADUser OR n:ADGroup OR n:ADComputer
                       OR n:ADGPO OR n:ADOU OR n:ADDomain
                       OR n:ADCertTemplate OR n:ADCA)
                RETURN id(n) AS id,
                       labels(n) AS labels,
                       coalesce(n.high_value, false) AS high_value,
                       coalesce(n.enabled, true)     AS enabled
                ',
                '
                MATCH (s)-[r]->(t)
                WHERE s.project_id = $project_id
                  AND t.project_id = $project_id
                  AND type(r) IN [{rel_type_list}]
                RETURN id(s) AS source,
                       id(t) AS target,
                       type(r)   AS type,
                       coalesce(r.cost, 1.0) AS cost
                ',
                {{project_id: $project_id}}
            )
            """,
            {"name": name, "project_id": project_id},
        )

        logger.info("Created identity graph projection", name=name, project_id=project_id)
        return name
