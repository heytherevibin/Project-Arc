"""
Entity Memory

Tracks named entities (hosts, users, services, credentials) discovered
during engagements and maintains their state across agent interactions.
Augments the Neo4j semantic knowledge base with relationship reasoning.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from core.logging import get_logger
from graph.client import Neo4jClient

logger = get_logger(__name__)


@dataclass
class Entity:
    """A tracked entity in the engagement."""
    entity_id: str
    entity_type: str          # host, user, service, credential, domain, etc.
    name: str                 # Primary identifier (hostname, username, etc.)
    properties: dict[str, Any] = field(default_factory=dict)
    relationships: list[dict[str, Any]] = field(default_factory=list)
    first_seen: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    last_seen: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    confidence: float = 1.0   # 0.0–1.0
    source: str = ""


class EntityMemory:
    """
    Entity tracking and relationship management.

    Stores entities in Neo4j with (:TrackedEntity) labels and
    creates typed relationships between them.  Supports queries
    like "what services run on host X?" or "which users have
    admin access to domain Y?".
    """

    def __init__(self, client: Neo4jClient) -> None:
        self._client = client

    async def track_entity(
        self,
        entity_type: str,
        name: str,
        properties: dict[str, Any] | None = None,
        source: str = "",
        project_id: str = "",
    ) -> str:
        """
        Track a newly discovered entity.  Upserts by (type, name).

        Returns the entity_id.
        """
        import uuid
        entity_id = f"ent-{uuid.uuid4().hex[:12]}"

        props = properties or {}
        props_keys = list(props.keys())

        # Build dynamic SET clause for extra properties
        set_clauses = ", ".join(
            f"e.`{k}` = ${k}" for k in props_keys
        )
        if set_clauses:
            set_clauses = ", " + set_clauses

        params: dict[str, Any] = {
            "entity_type": entity_type,
            "name": name,
            "entity_id": entity_id,
            "source": source,
            "project_id": project_id,
            **props,
        }

        await self._client.execute_write(
            f"""
            MERGE (e:TrackedEntity {{entity_type: $entity_type, name: $name}})
            ON CREATE SET
                e.entity_id = $entity_id,
                e.project_id = $project_id,
                e.source = $source,
                e.first_seen = datetime(),
                e.last_seen = datetime()
                {set_clauses}
            ON MATCH SET
                e.last_seen = datetime(),
                e.source = $source
                {set_clauses}
            """,
            params,
        )

        logger.debug("Tracked entity", entity_type=entity_type, name=name)
        return entity_id

    async def relate(
        self,
        source_name: str,
        target_name: str,
        relationship: str,
        properties: dict[str, Any] | None = None,
    ) -> None:
        """Create a typed relationship between two tracked entities."""
        props_json = str(properties or {})

        await self._client.execute_write(
            f"""
            MATCH (s:TrackedEntity {{name: $source}})
            MATCH (t:TrackedEntity {{name: $target}})
            MERGE (s)-[r:`{relationship}`]->(t)
            SET r.properties = $props, r.updated_at = datetime()
            """,
            {"source": source_name, "target": target_name, "props": props_json},
        )

    async def get_entity(self, name: str) -> dict[str, Any] | None:
        """Retrieve an entity by name."""
        records = await self._client.execute_read(
            """
            MATCH (e:TrackedEntity {name: $name})
            RETURN e
            """,
            {"name": name},
        )
        if records:
            return dict(records[0]["e"])
        return None

    async def get_related_entities(
        self,
        name: str,
        relationship: str | None = None,
        limit: int = 20,
    ) -> list[dict[str, Any]]:
        """Get entities related to the given entity."""
        if relationship:
            records = await self._client.execute_read(
                f"""
                MATCH (e:TrackedEntity {{name: $name}})-[r:`{relationship}`]-(related:TrackedEntity)
                RETURN related, type(r) AS rel_type
                LIMIT $limit
                """,
                {"name": name, "limit": limit},
            )
        else:
            records = await self._client.execute_read(
                """
                MATCH (e:TrackedEntity {name: $name})-[r]-(related:TrackedEntity)
                RETURN related, type(r) AS rel_type
                LIMIT $limit
                """,
                {"name": name, "limit": limit},
            )
        return [{"entity": dict(r["related"]), "relationship": r["rel_type"]} for r in records]

    async def search_entities(
        self,
        entity_type: str | None = None,
        project_id: str | None = None,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        """Search entities by type and/or project."""
        where_clauses: list[str] = []
        params: dict[str, Any] = {"limit": limit}

        if entity_type:
            where_clauses.append("e.entity_type = $entity_type")
            params["entity_type"] = entity_type
        if project_id:
            where_clauses.append("e.project_id = $project_id")
            params["project_id"] = project_id

        where = "WHERE " + " AND ".join(where_clauses) if where_clauses else ""

        records = await self._client.execute_read(
            f"""
            MATCH (e:TrackedEntity)
            {where}
            RETURN e
            ORDER BY e.last_seen DESC
            LIMIT $limit
            """,
            params,
        )
        return [dict(r["e"]) for r in records]
