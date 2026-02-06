"""
Semantic Memory - Knowledge Base

Stores structured knowledge about targets, services, vulnerabilities,
and their relationships in Neo4j. Provides similarity-based retrieval
for enriching agent context.
"""

from __future__ import annotations

import json
from typing import Any

from core.logging import get_logger
from graph.client import Neo4jClient

logger = get_logger(__name__)


class SemanticMemory:
    """
    Knowledge base backed by Neo4j.

    Stores entities extracted from tool outputs and links them
    into a knowledge graph for relationship-based retrieval.
    """

    def __init__(self, client: Neo4jClient) -> None:
        self._client = client

    async def upsert_entity(self, entity: dict[str, Any]) -> None:
        """
        Upsert a knowledge entity (host, service, vuln, credential, etc.).

        entity keys:
          - type: "ip" | "host" | "subdomain" | "url" | "vulnerability" | "credential" | "service"
          - value: primary identifier
          - source: discovery tool
          - (optional) additional properties
        """
        entity_type = entity.get("type", "unknown")
        value = entity.get("value", "")
        source = entity.get("source", "unknown")

        if not value:
            return

        # Store as a :KnowledgeEntity node
        extra_json = json.dumps(
            {k: v for k, v in entity.items() if k not in ("type", "value", "source")},
            default=str,
        )[:5_000]

        await self._client.execute_write(
            """
            MERGE (k:KnowledgeEntity {entity_type: $type, value: $value})
            ON CREATE SET
                k.created_at = datetime(),
                k.source = $source,
                k.extra = $extra
            ON MATCH SET
                k.updated_at = datetime(),
                k.source = $source,
                k.extra = $extra
            """,
            {"type": entity_type, "value": value, "source": source, "extra": extra_json},
        )

    async def search(
        self,
        query: str,
        project_id: str | None = None,
        target: str | None = None,
        limit: int = 10,
    ) -> list[dict[str, Any]]:
        """
        Search knowledge base for entities matching a query.

        Uses full-text search on entity values and types.
        """
        # Simple keyword-based search (can be upgraded to vector similarity)
        params: dict[str, Any] = {"query": f"*{query}*", "limit": limit}

        # Try full-text if available, fall back to CONTAINS
        try:
            records = await self._client.execute_read(
                """
                MATCH (k:KnowledgeEntity)
                WHERE k.value CONTAINS $plain_query
                   OR k.entity_type CONTAINS $plain_query
                RETURN k.entity_type AS type,
                       k.value AS value,
                       k.source AS source,
                       k.extra AS extra,
                       k.created_at AS created_at
                ORDER BY k.created_at DESC
                LIMIT $limit
                """,
                {"plain_query": query, "limit": limit},
            )
        except Exception:
            records = []

        return [dict(r) for r in records]

    async def get_entities_by_type(
        self,
        entity_type: str,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        """Get all entities of a given type."""
        records = await self._client.execute_read(
            """
            MATCH (k:KnowledgeEntity {entity_type: $type})
            RETURN k.value AS value, k.source AS source,
                   k.extra AS extra, k.created_at AS created_at
            ORDER BY k.created_at DESC
            LIMIT $limit
            """,
            {"type": entity_type, "limit": limit},
        )
        return [dict(r) for r in records]

    async def link_entities(
        self,
        source_value: str,
        target_value: str,
        relationship: str,
        properties: dict[str, Any] | None = None,
    ) -> None:
        """Create a relationship between two knowledge entities."""
        props_json = json.dumps(properties or {}, default=str)
        await self._client.execute_write(
            f"""
            MATCH (s:KnowledgeEntity {{value: $source}})
            MATCH (t:KnowledgeEntity {{value: $target}})
            MERGE (s)-[r:{relationship}]->(t)
            SET r.properties = $props, r.updated_at = datetime()
            """,
            {"source": source_value, "target": target_value, "props": props_json},
        )

    async def get_related(
        self,
        value: str,
        max_depth: int = 2,
        limit: int = 20,
    ) -> list[dict[str, Any]]:
        """Get entities related to a given entity (up to max_depth hops)."""
        records = await self._client.execute_read(
            """
            MATCH (start:KnowledgeEntity {value: $value})
            CALL {
                WITH start
                MATCH path = (start)-[*1..$depth]-(related:KnowledgeEntity)
                RETURN related, length(path) AS distance
                ORDER BY distance ASC
                LIMIT $limit
            }
            RETURN related.entity_type AS type,
                   related.value AS value,
                   related.source AS source,
                   distance
            """,
            {"value": value, "depth": max_depth, "limit": limit},
        )
        return [dict(r) for r in records]
