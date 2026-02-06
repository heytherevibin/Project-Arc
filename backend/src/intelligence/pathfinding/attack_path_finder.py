"""
Attack Path Finder

Neo4j GDS-powered attack path discovery. Finds shortest, all possible,
and K-shortest paths from the current position to a target using
Dijkstra, Yen's K-shortest, BFS, and centrality algorithms.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from core.logging import get_logger
from graph.client import Neo4jClient
from graph.projections.attack_surface import AttackSurfaceProjection

logger = get_logger(__name__)


@dataclass
class AttackPath:
    """A discovered attack path."""
    path_id: str
    nodes: list[dict[str, Any]]
    relationships: list[dict[str, Any]]
    total_cost: float
    path_length: int
    techniques: list[str] = field(default_factory=list)


@dataclass
class ChokePoint:
    """A critical node identified by centrality analysis."""
    node_id: str
    node_type: str
    name: str
    centrality_score: float
    paths_through: int = 0


@dataclass
class BlastRadius:
    """Impact assessment of compromising a node."""
    source: str
    reachable_hosts: int
    reachable_users: int
    reachable_data: int
    critical_assets_at_risk: list[dict[str, Any]] = field(default_factory=list)
    total_reachable: int = 0


class AttackPathFinder:
    """
    Neo4j GDS-powered attack path discovery.

    Finds optimal attack paths, critical choke points, and blast radius
    for compromised nodes.
    """

    def __init__(self, neo4j_client: Neo4jClient) -> None:
        self._client = neo4j_client
        self._projection = AttackSurfaceProjection(neo4j_client)

    async def ensure_projection(self, project_id: str) -> str:
        """Create or verify the GDS projection exists."""
        if not await self._projection.exists(project_id):
            return await self._projection.create(project_id)
        return self._projection._name(project_id)

    async def find_shortest_path(
        self,
        source_id: str,
        target_id: str,
        project_id: str,
    ) -> AttackPath | None:
        """
        Find shortest attack path using Dijkstra with exploit difficulty weights.
        """
        projection = await self.ensure_projection(project_id)

        try:
            result = await self._client.execute_read(
                """
                MATCH (source {project_id: $pid}), (target {project_id: $pid})
                WHERE elementId(source) = $source OR source.name = $source
                   OR source.address = $source OR source.sam_account_name = $source
                WITH source LIMIT 1
                MATCH (target {project_id: $pid})
                WHERE elementId(target) = $target OR target.name = $target
                   OR target.address = $target OR target.sam_account_name = $target
                WITH source, target LIMIT 1
                CALL gds.shortestPath.dijkstra.stream($projection, {
                    sourceNode: source,
                    targetNode: target,
                    relationshipWeightProperty: 'cost'
                })
                YIELD index, sourceNode, targetNode, totalCost, nodeIds, costs, path
                RETURN totalCost, nodeIds, costs,
                       [n IN nodes(path) | {id: elementId(n), labels: labels(n), name: coalesce(n.name, n.address, n.sam_account_name, '')}] AS pathNodes,
                       [r IN relationships(path) | {type: type(r), cost: coalesce(r.cost, r.difficulty, 0.5)}] AS pathRels
                """,
                {
                    "projection": projection,
                    "source": source_id,
                    "target": target_id,
                    "pid": project_id,
                },
            )

            if not result:
                return None

            row = result[0]
            return AttackPath(
                path_id=f"{source_id}->{target_id}",
                nodes=row.get("pathNodes", []),
                relationships=row.get("pathRels", []),
                total_cost=row.get("totalCost", 0.0),
                path_length=len(row.get("pathNodes", [])),
            )

        except Exception as e:
            logger.warning("Dijkstra path search failed", error=str(e))
            return None

    async def find_k_shortest_paths(
        self,
        source_id: str,
        target_id: str,
        project_id: str,
        k: int = 5,
    ) -> list[AttackPath]:
        """Find K-shortest paths using Yen's algorithm."""
        projection = await self.ensure_projection(project_id)

        try:
            result = await self._client.execute_read(
                """
                MATCH (source {project_id: $pid}), (target {project_id: $pid})
                WHERE source.name = $source OR source.address = $source
                WITH source LIMIT 1
                MATCH (target {project_id: $pid})
                WHERE target.name = $target OR target.address = $target
                WITH source, target LIMIT 1
                CALL gds.shortestPath.yens.stream($projection, {
                    sourceNode: source,
                    targetNode: target,
                    k: $k,
                    relationshipWeightProperty: 'cost'
                })
                YIELD index, totalCost, nodeIds, path
                RETURN index, totalCost,
                       [n IN nodes(path) | {id: elementId(n), labels: labels(n), name: coalesce(n.name, n.address, '')}] AS pathNodes,
                       [r IN relationships(path) | {type: type(r), cost: coalesce(r.cost, 0.5)}] AS pathRels
                ORDER BY totalCost ASC
                """,
                {
                    "projection": projection,
                    "source": source_id,
                    "target": target_id,
                    "pid": project_id,
                    "k": k,
                },
            )

            return [
                AttackPath(
                    path_id=f"path-{row['index']}",
                    nodes=row.get("pathNodes", []),
                    relationships=row.get("pathRels", []),
                    total_cost=row.get("totalCost", 0.0),
                    path_length=len(row.get("pathNodes", [])),
                )
                for row in result
            ]

        except Exception as e:
            logger.warning("Yen K-shortest paths failed", error=str(e))
            return []

    async def find_choke_points(
        self,
        project_id: str,
        top_n: int = 10,
    ) -> list[ChokePoint]:
        """
        Find critical nodes using betweenness centrality.
        These are high-value targets that many attack paths pass through.
        """
        projection = await self.ensure_projection(project_id)

        try:
            result = await self._client.execute_read(
                """
                CALL gds.betweenness.stream($projection)
                YIELD nodeId, score
                WITH gds.util.asNode(nodeId) AS node, score
                WHERE score > 0
                RETURN elementId(node) AS nodeId,
                       labels(node) AS labels,
                       coalesce(node.name, node.address, node.sam_account_name, '') AS name,
                       score
                ORDER BY score DESC
                LIMIT $top_n
                """,
                {"projection": projection, "top_n": top_n},
            )

            return [
                ChokePoint(
                    node_id=row["nodeId"],
                    node_type=row["labels"][0] if row["labels"] else "unknown",
                    name=row["name"],
                    centrality_score=row["score"],
                )
                for row in result
            ]

        except Exception as e:
            logger.warning("Choke point detection failed", error=str(e))
            return []

    async def calculate_blast_radius(
        self,
        compromised_node: str,
        project_id: str,
        max_depth: int = 5,
    ) -> BlastRadius:
        """Calculate the impact of compromising a specific node."""
        projection = await self.ensure_projection(project_id)

        try:
            result = await self._client.execute_read(
                """
                MATCH (source {project_id: $pid})
                WHERE source.name = $node OR source.address = $node
                WITH source LIMIT 1
                CALL gds.bfs.stream($projection, {
                    sourceNode: source,
                    maxDepth: $depth
                })
                YIELD path
                UNWIND nodes(path) AS reachable
                WITH DISTINCT reachable
                RETURN labels(reachable) AS labels,
                       coalesce(reachable.name, reachable.address, '') AS name,
                       coalesce(reachable.criticality, 'medium') AS criticality
                """,
                {
                    "projection": projection,
                    "node": compromised_node,
                    "pid": project_id,
                    "depth": max_depth,
                },
            )

            hosts = 0
            users = 0
            data_nodes = 0
            critical_assets: list[dict[str, Any]] = []

            for row in result:
                labels = row.get("labels", [])
                if "IP" in labels or "ADComputer" in labels or "Subdomain" in labels:
                    hosts += 1
                if "ADUser" in labels or "AzureUser" in labels:
                    users += 1
                if "Data" in labels:
                    data_nodes += 1
                if row.get("criticality") == "high":
                    critical_assets.append({
                        "name": row["name"],
                        "type": labels[0] if labels else "unknown",
                    })

            return BlastRadius(
                source=compromised_node,
                reachable_hosts=hosts,
                reachable_users=users,
                reachable_data=data_nodes,
                critical_assets_at_risk=critical_assets,
                total_reachable=len(result),
            )

        except Exception as e:
            logger.warning("Blast radius calculation failed", error=str(e))
            return BlastRadius(
                source=compromised_node,
                reachable_hosts=0,
                reachable_users=0,
                reachable_data=0,
            )

    async def find_high_value_nodes(
        self,
        project_id: str,
        top_n: int = 10,
    ) -> list[dict[str, Any]]:
        """Find high-value nodes using PageRank."""
        projection = await self.ensure_projection(project_id)

        try:
            result = await self._client.execute_read(
                """
                CALL gds.pageRank.stream($projection)
                YIELD nodeId, score
                WITH gds.util.asNode(nodeId) AS node, score
                RETURN elementId(node) AS nodeId,
                       labels(node) AS labels,
                       coalesce(node.name, node.address, '') AS name,
                       score
                ORDER BY score DESC
                LIMIT $top_n
                """,
                {"projection": projection, "top_n": top_n},
            )

            return [dict(r) for r in result]

        except Exception as e:
            logger.warning("PageRank failed", error=str(e))
            return []
