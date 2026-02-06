"""
Attack Path Finder

Uses Neo4j GDS shortest-path and all-shortest-paths algorithms to
discover attack paths between entry points and high-value targets.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from core.logging import get_logger
from graph.client import Neo4jClient

logger = get_logger(__name__)


@dataclass
class PathStep:
    """Single step/hop in an attack path."""
    node_id: str
    label: str          # e.g. "Host", "ADUser", "Credential"
    name: str
    properties: dict[str, Any] = field(default_factory=dict)
    relationship: str = ""  # relationship type to next node


@dataclass
class AttackPath:
    """A complete attack path from source to target."""
    path_id: str
    source: str
    target: str
    steps: list[PathStep] = field(default_factory=list)
    total_cost: float = 0.0
    hop_count: int = 0
    risk_score: float = 0.0
    techniques: list[str] = field(default_factory=list)  # MITRE technique IDs


class AttackPathFinder:
    """
    Discovers attack paths in the Neo4j graph using GDS algorithms.

    Supports:
    - Shortest path between two nodes
    - All shortest paths
    - k-shortest paths (Yen's algorithm via GDS)
    - Paths to high-value targets (Domain Admin, critical servers)
    """

    GRAPH_PROJECTION = "attack-surface"

    def __init__(self, neo4j_client: Neo4jClient) -> None:
        self._client = neo4j_client

    async def find_shortest_path(
        self,
        source_id: str,
        target_id: str,
        project_id: str,
    ) -> AttackPath | None:
        """Find shortest attack path between two nodes using native Cypher."""
        result = await self._client.execute_read(
            """
            MATCH p = shortestPath(
                (src {id: $source, project_id: $pid})-[*..15]-
                (tgt {id: $target, project_id: $pid})
            )
            RETURN
                [n IN nodes(p) | {
                    id: coalesce(n.id, n.object_id, n.address, n.name),
                    label: labels(n)[0],
                    name: coalesce(n.name, n.address, n.object_id, ''),
                    properties: properties(n)
                }] AS nodes,
                [r IN relationships(p) | type(r)] AS rels,
                length(p) AS hops
            """,
            {"source": source_id, "target": target_id, "pid": project_id},
        )

        if not result:
            return None

        row = result[0]
        steps = self._build_steps(row["nodes"], row["rels"])

        return AttackPath(
            path_id=f"{source_id}->{target_id}",
            source=source_id,
            target=target_id,
            steps=steps,
            hop_count=row["hops"],
        )

    async def find_all_shortest_paths(
        self,
        source_id: str,
        target_id: str,
        project_id: str,
        limit: int = 10,
    ) -> list[AttackPath]:
        """Find all shortest paths between two nodes."""
        result = await self._client.execute_read(
            """
            MATCH p = allShortestPaths(
                (src {id: $source, project_id: $pid})-[*..15]-
                (tgt {id: $target, project_id: $pid})
            )
            WITH p, length(p) AS hops
            ORDER BY hops ASC
            LIMIT $limit
            RETURN
                [n IN nodes(p) | {
                    id: coalesce(n.id, n.object_id, n.address, n.name),
                    label: labels(n)[0],
                    name: coalesce(n.name, n.address, n.object_id, ''),
                    properties: properties(n)
                }] AS nodes,
                [r IN relationships(p) | type(r)] AS rels,
                hops
            """,
            {"source": source_id, "target": target_id, "pid": project_id, "limit": limit},
        )

        paths: list[AttackPath] = []
        for idx, row in enumerate(result):
            steps = self._build_steps(row["nodes"], row["rels"])
            paths.append(AttackPath(
                path_id=f"{source_id}->{target_id}#{idx}",
                source=source_id,
                target=target_id,
                steps=steps,
                hop_count=row["hops"],
            ))
        return paths

    async def find_paths_to_domain_admin(
        self,
        project_id: str,
        limit: int = 20,
    ) -> list[AttackPath]:
        """Find shortest paths from any compromised node to Domain Admin."""
        result = await self._client.execute_read(
            """
            MATCH (da:ADGroup {project_id: $pid})
            WHERE da.name =~ '(?i).*domain admins.*'
            MATCH p = shortestPath(
                (src {project_id: $pid})-[*..15]-(da)
            )
            WHERE src <> da
              AND (src:Host OR src:IP OR src:ADUser OR src:ADComputer)
            WITH p, src, da, length(p) AS hops
            ORDER BY hops ASC
            LIMIT $limit
            RETURN
                [n IN nodes(p) | {
                    id: coalesce(n.id, n.object_id, n.address, n.name),
                    label: labels(n)[0],
                    name: coalesce(n.name, n.address, n.object_id, ''),
                    properties: properties(n)
                }] AS nodes,
                [r IN relationships(p) | type(r)] AS rels,
                hops,
                coalesce(src.id, src.name, src.address) AS src_name,
                coalesce(da.name) AS da_name
            """,
            {"pid": project_id, "limit": limit},
        )

        paths: list[AttackPath] = []
        for idx, row in enumerate(result):
            steps = self._build_steps(row["nodes"], row["rels"])
            paths.append(AttackPath(
                path_id=f"da-path-{idx}",
                source=row["src_name"],
                target=row["da_name"],
                steps=steps,
                hop_count=row["hops"],
            ))
        return paths

    async def find_critical_paths(
        self,
        project_id: str,
        max_hops: int = 10,
        limit: int = 25,
    ) -> list[AttackPath]:
        """
        Find paths from internet-facing assets to high-value targets
        (servers, domain controllers, databases).
        """
        result = await self._client.execute_read(
            """
            MATCH (entry {project_id: $pid})
            WHERE (entry:IP OR entry:Host OR entry:Subdomain)
              AND (entry.is_internet_facing = true OR entry.external = true)
            MATCH (target {project_id: $pid})
            WHERE (target:ADComputer OR target:Host)
              AND (target.is_dc = true OR target.criticality = 'high'
                   OR target.role IN ['dc', 'database', 'ca'])
            MATCH p = shortestPath((entry)-[*..{max_hops}]-(target))
            WITH p, entry, target, length(p) AS hops
            ORDER BY hops ASC
            LIMIT $limit
            RETURN
                [n IN nodes(p) | {
                    id: coalesce(n.id, n.object_id, n.address, n.name),
                    label: labels(n)[0],
                    name: coalesce(n.name, n.address, n.object_id, ''),
                    properties: properties(n)
                }] AS nodes,
                [r IN relationships(p) | type(r)] AS rels,
                hops,
                coalesce(entry.name, entry.address) AS entry_name,
                coalesce(target.name, target.address) AS target_name
            """.replace("{max_hops}", str(max_hops)),
            {"pid": project_id, "limit": limit},
        )

        paths: list[AttackPath] = []
        for idx, row in enumerate(result):
            steps = self._build_steps(row["nodes"], row["rels"])
            paths.append(AttackPath(
                path_id=f"critical-{idx}",
                source=row.get("entry_name", "entry"),
                target=row.get("target_name", "target"),
                steps=steps,
                hop_count=row["hops"],
            ))
        return paths

    async def find_choke_points(
        self,
        project_id: str,
        limit: int = 15,
    ) -> list[dict[str, Any]]:
        """
        Identify choke points — nodes that appear in many attack paths.
        Uses betweenness centrality on the projected graph if available,
        otherwise falls back to path-frequency heuristic.
        """
        # Try GDS betweenness centrality first
        try:
            result = await self._client.execute_read(
                """
                CALL gds.betweenness.stream($graph)
                YIELD nodeId, score
                WITH gds.util.asNode(nodeId) AS node, score
                WHERE node.project_id = $pid AND score > 0
                RETURN
                    coalesce(node.id, node.name, node.address) AS id,
                    labels(node)[0] AS label,
                    coalesce(node.name, node.address) AS name,
                    score AS betweenness
                ORDER BY score DESC
                LIMIT $limit
                """,
                {"graph": self.GRAPH_PROJECTION, "pid": project_id, "limit": limit},
            )
            return [dict(r) for r in result]
        except Exception:
            logger.debug("GDS betweenness not available, using fallback")

        # Fallback: count how many paths pass through each node
        result = await self._client.execute_read(
            """
            MATCH (entry {project_id: $pid})
            WHERE (entry:IP OR entry:Host) AND entry.is_internet_facing = true
            MATCH (target {project_id: $pid})
            WHERE (target:ADComputer OR target:Host) AND target.criticality = 'high'
            MATCH p = shortestPath((entry)-[*..10]-(target))
            UNWIND nodes(p) AS n
            WITH n, count(*) AS freq
            WHERE freq > 1
            RETURN
                coalesce(n.id, n.name, n.address) AS id,
                labels(n)[0] AS label,
                coalesce(n.name, n.address) AS name,
                freq AS betweenness
            ORDER BY freq DESC
            LIMIT $limit
            """,
            {"pid": project_id, "limit": limit},
        )
        return [dict(r) for r in result]

    # ----------- helpers -------------------------------------------------------
    @staticmethod
    def _build_steps(nodes: list[dict], rels: list[str]) -> list[PathStep]:
        steps: list[PathStep] = []
        for idx, node in enumerate(nodes):
            rel = rels[idx] if idx < len(rels) else ""
            steps.append(PathStep(
                node_id=str(node.get("id", "")),
                label=node.get("label", ""),
                name=node.get("name", ""),
                properties=node.get("properties", {}),
                relationship=rel,
            ))
        return steps
