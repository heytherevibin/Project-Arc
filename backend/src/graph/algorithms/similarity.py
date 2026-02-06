"""
Similarity Analyser

Uses Neo4j GDS node similarity (Jaccard / Overlap) to discover
similar attack patterns, hosts, or vulnerability profiles across
the attack surface graph.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from core.logging import get_logger
from graph.client import Neo4jClient

logger = get_logger(__name__)


@dataclass
class SimilarityResult:
    """A pair of similar nodes with their similarity score."""
    node1_id: str
    node1_name: str
    node2_id: str
    node2_name: str
    similarity: float  # 0-1
    shared_properties: list[str] = field(default_factory=list)


class SimilarityAnalyser:
    """
    Finds similar nodes in the attack graph using Neo4j GDS
    similarity algorithms.

    Use cases:
    - Find hosts with similar vulnerability profiles
    - Detect similar attack patterns across engagements
    - Group nodes by relationship overlap
    """

    def __init__(self, client: Neo4jClient) -> None:
        self._client = client

    async def find_similar_nodes(
        self,
        projection_name: str,
        similarity_metric: str = "jaccard",
        top_k: int = 10,
        similarity_cutoff: float = 0.3,
    ) -> list[SimilarityResult]:
        """
        Find similar node pairs in a GDS projection.

        Parameters
        ----------
        projection_name  : name of the GDS graph projection
        similarity_metric: "jaccard" or "overlap"
        top_k            : number of most similar pairs per node
        similarity_cutoff: minimum similarity score
        """
        algo = "gds.nodeSimilarity"

        query = f"""
        CALL {algo}.stream($projection, {{
            topK: $topK,
            similarityCutoff: $cutoff
        }})
        YIELD node1, node2, similarity
        WITH gds.util.asNode(node1) AS n1,
             gds.util.asNode(node2) AS n2,
             similarity
        RETURN n1.node_id AS node1_id,
               coalesce(n1.name, n1.hostname, n1.node_id) AS node1_name,
               n2.node_id AS node2_id,
               coalesce(n2.name, n2.hostname, n2.node_id) AS node2_name,
               similarity
        ORDER BY similarity DESC
        LIMIT $limit
        """
        params = {
            "projection": projection_name,
            "topK": top_k,
            "cutoff": similarity_cutoff,
            "limit": top_k * 2,
        }

        records = await self._client.execute_read(query, params)

        results = [
            SimilarityResult(
                node1_id=r["node1_id"],
                node1_name=r["node1_name"],
                node2_id=r["node2_id"],
                node2_name=r["node2_name"],
                similarity=r["similarity"],
            )
            for r in records
        ]

        logger.info(
            "Node similarity computed",
            projection=projection_name,
            metric=similarity_metric,
            pairs=len(results),
        )
        return results

    async def find_similar_paths(
        self,
        source_path_nodes: list[str],
        projection_name: str,
        top_k: int = 5,
    ) -> list[dict[str, Any]]:
        """
        Given a set of nodes forming a path, find other paths in the
        graph that traverse similar nodes.
        """
        query = """
        UNWIND $path_nodes AS pid
        MATCH (n {node_id: pid})
        WITH collect(id(n)) AS source_ids

        CALL gds.nodeSimilarity.stream($projection, {
            topK: $topK
        })
        YIELD node1, node2, similarity
        WHERE node1 IN source_ids
        WITH gds.util.asNode(node2) AS similar,
             avg(similarity) AS avg_sim
        RETURN similar.node_id AS node_id,
               coalesce(similar.name, similar.hostname, similar.node_id) AS name,
               labels(similar) AS labels,
               avg_sim
        ORDER BY avg_sim DESC
        LIMIT $topK
        """
        params = {
            "path_nodes": source_path_nodes,
            "projection": projection_name,
            "topK": top_k,
        }

        records = await self._client.execute_read(query, params)
        return [dict(r) for r in records]

    async def find_hosts_with_similar_vulns(
        self,
        host_id: str,
        project_id: str | None = None,
        limit: int = 10,
    ) -> list[SimilarityResult]:
        """
        Find hosts with similar vulnerability profiles using
        direct Cypher (no GDS projection required).
        """
        project_filter = "AND h2.project_id = $project_id" if project_id else ""
        query = f"""
        MATCH (h1:Host {{node_id: $host_id}})-[:HAS_VULN]->(v:Vulnerability)
        WITH h1, collect(v.vuln_id) AS h1_vulns
        MATCH (h2:Host)-[:HAS_VULN]->(v2:Vulnerability)
        WHERE h2 <> h1 {project_filter}
        WITH h1, h1_vulns, h2, collect(v2.vuln_id) AS h2_vulns
        WITH h1, h2, h1_vulns, h2_vulns,
             size([x IN h1_vulns WHERE x IN h2_vulns]) AS intersection,
             size(h1_vulns + [x IN h2_vulns WHERE NOT x IN h1_vulns]) AS union_size
        WHERE union_size > 0
        WITH h1, h2,
             toFloat(intersection) / union_size AS jaccard
        WHERE jaccard > 0.2
        RETURN h1.node_id AS node1_id,
               coalesce(h1.hostname, h1.ip) AS node1_name,
               h2.node_id AS node2_id,
               coalesce(h2.hostname, h2.ip) AS node2_name,
               jaccard AS similarity
        ORDER BY jaccard DESC
        LIMIT $limit
        """
        params: dict[str, Any] = {"host_id": host_id, "limit": limit}
        if project_id:
            params["project_id"] = project_id

        records = await self._client.execute_read(query, params)
        return [
            SimilarityResult(
                node1_id=r["node1_id"],
                node1_name=r["node1_name"],
                node2_id=r["node2_id"],
                node2_name=r["node2_name"],
                similarity=r["similarity"],
            )
            for r in records
        ]
