"""
Centrality Analyser

Computes various centrality metrics on the attack graph to identify
critical nodes (high-value targets, choke points, pivot hosts).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from core.logging import get_logger
from graph.client import Neo4jClient

logger = get_logger(__name__)


@dataclass
class CentralityResult:
    """Centrality scores for a single node."""
    node_id: str
    label: str
    name: str
    betweenness: float = 0.0
    degree: float = 0.0
    pagerank: float = 0.0
    closeness: float = 0.0
    composite: float = 0.0
    properties: dict[str, Any] = field(default_factory=dict)


class CentralityAnalyser:
    """
    Runs centrality algorithms on the attack-surface GDS projection.

    Algorithms:
    - Betweenness: nodes on many shortest paths (choke points)
    - Degree: nodes with many connections (hubs)
    - PageRank: nodes connected to other important nodes
    - Closeness: nodes closest to all others (fast pivot)
    """

    DEFAULT_PROJECTION = "attack-surface"

    def __init__(self, neo4j_client: Neo4jClient, projection: str | None = None) -> None:
        self._client = neo4j_client
        self._projection = projection or self.DEFAULT_PROJECTION

    async def analyse(
        self,
        project_id: str,
        top_n: int = 25,
    ) -> list[CentralityResult]:
        """
        Run all centrality metrics and return a merged, ranked list
        of the most critical nodes.
        """
        betweenness = await self._betweenness(project_id, top_n * 2)
        degree = await self._degree(project_id, top_n * 2)
        pagerank = await self._pagerank(project_id, top_n * 2)
        closeness = await self._closeness(project_id, top_n * 2)

        # Merge into a single dict keyed by node_id
        merged: dict[str, CentralityResult] = {}
        for b in betweenness:
            nid = b["id"]
            merged[nid] = CentralityResult(
                node_id=nid,
                label=b.get("label", ""),
                name=b.get("name", ""),
                betweenness=b.get("score", 0.0),
            )

        for d in degree:
            nid = d["id"]
            if nid in merged:
                merged[nid].degree = d.get("score", 0.0)
            else:
                merged[nid] = CentralityResult(
                    node_id=nid, label=d.get("label", ""),
                    name=d.get("name", ""), degree=d.get("score", 0.0))

        for p in pagerank:
            nid = p["id"]
            if nid in merged:
                merged[nid].pagerank = p.get("score", 0.0)
            else:
                merged[nid] = CentralityResult(
                    node_id=nid, label=p.get("label", ""),
                    name=p.get("name", ""), pagerank=p.get("score", 0.0))

        for c in closeness:
            nid = c["id"]
            if nid in merged:
                merged[nid].closeness = c.get("score", 0.0)
            else:
                merged[nid] = CentralityResult(
                    node_id=nid, label=c.get("label", ""),
                    name=c.get("name", ""), closeness=c.get("score", 0.0))

        # Normalise and compute composite
        self._normalise_and_rank(merged)

        results = sorted(merged.values(), key=lambda r: r.composite, reverse=True)[:top_n]
        logger.info("Centrality analysis complete", project_id=project_id, nodes=len(results))
        return results

    # ---- individual algorithms -----------------------------------------------
    async def _betweenness(self, project_id: str, limit: int) -> list[dict[str, Any]]:
        return await self._run_gds_stream(
            "gds.betweenness.stream", project_id, limit)

    async def _degree(self, project_id: str, limit: int) -> list[dict[str, Any]]:
        return await self._run_gds_stream(
            "gds.degree.stream", project_id, limit)

    async def _pagerank(self, project_id: str, limit: int) -> list[dict[str, Any]]:
        return await self._run_gds_stream(
            "gds.pageRank.stream", project_id, limit)

    async def _closeness(self, project_id: str, limit: int) -> list[dict[str, Any]]:
        return await self._run_gds_stream(
            "gds.closeness.stream", project_id, limit)

    async def _run_gds_stream(
        self,
        algo: str,
        project_id: str,
        limit: int,
    ) -> list[dict[str, Any]]:
        """Execute a GDS stream algorithm and return results."""
        try:
            result = await self._client.execute_read(
                f"""
                CALL {algo}($graph)
                YIELD nodeId, score
                WITH gds.util.asNode(nodeId) AS node, score
                WHERE node.project_id = $pid AND score > 0
                RETURN
                    coalesce(node.id, node.name, node.address, node.object_id) AS id,
                    labels(node)[0] AS label,
                    coalesce(node.name, node.address, node.object_id) AS name,
                    score
                ORDER BY score DESC
                LIMIT $limit
                """,
                {"graph": self._projection, "pid": project_id, "limit": limit},
            )
            return [dict(r) for r in result]
        except Exception as e:
            logger.debug("GDS algorithm unavailable", algo=algo, error=str(e)[:200])
            return []

    # ---- normalisation -------------------------------------------------------
    @staticmethod
    def _normalise_and_rank(merged: dict[str, CentralityResult]) -> None:
        """Normalise all scores to [0, 1] and compute composite."""
        if not merged:
            return

        nodes = list(merged.values())

        def _max_of(attr: str) -> float:
            return max((getattr(n, attr) for n in nodes), default=1.0) or 1.0

        max_b = _max_of("betweenness")
        max_d = _max_of("degree")
        max_p = _max_of("pagerank")
        max_c = _max_of("closeness")

        for node in nodes:
            nb = node.betweenness / max_b
            nd = node.degree / max_d
            np_ = node.pagerank / max_p
            nc = node.closeness / max_c

            node.betweenness = round(nb, 4)
            node.degree = round(nd, 4)
            node.pagerank = round(np_, 4)
            node.closeness = round(nc, 4)

            # Weighted composite: betweenness most important for attack paths
            node.composite = round(
                0.35 * nb + 0.25 * np_ + 0.20 * nd + 0.20 * nc, 4
            )
