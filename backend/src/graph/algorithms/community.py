"""
Community Detection

Uses Neo4j GDS community detection algorithms to identify network
segments, trust boundaries, and logical groupings in the attack graph.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from core.logging import get_logger
from graph.client import Neo4jClient

logger = get_logger(__name__)


@dataclass
class CommunityMember:
    """A node that belongs to a detected community."""
    node_id: str
    label: str
    name: str
    properties: dict[str, Any] = field(default_factory=dict)


@dataclass
class CommunityResult:
    """A detected community / segment."""
    community_id: int
    size: int
    members: list[CommunityMember] = field(default_factory=list)
    labels: dict[str, int] = field(default_factory=dict)   # label → count
    description: str = ""
    is_internet_facing: bool = False
    has_high_value_target: bool = False


class CommunityDetector:
    """
    Detects logical communities in the attack graph for:
    - Network segmentation analysis
    - Trust boundary identification
    - Lateral movement scope estimation
    - Blast-radius calculation

    Algorithms:
    - Louvain (default): modularity-based, fast
    - Label Propagation: simpler, faster for large graphs
    - Weakly Connected Components: basic connectivity
    """

    DEFAULT_PROJECTION = "attack-surface"

    def __init__(self, neo4j_client: Neo4jClient, projection: str | None = None) -> None:
        self._client = neo4j_client
        self._projection = projection or self.DEFAULT_PROJECTION

    async def detect_louvain(
        self,
        project_id: str,
        min_community_size: int = 2,
        limit: int = 50,
    ) -> list[CommunityResult]:
        """Detect communities using Louvain modularity optimisation."""
        return await self._detect(
            "gds.louvain.stream", project_id, min_community_size, limit
        )

    async def detect_label_propagation(
        self,
        project_id: str,
        min_community_size: int = 2,
        limit: int = 50,
    ) -> list[CommunityResult]:
        """Detect communities using Label Propagation."""
        return await self._detect(
            "gds.labelPropagation.stream", project_id, min_community_size, limit
        )

    async def detect_components(
        self,
        project_id: str,
    ) -> list[CommunityResult]:
        """Detect weakly connected components (basic connectivity groups)."""
        return await self._detect(
            "gds.wcc.stream", project_id, min_community_size=1, limit=100
        )

    async def segmentation_report(
        self,
        project_id: str,
    ) -> dict[str, Any]:
        """
        Generate a network segmentation report showing:
        - Number of segments
        - Cross-segment connections (potential lateral movement paths)
        - Internet-facing segments
        - Segments containing high-value targets
        """
        communities = await self.detect_louvain(project_id)

        internet_facing = [c for c in communities if c.is_internet_facing]
        high_value = [c for c in communities if c.has_high_value_target]

        # Count cross-segment edges
        cross_edges = await self._count_cross_edges(project_id, communities)

        report = {
            "total_segments": len(communities),
            "internet_facing_segments": len(internet_facing),
            "high_value_segments": len(high_value),
            "cross_segment_connections": cross_edges,
            "largest_segment_size": max((c.size for c in communities), default=0),
            "average_segment_size": (
                round(sum(c.size for c in communities) / max(len(communities), 1), 1)
            ),
            "segments": [
                {
                    "id": c.community_id,
                    "size": c.size,
                    "labels": c.labels,
                    "internet_facing": c.is_internet_facing,
                    "has_hvt": c.has_high_value_target,
                    "description": c.description,
                }
                for c in communities
            ],
        }

        logger.info(
            "Segmentation report generated",
            project_id=project_id,
            segments=len(communities),
            cross_edges=cross_edges,
        )
        return report

    # ------------- internal ---------------------------------------------------
    async def _detect(
        self,
        algo: str,
        project_id: str,
        min_community_size: int,
        limit: int,
    ) -> list[CommunityResult]:
        """Run a GDS community algorithm and group results."""
        try:
            result = await self._client.execute_read(
                f"""
                CALL {algo}($graph)
                YIELD nodeId, communityId
                WITH gds.util.asNode(nodeId) AS node, communityId
                WHERE node.project_id = $pid
                RETURN
                    communityId,
                    coalesce(node.id, node.name, node.address, node.object_id) AS id,
                    labels(node)[0] AS label,
                    coalesce(node.name, node.address, node.object_id) AS name,
                    node.is_internet_facing AS internet_facing,
                    node.criticality AS criticality,
                    node.is_dc AS is_dc,
                    node.role AS role
                ORDER BY communityId
                """,
                {"graph": self._projection, "pid": project_id},
            )
        except Exception as e:
            logger.warning("GDS community detection failed", algo=algo, error=str(e)[:200])
            return await self._fallback_components(project_id, min_community_size, limit)

        # Group by community
        communities_map: dict[int, list[dict[str, Any]]] = {}
        for row in result:
            cid = row["communityId"]
            communities_map.setdefault(cid, []).append(dict(row))

        communities: list[CommunityResult] = []
        for cid, members in communities_map.items():
            if len(members) < min_community_size:
                continue

            label_counts: dict[str, int] = {}
            community_members: list[CommunityMember] = []
            is_internet = False
            has_hvt = False

            for m in members:
                lbl = m.get("label", "Unknown")
                label_counts[lbl] = label_counts.get(lbl, 0) + 1
                community_members.append(CommunityMember(
                    node_id=str(m["id"]),
                    label=lbl,
                    name=m.get("name", ""),
                ))
                if m.get("internet_facing"):
                    is_internet = True
                if (m.get("criticality") == "high" or m.get("is_dc")
                        or m.get("role") in ("dc", "database", "ca")):
                    has_hvt = True

            desc = f"Segment {cid}: {len(members)} nodes"
            if is_internet:
                desc += " [internet-facing]"
            if has_hvt:
                desc += " [contains HVT]"

            communities.append(CommunityResult(
                community_id=cid,
                size=len(members),
                members=community_members[:100],  # Cap for large communities
                labels=label_counts,
                description=desc,
                is_internet_facing=is_internet,
                has_high_value_target=has_hvt,
            ))

        communities.sort(key=lambda c: c.size, reverse=True)
        return communities[:limit]

    async def _fallback_components(
        self,
        project_id: str,
        min_size: int,
        limit: int,
    ) -> list[CommunityResult]:
        """Fallback when GDS is unavailable: use native WCC-like approach."""
        result = await self._client.execute_read(
            """
            MATCH (n {project_id: $pid})
            OPTIONAL MATCH (n)-[r]-(m {project_id: $pid})
            WITH n, collect(DISTINCT m) AS neighbours
            RETURN
                coalesce(n.id, n.name, n.address) AS id,
                labels(n)[0] AS label,
                coalesce(n.name, n.address) AS name,
                size(neighbours) AS degree
            ORDER BY degree DESC
            LIMIT 200
            """,
            {"pid": project_id},
        )

        if not result:
            return []

        # Simple grouping: treat as a single community
        members = [CommunityMember(
            node_id=str(r["id"]), label=r.get("label", ""), name=r.get("name", "")
        ) for r in result]

        label_counts: dict[str, int] = {}
        for m in members:
            label_counts[m.label] = label_counts.get(m.label, 0) + 1

        return [CommunityResult(
            community_id=0,
            size=len(members),
            members=members[:100],
            labels=label_counts,
            description=f"Connected component: {len(members)} nodes",
        )]

    async def _count_cross_edges(
        self,
        project_id: str,
        communities: list[CommunityResult],
    ) -> int:
        """Count edges between different communities (potential lateral movement)."""
        if len(communities) < 2:
            return 0

        # Build node → community mapping
        node_to_community: dict[str, int] = {}
        for c in communities:
            for m in c.members:
                node_to_community[m.node_id] = c.community_id

        try:
            result = await self._client.execute_read(
                """
                MATCH (a {project_id: $pid})-[r]->(b {project_id: $pid})
                RETURN
                    coalesce(a.id, a.name, a.address) AS src,
                    coalesce(b.id, b.name, b.address) AS tgt
                LIMIT 5000
                """,
                {"pid": project_id},
            )
            cross = 0
            for r in result:
                src_c = node_to_community.get(str(r["src"]))
                tgt_c = node_to_community.get(str(r["tgt"]))
                if src_c is not None and tgt_c is not None and src_c != tgt_c:
                    cross += 1
            return cross
        except Exception:
            return 0
