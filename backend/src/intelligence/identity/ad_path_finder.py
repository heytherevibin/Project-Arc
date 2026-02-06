"""
AD Attack Path Finder

Dedicated Active Directory attack path discovery using Neo4j GDS
on the identity graph projection.  Finds paths to Domain Admin,
GPO-based paths, ACL abuse paths, and shadow admin paths.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from core.logging import get_logger
from graph.client import Neo4jClient

logger = get_logger(__name__)


@dataclass
class ADPath:
    """An AD attack path."""
    path_id: str
    source: dict[str, Any]
    target: dict[str, Any]
    hops: list[dict[str, Any]]
    path_length: int
    attack_type: str
    risk_level: str = "high"
    details: str = ""


class ADPathFinder:
    """
    Discovers Active Directory attack paths using Neo4j graph queries.

    Path types:
    - Paths to Domain Admin
    - GPO-based paths (GPO → OU → targets)
    - ACL abuse paths (GenericAll, WriteDacl, WriteOwner, etc.)
    - Shadow admin paths (indirect admin access)
    """

    def __init__(self, client: Neo4jClient) -> None:
        self._client = client

    # ------------------------------------------------------------------
    # Paths to Domain Admin
    # ------------------------------------------------------------------

    async def find_paths_to_da(
        self,
        project_id: str | None = None,
        max_depth: int = 8,
        limit: int = 20,
    ) -> list[ADPath]:
        """Find shortest paths from any user to Domain Admins group."""
        project_filter = "AND u.project_id = $project_id" if project_id else ""
        query = f"""
        MATCH (da:ADGroup)
        WHERE da.name =~ '(?i)domain admins@.*'
        MATCH (u:ADUser)
        WHERE u.enabled = true {project_filter}
        MATCH path = shortestPath((u)-[*1..{max_depth}]->(da))
        RETURN u.username AS source,
               da.name AS target,
               [n IN nodes(path) | {{name: n.name, labels: labels(n)}}] AS hops,
               length(path) AS path_length
        ORDER BY path_length ASC
        LIMIT $limit
        """
        params: dict[str, Any] = {"limit": limit}
        if project_id:
            params["project_id"] = project_id

        records = await self._client.execute_read(query, params)
        return [
            ADPath(
                path_id=f"da-path-{i}",
                source={"username": r["source"]},
                target={"name": r["target"]},
                hops=r["hops"],
                path_length=r["path_length"],
                attack_type="domain_admin",
                risk_level="critical",
                details=f"Path from {r['source']} to Domain Admins ({r['path_length']} hops)",
            )
            for i, r in enumerate(records)
        ]

    # ------------------------------------------------------------------
    # GPO-based paths
    # ------------------------------------------------------------------

    async def find_paths_via_gpo(
        self,
        project_id: str | None = None,
        limit: int = 20,
    ) -> list[ADPath]:
        """Find attack paths through Group Policy Objects."""
        project_filter = "AND gpo.project_id = $project_id" if project_id else ""
        query = f"""
        MATCH (u:ADUser)-[:CanModifyGPO]->(gpo:GPO)-[:AppliesTo]->(ou:OU)-[:Contains]->(target)
        WHERE u.enabled = true {project_filter}
        RETURN u.username AS source,
               gpo.name AS gpo_name,
               ou.name AS ou_name,
               target.name AS target_name,
               labels(target) AS target_labels
        LIMIT $limit
        """
        params: dict[str, Any] = {"limit": limit}
        if project_id:
            params["project_id"] = project_id

        records = await self._client.execute_read(query, params)
        return [
            ADPath(
                path_id=f"gpo-path-{i}",
                source={"username": r["source"]},
                target={"name": r["target_name"], "labels": r["target_labels"]},
                hops=[
                    {"name": r["source"], "type": "ADUser"},
                    {"name": r["gpo_name"], "type": "GPO"},
                    {"name": r["ou_name"], "type": "OU"},
                    {"name": r["target_name"], "type": str(r["target_labels"])},
                ],
                path_length=3,
                attack_type="gpo_abuse",
                risk_level="high",
                details=f"{r['source']} → GPO:{r['gpo_name']} → OU:{r['ou_name']} → {r['target_name']}",
            )
            for i, r in enumerate(records)
        ]

    # ------------------------------------------------------------------
    # ACL abuse paths
    # ------------------------------------------------------------------

    async def find_paths_via_acl(
        self,
        project_id: str | None = None,
        max_depth: int = 5,
        limit: int = 20,
    ) -> list[ADPath]:
        """Find attack paths through ACL abuse (GenericAll, WriteDacl, etc.)."""
        acl_rels = "GenericAll|WriteDacl|WriteOwner|ForceChangePassword|AddMember|GenericWrite"
        project_filter = "AND u.project_id = $project_id" if project_id else ""
        query = f"""
        MATCH (u:ADUser)
        WHERE u.enabled = true {project_filter}
        MATCH path = (u)-[:{acl_rels}*1..{max_depth}]->(target)
        WHERE target <> u
        RETURN u.username AS source,
               target.name AS target_name,
               labels(target) AS target_labels,
               [r IN relationships(path) | type(r)] AS rel_types,
               length(path) AS path_length
        ORDER BY path_length ASC
        LIMIT $limit
        """
        params: dict[str, Any] = {"limit": limit}
        if project_id:
            params["project_id"] = project_id

        records = await self._client.execute_read(query, params)
        return [
            ADPath(
                path_id=f"acl-path-{i}",
                source={"username": r["source"]},
                target={"name": r["target_name"], "labels": r["target_labels"]},
                hops=[{"rel": rel} for rel in r["rel_types"]],
                path_length=r["path_length"],
                attack_type="acl_abuse",
                risk_level="high",
                details=f"{r['source']} → {'→'.join(r['rel_types'])} → {r['target_name']}",
            )
            for i, r in enumerate(records)
        ]

    # ------------------------------------------------------------------
    # Shadow admin paths
    # ------------------------------------------------------------------

    async def find_shadow_admin_paths(
        self,
        project_id: str | None = None,
        max_depth: int = 6,
        limit: int = 20,
    ) -> list[ADPath]:
        """
        Find shadow admin paths — users who are not direct members
        of admin groups but can reach admin privileges indirectly.
        """
        project_filter = "AND u.project_id = $project_id" if project_id else ""
        query = f"""
        MATCH (admin_group:ADGroup)
        WHERE admin_group.name =~ '(?i)(domain admins|enterprise admins|administrators)@.*'
        MATCH (u:ADUser)
        WHERE u.enabled = true
              AND NOT (u)-[:MemberOf*1..3]->(admin_group)
              {project_filter}
        MATCH path = shortestPath((u)-[*1..{max_depth}]->(admin_group))
        WHERE length(path) > 1
        RETURN u.username AS source,
               admin_group.name AS target_group,
               [n IN nodes(path) | {{name: n.name, labels: labels(n)}}] AS hops,
               length(path) AS path_length
        ORDER BY path_length ASC
        LIMIT $limit
        """
        params: dict[str, Any] = {"limit": limit}
        if project_id:
            params["project_id"] = project_id

        records = await self._client.execute_read(query, params)
        return [
            ADPath(
                path_id=f"shadow-path-{i}",
                source={"username": r["source"]},
                target={"name": r["target_group"]},
                hops=r["hops"],
                path_length=r["path_length"],
                attack_type="shadow_admin",
                risk_level="critical",
                details=f"Shadow admin: {r['source']} → {r['target_group']} ({r['path_length']} hops)",
            )
            for i, r in enumerate(records)
        ]
