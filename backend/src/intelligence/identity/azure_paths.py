"""
Azure AD Path Finder

Discovers attack paths specific to Azure Active Directory:
Global Admin paths, App Admin paths, and Service Principal abuse.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from core.logging import get_logger
from graph.client import Neo4jClient

logger = get_logger(__name__)


@dataclass
class AzurePath:
    """An Azure AD attack path."""
    path_id: str
    source: dict[str, Any]
    target: dict[str, Any]
    hops: list[dict[str, Any]]
    path_length: int
    attack_type: str
    risk_level: str = "high"
    details: str = ""


class AzurePathFinder:
    """
    Discovers Azure AD-specific privilege escalation and abuse paths.

    Queries :AzureUser, :AzureApp, :AzureRole, :AzureServicePrincipal
    nodes in the Neo4j identity graph.
    """

    def __init__(self, client: Neo4jClient) -> None:
        self._client = client

    # ------------------------------------------------------------------
    # Global Admin paths
    # ------------------------------------------------------------------

    async def find_global_admin_paths(
        self,
        project_id: str | None = None,
        max_depth: int = 6,
        limit: int = 20,
    ) -> list[AzurePath]:
        """Find paths from any Azure user to Global Administrator role."""
        project_filter = "AND u.project_id = $project_id" if project_id else ""
        query = f"""
        MATCH (ga:AzureRole)
        WHERE ga.display_name =~ '(?i)global administrator'
        MATCH (u:AzureUser)
        WHERE u.enabled = true {project_filter}
        MATCH path = shortestPath((u)-[*1..{max_depth}]->(ga))
        RETURN u.display_name AS source,
               u.user_principal_name AS upn,
               ga.display_name AS target_role,
               [n IN nodes(path) | {{name: coalesce(n.display_name, n.name, 'unknown'), labels: labels(n)}}] AS hops,
               length(path) AS path_length
        ORDER BY path_length ASC
        LIMIT $limit
        """
        params: dict[str, Any] = {"limit": limit}
        if project_id:
            params["project_id"] = project_id

        records = await self._client.execute_read(query, params)
        return [
            AzurePath(
                path_id=f"azure-ga-{i}",
                source={"name": r["source"], "upn": r.get("upn", "")},
                target={"role": r["target_role"]},
                hops=r["hops"],
                path_length=r["path_length"],
                attack_type="global_admin",
                risk_level="critical",
                details=f"{r['source']} → Global Administrator ({r['path_length']} hops)",
            )
            for i, r in enumerate(records)
        ]

    # ------------------------------------------------------------------
    # App Admin paths
    # ------------------------------------------------------------------

    async def find_app_admin_paths(
        self,
        project_id: str | None = None,
        max_depth: int = 5,
        limit: int = 20,
    ) -> list[AzurePath]:
        """Find paths through Azure Application administrator role."""
        project_filter = "AND u.project_id = $project_id" if project_id else ""
        query = f"""
        MATCH (role:AzureRole)
        WHERE role.display_name =~ '(?i)application administrator'
        MATCH (u:AzureUser)
        WHERE u.enabled = true {project_filter}
        MATCH path = shortestPath((u)-[*1..{max_depth}]->(role))
        RETURN u.display_name AS source,
               role.display_name AS target_role,
               [n IN nodes(path) | {{name: coalesce(n.display_name, n.name, 'unknown'), labels: labels(n)}}] AS hops,
               length(path) AS path_length
        ORDER BY path_length ASC
        LIMIT $limit
        """
        params: dict[str, Any] = {"limit": limit}
        if project_id:
            params["project_id"] = project_id

        records = await self._client.execute_read(query, params)
        return [
            AzurePath(
                path_id=f"azure-app-{i}",
                source={"name": r["source"]},
                target={"role": r["target_role"]},
                hops=r["hops"],
                path_length=r["path_length"],
                attack_type="app_admin",
                risk_level="high",
                details=f"{r['source']} → App Administrator ({r['path_length']} hops)",
            )
            for i, r in enumerate(records)
        ]

    # ------------------------------------------------------------------
    # Service Principal abuse
    # ------------------------------------------------------------------

    async def find_service_principal_abuse(
        self,
        project_id: str | None = None,
        limit: int = 20,
    ) -> list[AzurePath]:
        """
        Find service principals with dangerous permissions that could
        be abused for privilege escalation.
        """
        project_filter = "AND sp.project_id = $project_id" if project_id else ""
        query = f"""
        MATCH (sp:AzureServicePrincipal)
        WHERE sp.enabled = true {project_filter}
        MATCH (sp)-[r:HasPermission]->(target)
        WHERE r.permission IN [
            'Application.ReadWrite.All',
            'RoleManagement.ReadWrite.Directory',
            'AppRoleAssignment.ReadWrite.All',
            'Directory.ReadWrite.All'
        ]
        OPTIONAL MATCH (owner)-[:Owns]->(sp)
        RETURN sp.display_name AS sp_name,
               sp.app_id AS app_id,
               r.permission AS permission,
               target.display_name AS target_name,
               labels(target) AS target_labels,
               coalesce(owner.display_name, 'unknown') AS owner_name
        LIMIT $limit
        """
        params: dict[str, Any] = {"limit": limit}
        if project_id:
            params["project_id"] = project_id

        records = await self._client.execute_read(query, params)
        return [
            AzurePath(
                path_id=f"azure-sp-{i}",
                source={"name": r["sp_name"], "app_id": r.get("app_id", "")},
                target={"name": r["target_name"], "labels": r["target_labels"]},
                hops=[
                    {"name": r["sp_name"], "type": "ServicePrincipal"},
                    {"name": r["permission"], "type": "Permission"},
                    {"name": r["target_name"], "type": str(r["target_labels"])},
                ],
                path_length=2,
                attack_type="service_principal_abuse",
                risk_level="critical",
                details=f"SP:{r['sp_name']} has {r['permission']} on {r['target_name']} (owner: {r['owner_name']})",
            )
            for i, r in enumerate(records)
        ]
