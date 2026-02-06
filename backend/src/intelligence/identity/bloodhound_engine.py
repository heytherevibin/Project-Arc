"""
BloodHound-Style Identity Attack Path Engine

Analyzes Active Directory and Azure AD environments for privilege
escalation paths, kerberoastable accounts, ADCS abuse, delegation
attacks, and domain admin paths.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from core.logging import get_logger
from graph.client import Neo4jClient
from graph.projections.identity_graph import IdentityGraphProjection

logger = get_logger(__name__)


@dataclass
class IdentityPath:
    """An identity-based attack path (e.g., user → domain admin)."""
    path_id: str
    source: dict[str, Any]
    target: dict[str, Any]
    hops: list[dict[str, Any]]
    total_cost: float
    attack_type: str  # e.g., "domain_admin", "kerberoast", "adcs_esc1"


@dataclass
class PrivilegeEscalation:
    """A privilege escalation opportunity."""
    source_user: str
    target: str
    method: str
    risk_level: str
    details: str


@dataclass
class IdentityAnalysisResult:
    """Complete identity analysis results."""
    domain_admin_paths: list[IdentityPath]
    kerberoastable_users: list[dict[str, Any]]
    asrep_roastable_users: list[dict[str, Any]]
    unconstrained_delegation: list[dict[str, Any]]
    adcs_vulnerable_templates: list[dict[str, Any]]
    privilege_escalations: list[PrivilegeEscalation]
    high_value_targets: list[dict[str, Any]]
    stats: dict[str, int]


class BloodHoundEngine:
    """
    BloodHound-style analysis engine for AD/Azure identity attack paths.

    Uses Neo4j GDS identity graph projection for path discovery
    and standard Cypher for enumeration queries.
    """

    def __init__(self, neo4j_client: Neo4jClient) -> None:
        self._client = neo4j_client
        self._projection = IdentityGraphProjection(neo4j_client)

    async def full_analysis(self, project_id: str) -> IdentityAnalysisResult:
        """Run complete identity analysis for a project."""
        logger.info("Starting identity analysis", project_id=project_id)

        da_paths = await self.find_domain_admin_paths(project_id)
        kerb = await self.find_kerberoastable(project_id)
        asrep = await self.find_asrep_roastable(project_id)
        unconstrained = await self.find_unconstrained_delegation(project_id)
        adcs = await self.find_adcs_vulnerable(project_id)
        privesc = await self.find_privilege_escalations(project_id)
        hv = await self.find_high_value_targets(project_id)
        stats = await self.get_domain_stats(project_id)

        result = IdentityAnalysisResult(
            domain_admin_paths=da_paths,
            kerberoastable_users=kerb,
            asrep_roastable_users=asrep,
            unconstrained_delegation=unconstrained,
            adcs_vulnerable_templates=adcs,
            privilege_escalations=privesc,
            high_value_targets=hv,
            stats=stats,
        )

        logger.info(
            "Identity analysis complete",
            da_paths=len(da_paths),
            kerberoastable=len(kerb),
            adcs_vuln=len(adcs),
        )
        return result

    async def find_domain_admin_paths(
        self,
        project_id: str,
        limit: int = 20,
    ) -> list[IdentityPath]:
        """Find shortest paths from any user to Domain Admins."""
        result = await self._client.execute_read(
            """
            MATCH (da:ADGroup {project_id: $pid})
            WHERE da.name =~ '(?i).*domain admins.*' OR da.high_value = true
            WITH da LIMIT 1
            MATCH (u:ADUser {project_id: $pid, enabled: true})
            WHERE NOT (u)-[:MEMBER_OF*1..]->(da)
            WITH u, da
            MATCH path = shortestPath((u)-[*1..8]->(da))
            WHERE ALL(r IN relationships(path) WHERE type(r) IN [
                'MEMBER_OF','ADMIN_TO','GENERIC_ALL','GENERIC_WRITE',
                'WRITE_DACL','WRITE_OWNER','FORCE_CHANGE_PASSWORD',
                'OWNS','ADD_MEMBER','HAS_SPN_TO','ALLOWED_TO_DELEGATE'
            ])
            RETURN u.sam_account_name AS source_name,
                   da.name AS target_name,
                   length(path) AS hops,
                   [n IN nodes(path) | {
                       name: coalesce(n.sam_account_name, n.name, ''),
                       labels: labels(n)
                   }] AS path_nodes,
                   [r IN relationships(path) | type(r)] AS rel_types
            ORDER BY hops ASC
            LIMIT $limit
            """,
            {"pid": project_id, "limit": limit},
        )

        paths: list[IdentityPath] = []
        for i, row in enumerate(result):
            paths.append(IdentityPath(
                path_id=f"da-path-{i}",
                source={"name": row["source_name"], "type": "ADUser"},
                target={"name": row["target_name"], "type": "ADGroup"},
                hops=row.get("path_nodes", []),
                total_cost=float(row.get("hops", 0)),
                attack_type="domain_admin",
            ))

        return paths

    async def find_kerberoastable(self, project_id: str) -> list[dict[str, Any]]:
        """Find kerberoastable accounts (users with SPNs)."""
        return await self._client.execute_read(
            """
            MATCH (u:ADUser {project_id: $pid, enabled: true, has_spn: true})
            OPTIONAL MATCH (u)-[:MEMBER_OF*1..3]->(g:ADGroup)
            WITH u, collect(DISTINCT g.name) AS groups
            RETURN u.sam_account_name AS username,
                   u.display_name AS display_name,
                   u.admin_count AS admin_count,
                   groups,
                   u.description AS description
            ORDER BY u.admin_count DESC
            """,
            {"pid": project_id},
        )

    async def find_asrep_roastable(self, project_id: str) -> list[dict[str, Any]]:
        """Find AS-REP roastable accounts (no pre-auth required)."""
        return await self._client.execute_read(
            """
            MATCH (u:ADUser {project_id: $pid, enabled: true})
            WHERE u.dont_require_preauth = true
            RETURN u.sam_account_name AS username,
                   u.display_name AS display_name,
                   u.admin_count AS admin_count
            """,
            {"pid": project_id},
        )

    async def find_unconstrained_delegation(self, project_id: str) -> list[dict[str, Any]]:
        """Find computers with unconstrained delegation."""
        return await self._client.execute_read(
            """
            MATCH (c:ADComputer {project_id: $pid, unconstrained_delegation: true})
            WHERE NOT c.is_dc = true
            RETURN c.name AS computer,
                   c.operating_system AS os,
                   c.description AS description
            """,
            {"pid": project_id},
        )

    async def find_adcs_vulnerable(self, project_id: str) -> list[dict[str, Any]]:
        """Find ADCS certificate templates vulnerable to abuse (ESC1-ESC9)."""
        return await self._client.execute_read(
            """
            MATCH (t:ADCertTemplate {project_id: $pid})
            OPTIONAL MATCH (u:ADUser)-[:CAN_ENROLL]->(t)
            OPTIONAL MATCH (g:ADGroup)-[:CAN_ENROLL]->(t)
            WITH t,
                 collect(DISTINCT u.sam_account_name) AS enrollable_users,
                 collect(DISTINCT g.name) AS enrollable_groups
            WHERE size(enrollable_users) > 0 OR size(enrollable_groups) > 0
            RETURN t.template_name AS template,
                   enrollable_users,
                   enrollable_groups,
                   t.vuln_type AS vulnerability_type
            """,
            {"pid": project_id},
        )

    async def find_privilege_escalations(
        self,
        project_id: str,
    ) -> list[PrivilegeEscalation]:
        """Find direct privilege escalation opportunities."""
        escalations: list[PrivilegeEscalation] = []

        # GenericAll on users → password reset
        result = await self._client.execute_read(
            """
            MATCH (a)-[:GENERIC_ALL]->(b:ADUser {project_id: $pid})
            WHERE a.project_id = $pid AND a <> b
            RETURN coalesce(a.sam_account_name, a.name) AS source,
                   b.sam_account_name AS target,
                   labels(a)[0] AS source_type
            LIMIT 50
            """,
            {"pid": project_id},
        )
        for row in result:
            escalations.append(PrivilegeEscalation(
                source_user=row["source"],
                target=row["target"],
                method="GenericAll → Force Password Change",
                risk_level="critical",
                details=f"{row['source']} has GenericAll on {row['target']}",
            ))

        # WriteDACL → grant themselves GenericAll
        result2 = await self._client.execute_read(
            """
            MATCH (a)-[:WRITE_DACL]->(b {project_id: $pid})
            WHERE a.project_id = $pid AND a <> b
            RETURN coalesce(a.sam_account_name, a.name) AS source,
                   coalesce(b.sam_account_name, b.name) AS target,
                   labels(b)[0] AS target_type
            LIMIT 50
            """,
            {"pid": project_id},
        )
        for row in result2:
            escalations.append(PrivilegeEscalation(
                source_user=row["source"],
                target=row["target"],
                method="WriteDACL → Modify Permissions",
                risk_level="critical",
                details=f"{row['source']} can modify DACL on {row['target']}",
            ))

        return escalations

    async def find_high_value_targets(self, project_id: str) -> list[dict[str, Any]]:
        """Find high-value targets in the AD environment."""
        return await self._client.execute_read(
            """
            MATCH (n {project_id: $pid})
            WHERE n.high_value = true OR n.admin_count > 0 OR n.is_dc = true
            RETURN coalesce(n.sam_account_name, n.name) AS name,
                   labels(n) AS labels,
                   n.description AS description,
                   n.is_dc AS is_dc,
                   n.admin_count AS admin_count
            ORDER BY n.admin_count DESC
            LIMIT 50
            """,
            {"pid": project_id},
        )

    async def get_domain_stats(self, project_id: str) -> dict[str, int]:
        """Get AD domain statistics."""
        result = await self._client.execute_read(
            """
            MATCH (n {project_id: $pid})
            WITH labels(n)[0] AS label, count(n) AS cnt
            WHERE label IN ['ADUser','ADGroup','ADComputer','ADGPO','ADOU','ADDomain']
            RETURN label, cnt
            """,
            {"pid": project_id},
        )
        return {row["label"]: row["cnt"] for row in result}
