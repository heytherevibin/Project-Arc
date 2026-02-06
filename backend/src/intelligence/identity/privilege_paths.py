"""
Privilege Path Finder

Cross-platform privilege escalation discovery: local privesc,
token manipulation, delegation abuse, and certificate abuse.
Combines AD and local host privilege escalation techniques.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from core.logging import get_logger
from graph.client import Neo4jClient

logger = get_logger(__name__)


@dataclass
class PrivilegePath:
    """A privilege escalation path."""
    path_id: str
    source: dict[str, Any]
    target_privilege: str
    method: str
    prerequisites: list[str]
    risk_level: str = "high"
    tools: list[str] = field(default_factory=list)
    details: str = ""


class PrivilegePathFinder:
    """
    Discovers privilege escalation paths across platforms.

    Combines:
    - Local privilege escalation (misconfigs, kernel exploits)
    - Token manipulation (impersonation, token theft)
    - Delegation abuse (unconstrained, constrained, RBCD)
    - Certificate abuse (AD CS ESC1-ESC8)
    """

    def __init__(self, client: Neo4jClient) -> None:
        self._client = client

    # ------------------------------------------------------------------
    # Local Privilege Escalation
    # ------------------------------------------------------------------

    async def find_local_privesc(
        self,
        project_id: str | None = None,
        limit: int = 20,
    ) -> list[PrivilegePath]:
        """
        Find local privilege escalation opportunities:
        - Writable service paths
        - Unquoted service paths
        - Misconfigured scheduled tasks
        - SUID binaries (Linux)
        """
        project_filter = "AND h.project_id = $project_id" if project_id else ""
        query = f"""
        MATCH (h:Host)
        WHERE h.has_privesc_vector = true {project_filter}
        OPTIONAL MATCH (h)-[:HAS_SERVICE]->(s:Service)
        WHERE s.writable_path = true OR s.unquoted_path = true
        RETURN h.hostname AS hostname,
               h.os AS os,
               collect({{
                   service: s.name,
                   writable: s.writable_path,
                   unquoted: s.unquoted_path
               }}) AS services
        LIMIT $limit
        """
        params: dict[str, Any] = {"limit": limit}
        if project_id:
            params["project_id"] = project_id

        records = await self._client.execute_read(query, params)
        results: list[PrivilegePath] = []

        for i, r in enumerate(records):
            services = [s for s in r.get("services", []) if s.get("service")]
            methods: list[str] = []
            if any(s.get("writable") for s in services):
                methods.append("writable_service_path")
            if any(s.get("unquoted") for s in services):
                methods.append("unquoted_service_path")

            for method in methods:
                results.append(PrivilegePath(
                    path_id=f"privesc-local-{i}-{method}",
                    source={"hostname": r["hostname"], "os": r.get("os", "")},
                    target_privilege="SYSTEM/root",
                    method=method,
                    prerequisites=["local access"],
                    risk_level="high",
                    tools=["metasploit"],
                    details=f"{r['hostname']}: {method}",
                ))

        return results

    # ------------------------------------------------------------------
    # Token Manipulation
    # ------------------------------------------------------------------

    async def find_token_manipulation(
        self,
        project_id: str | None = None,
        limit: int = 20,
    ) -> list[PrivilegePath]:
        """
        Find token manipulation opportunities (SeImpersonate, etc.).
        """
        project_filter = "AND h.project_id = $project_id" if project_id else ""
        query = f"""
        MATCH (h:Host)-[:HAS_SESSION]->(session)
        WHERE session.has_impersonate_priv = true {project_filter}
        RETURN h.hostname AS hostname,
               session.username AS username,
               session.privileges AS privileges
        LIMIT $limit
        """
        params: dict[str, Any] = {"limit": limit}
        if project_id:
            params["project_id"] = project_id

        records = await self._client.execute_read(query, params)
        return [
            PrivilegePath(
                path_id=f"privesc-token-{i}",
                source={"hostname": r["hostname"], "user": r.get("username", "")},
                target_privilege="SYSTEM",
                method="token_impersonation",
                prerequisites=["SeImpersonatePrivilege"],
                risk_level="high",
                tools=["metasploit", "impacket"],
                details=f"{r.get('username', 'unknown')}@{r['hostname']} has impersonation privileges",
            )
            for i, r in enumerate(records)
        ]

    # ------------------------------------------------------------------
    # Delegation Abuse
    # ------------------------------------------------------------------

    async def find_delegation_abuse(
        self,
        project_id: str | None = None,
        limit: int = 20,
    ) -> list[PrivilegePath]:
        """
        Find Kerberos delegation abuse paths:
        - Unconstrained delegation
        - Constrained delegation
        - Resource-based constrained delegation (RBCD)
        """
        project_filter = "AND n.project_id = $project_id" if project_id else ""
        query = f"""
        MATCH (n)
        WHERE (n:ADComputer OR n:ADUser)
              AND (n.unconstrained_delegation = true
                   OR n.constrained_delegation = true
                   OR size(coalesce(n.allowed_to_delegate_to, [])) > 0)
              {project_filter}
        RETURN n.name AS name,
               labels(n) AS labels,
               n.unconstrained_delegation AS unconstrained,
               n.constrained_delegation AS constrained,
               n.allowed_to_delegate_to AS delegate_targets
        LIMIT $limit
        """
        params: dict[str, Any] = {"limit": limit}
        if project_id:
            params["project_id"] = project_id

        records = await self._client.execute_read(query, params)
        results: list[PrivilegePath] = []

        for i, r in enumerate(records):
            if r.get("unconstrained"):
                results.append(PrivilegePath(
                    path_id=f"privesc-deleg-unc-{i}",
                    source={"name": r["name"], "labels": r["labels"]},
                    target_privilege="Domain Admin (via TGT collection)",
                    method="unconstrained_delegation",
                    prerequisites=["compromise of delegating host/account"],
                    risk_level="critical",
                    tools=["impacket", "crackmapexec"],
                    details=f"{r['name']} has unconstrained delegation",
                ))
            if r.get("constrained") or r.get("delegate_targets"):
                targets = r.get("delegate_targets", [])
                results.append(PrivilegePath(
                    path_id=f"privesc-deleg-con-{i}",
                    source={"name": r["name"], "labels": r["labels"]},
                    target_privilege=f"Access to {','.join(targets[:3]) if targets else 'delegated services'}",
                    method="constrained_delegation",
                    prerequisites=["compromise of delegating account", "TGT for account"],
                    risk_level="high",
                    tools=["impacket"],
                    details=f"{r['name']} has constrained delegation to {targets}",
                ))

        return results

    # ------------------------------------------------------------------
    # Certificate Abuse
    # ------------------------------------------------------------------

    async def find_certificate_abuse(
        self,
        project_id: str | None = None,
        limit: int = 20,
    ) -> list[PrivilegePath]:
        """
        Find AD CS (Active Directory Certificate Services) abuse paths.
        Looks for vulnerable certificate templates (ESC1-ESC8).
        """
        project_filter = "AND t.project_id = $project_id" if project_id else ""
        query = f"""
        MATCH (t:CertificateTemplate)
        WHERE t.vulnerable = true {project_filter}
        OPTIONAL MATCH (t)-[:ISSUED_BY]->(ca:CertificateAuthority)
        RETURN t.name AS template_name,
               t.esc_type AS esc_type,
               t.enrollee_supplies_subject AS enrollee_subject,
               t.requires_manager_approval AS manager_approval,
               ca.name AS ca_name
        LIMIT $limit
        """
        params: dict[str, Any] = {"limit": limit}
        if project_id:
            params["project_id"] = project_id

        records = await self._client.execute_read(query, params)
        return [
            PrivilegePath(
                path_id=f"privesc-cert-{i}",
                source={"template": r["template_name"], "ca": r.get("ca_name", "")},
                target_privilege="Domain Admin (via certificate impersonation)",
                method=f"adcs_{r.get('esc_type', 'unknown')}",
                prerequisites=["enrollment rights on vulnerable template"],
                risk_level="critical",
                tools=["certipy"],
                details=f"Template '{r['template_name']}' vulnerable to {r.get('esc_type', 'unknown')} "
                        f"(enrollee supplies subject: {r.get('enrollee_subject', False)})",
            )
            for i, r in enumerate(records)
        ]
