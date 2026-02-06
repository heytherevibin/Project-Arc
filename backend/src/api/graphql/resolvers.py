"""
Arc GraphQL Resolvers

Resolve GraphQL queries against Neo4j and the mission manager.
Each resolver fetches data from the graph database or in-memory stores
and maps them to Strawberry types.
"""

from __future__ import annotations

from typing import Any, Optional

from core.logging import get_logger

logger = get_logger(__name__)


# ---- Neo4j helper -----------------------------------------------------------

async def _neo4j_read(query: str, params: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    """Execute a read query against Neo4j, returning empty list on failure."""
    try:
        from graph.client import get_neo4j_client
        client = get_neo4j_client()
        return await client.execute_read(query, params or {})
    except Exception as e:
        logger.warning("GraphQL Neo4j query failed", error=str(e)[:200])
        return []


# ---- Project resolvers -------------------------------------------------------

async def resolve_projects(limit: int = 50) -> list:
    from api.graphql.schema import ProjectType
    rows = await _neo4j_read(
        "MATCH (p:Project) RETURN p ORDER BY p.created_at DESC LIMIT $limit",
        {"limit": limit},
    )
    return [
        ProjectType(
            project_id=r["p"].get("project_id", ""),
            name=r["p"].get("name", ""),
            target=r["p"].get("target"),
            status=r["p"].get("status"),
            created_at=r["p"].get("created_at"),
        )
        for r in rows
    ]


async def resolve_project(project_id: str) -> Optional[Any]:
    from api.graphql.schema import ProjectType
    rows = await _neo4j_read(
        "MATCH (p:Project {project_id: $pid}) RETURN p",
        {"pid": project_id},
    )
    if not rows:
        return None
    p = rows[0]["p"]
    return ProjectType(
        project_id=p.get("project_id", ""),
        name=p.get("name", ""),
        target=p.get("target"),
        status=p.get("status"),
        created_at=p.get("created_at"),
    )


# ---- Vulnerability resolvers ------------------------------------------------

async def resolve_vulnerabilities(
    project_id: str,
    severity: str | None = None,
    limit: int = 100,
) -> list:
    from api.graphql.schema import VulnerabilityType
    where = "v.project_id = $pid"
    params: dict[str, Any] = {"pid": project_id, "limit": limit}
    if severity:
        where += " AND v.severity = $sev"
        params["sev"] = severity.lower()

    rows = await _neo4j_read(
        f"""
        MATCH (v:Vulnerability)
        WHERE {where}
        OPTIONAL MATCH (v)-[:ASSOCIATED_CVE]->(c:CVE)
        RETURN v.vulnerability_id AS id, v.name AS name,
               v.severity AS severity, v.template_id AS template_id,
               v.description AS description, v.matched_at AS matched_at,
               c.cve_id AS cve_id, c.cvss_score AS cvss_score,
               v.project_id AS project_id
        ORDER BY CASE v.severity
            WHEN 'critical' THEN 0 WHEN 'high' THEN 1
            WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4
        END
        LIMIT $limit
        """,
        params,
    )
    results = []
    for r in rows:
        cvss = r.get("cvss_score")
        if isinstance(cvss, str):
            try:
                cvss = float(cvss)
            except ValueError:
                cvss = None
        results.append(VulnerabilityType(
            id=r.get("id", ""),
            name=r.get("name", ""),
            severity=r.get("severity", "info"),
            template_id=r.get("template_id"),
            description=r.get("description"),
            cve_id=r.get("cve_id"),
            cvss_score=cvss,
            matched_at=r.get("matched_at"),
            project_id=r.get("project_id", project_id),
        ))
    return results


async def resolve_vulnerability(vuln_id: str) -> Optional[Any]:
    from api.graphql.schema import VulnerabilityType
    rows = await _neo4j_read(
        """
        MATCH (v:Vulnerability {vulnerability_id: $vid})
        OPTIONAL MATCH (v)-[:ASSOCIATED_CVE]->(c:CVE)
        RETURN v, c.cve_id AS cve_id, c.cvss_score AS cvss_score
        """,
        {"vid": vuln_id},
    )
    if not rows:
        return None
    r = rows[0]
    v = r["v"]
    cvss = r.get("cvss_score")
    if isinstance(cvss, str):
        try:
            cvss = float(cvss)
        except ValueError:
            cvss = None
    return VulnerabilityType(
        id=v.get("vulnerability_id", ""),
        name=v.get("name", ""),
        severity=v.get("severity", "info"),
        template_id=v.get("template_id"),
        description=v.get("description"),
        cve_id=r.get("cve_id"),
        cvss_score=cvss,
        matched_at=v.get("matched_at"),
        project_id=v.get("project_id", ""),
    )


# ---- Host resolvers ----------------------------------------------------------

async def resolve_hosts(project_id: str, limit: int = 200) -> list:
    from api.graphql.schema import HostType
    rows = await _neo4j_read(
        """
        MATCH (s:Subdomain {project_id: $pid})
        OPTIONAL MATCH (s)-[:RESOLVES_TO]->(i:IP)
        OPTIONAL MATCH (i)-[:HAS_PORT]->(p:Port)
        RETURN s.name AS hostname,
               collect(DISTINCT i.address) AS ips,
               collect(DISTINCT p.number) AS ports
        LIMIT $limit
        """,
        {"pid": project_id, "limit": limit},
    )
    return [
        HostType(
            hostname=r.get("hostname", ""),
            ips=r.get("ips", []),
            ports=[p for p in r.get("ports", []) if p is not None],
        )
        for r in rows
    ]


async def resolve_host(project_id: str, hostname: str) -> Optional[Any]:
    from api.graphql.schema import HostType
    rows = await _neo4j_read(
        """
        MATCH (s:Subdomain {project_id: $pid, name: $name})
        OPTIONAL MATCH (s)-[:RESOLVES_TO]->(i:IP)
        OPTIONAL MATCH (i)-[:HAS_PORT]->(p:Port)
        RETURN s.name AS hostname,
               collect(DISTINCT i.address) AS ips,
               collect(DISTINCT p.number) AS ports
        """,
        {"pid": project_id, "name": hostname},
    )
    if not rows:
        return None
    r = rows[0]
    return HostType(
        hostname=r.get("hostname", ""),
        ips=r.get("ips", []),
        ports=[p for p in r.get("ports", []) if p is not None],
    )


# ---- Technology resolvers ----------------------------------------------------

async def resolve_technologies(project_id: str) -> list:
    from api.graphql.schema import TechnologyType
    rows = await _neo4j_read(
        """
        MATCH (t:Technology {project_id: $pid})
        OPTIONAL MATCH (u:URL)-[:USES_TECHNOLOGY]->(t)
        RETURN t.name AS name, t.version AS version,
               t.category AS category,
               collect(DISTINCT u.url) AS urls
        LIMIT 200
        """,
        {"pid": project_id},
    )
    return [
        TechnologyType(
            name=r.get("name", ""),
            version=r.get("version"),
            category=r.get("category"),
            urls=[u for u in r.get("urls", []) if u],
        )
        for r in rows
    ]


# ---- Attack path resolvers --------------------------------------------------

async def resolve_attack_paths(project_id: str, limit: int = 50) -> list:
    from api.graphql.schema import AttackPathType
    rows = await _neo4j_read(
        """
        MATCH (ap:AttackPath {project_id: $pid})
        RETURN ap.path_id AS path_id, ap.source AS source,
               ap.target AS target, ap.hops AS hops,
               ap.risk_score AS risk_score,
               ap.techniques AS techniques
        ORDER BY ap.risk_score DESC
        LIMIT $limit
        """,
        {"pid": project_id, "limit": limit},
    )
    return [
        AttackPathType(
            path_id=r.get("path_id", ""),
            source=r.get("source", ""),
            target=r.get("target", ""),
            hops=r.get("hops", 0),
            risk_score=r.get("risk_score"),
            techniques=r.get("techniques", []) or [],
        )
        for r in rows
    ]


# ---- Mission resolvers -------------------------------------------------------

async def resolve_missions(limit: int = 50) -> list:
    from api.graphql.schema import MissionType
    try:
        from agents.shared.agent_protocol import get_mission_manager
        manager = get_mission_manager()
        missions = manager.list_missions()[:limit]
        return [
            MissionType(
                mission_id=m.mission_id,
                objective=m.objective,
                target=m.target,
                status=m.status.value,
                phase=m.current_phase,
                created_at=m.created_at,
                discovered_hosts=list(m.discovered_hosts),
                discovered_vulns=list(m.discovered_vulns),
            )
            for m in missions
        ]
    except Exception as e:
        logger.warning("Failed to resolve missions", error=str(e)[:200])
        return []


async def resolve_mission(mission_id: str) -> Optional[Any]:
    from api.graphql.schema import MissionType
    try:
        from agents.shared.agent_protocol import get_mission_manager
        manager = get_mission_manager()
        m = manager.get_mission(mission_id)
        if not m:
            return None
        return MissionType(
            mission_id=m.mission_id,
            objective=m.objective,
            target=m.target,
            status=m.status.value,
            phase=m.current_phase,
            created_at=m.created_at,
            discovered_hosts=list(m.discovered_hosts),
            discovered_vulns=list(m.discovered_vulns),
        )
    except Exception as e:
        logger.warning("Failed to resolve mission", error=str(e)[:200])
        return None


# ---- Agent resolvers ---------------------------------------------------------

async def resolve_agents() -> list:
    from api.graphql.schema import AgentType
    # Return statically-known agents from the specialist registry
    agents_list = [
        AgentType(
            agent_id="supervisor",
            name="Supervisor",
            role="orchestrator",
            status="active",
            supported_phases=["all"],
            tools=[],
        ),
        AgentType(
            agent_id="recon",
            name="Recon Specialist",
            role="specialist",
            supported_phases=["RECONNAISSANCE"],
            tools=["naabu", "httpx", "subfinder", "dnsx", "katana", "nuclei"],
        ),
        AgentType(
            agent_id="vuln_analyst",
            name="Vulnerability Analyst",
            role="specialist",
            supported_phases=["VULNERABILITY_ANALYSIS"],
            tools=["nuclei", "gvm", "nikto"],
        ),
        AgentType(
            agent_id="exploit",
            name="Exploit Specialist",
            role="specialist",
            supported_phases=["EXPLOITATION"],
            tools=["metasploit", "sqlmap", "commix"],
        ),
        AgentType(
            agent_id="post_exploit",
            name="Post-Exploitation Specialist",
            role="specialist",
            supported_phases=["POST_EXPLOITATION"],
            tools=["impacket", "bloodhound", "crackmapexec"],
        ),
        AgentType(
            agent_id="pivot",
            name="Lateral Movement Specialist",
            role="specialist",
            supported_phases=["LATERAL_MOVEMENT"],
            tools=["crackmapexec", "impacket", "proxychains"],
        ),
        AgentType(
            agent_id="persistence",
            name="Persistence Specialist",
            role="specialist",
            supported_phases=["PERSISTENCE"],
            tools=["sliver", "havoc"],
        ),
        AgentType(
            agent_id="exfil",
            name="Exfiltration Specialist",
            role="specialist",
            supported_phases=["EXFILTRATION"],
            tools=["curl", "impacket"],
        ),
    ]
    return agents_list


async def resolve_agent(agent_id: str) -> Optional[Any]:
    agents = await resolve_agents()
    for a in agents:
        if a.agent_id == agent_id:
            return a
    return None


# ---- Stats resolver ----------------------------------------------------------

async def resolve_stats(project_id: str | None = None) -> Any:
    from api.graphql.schema import StatsType

    if project_id:
        # Per-project stats
        rows = await _neo4j_read(
            """
            MATCH (v:Vulnerability {project_id: $pid})
            RETURN v.severity AS severity, count(*) AS cnt
            """,
            {"pid": project_id},
        )
        counts = {r["severity"]: r["cnt"] for r in rows if r["severity"]}

        host_rows = await _neo4j_read(
            "MATCH (s:Subdomain {project_id: $pid}) RETURN count(s) AS cnt",
            {"pid": project_id},
        )
        total_hosts = host_rows[0]["cnt"] if host_rows else 0

        return StatsType(
            total_projects=1,
            total_hosts=total_hosts,
            total_vulnerabilities=sum(counts.values()),
            total_critical=counts.get("critical", 0),
            total_high=counts.get("high", 0),
            total_medium=counts.get("medium", 0),
            total_low=counts.get("low", 0),
        )

    # Global stats
    proj_rows = await _neo4j_read("MATCH (p:Project) RETURN count(p) AS cnt")
    host_rows = await _neo4j_read("MATCH (s:Subdomain) RETURN count(s) AS cnt")
    vuln_rows = await _neo4j_read(
        "MATCH (v:Vulnerability) RETURN v.severity AS severity, count(*) AS cnt"
    )
    counts = {r["severity"]: r["cnt"] for r in vuln_rows if r["severity"]}

    return StatsType(
        total_projects=proj_rows[0]["cnt"] if proj_rows else 0,
        total_hosts=host_rows[0]["cnt"] if host_rows else 0,
        total_vulnerabilities=sum(counts.values()),
        total_critical=counts.get("critical", 0),
        total_high=counts.get("high", 0),
        total_medium=counts.get("medium", 0),
        total_low=counts.get("low", 0),
    )
