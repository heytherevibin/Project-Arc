"""
Arc GraphQL Schema

Defines the GraphQL schema using Strawberry, providing typed queries
for projects, vulnerabilities, hosts, attack paths, missions, and agents.
"""

from __future__ import annotations

from typing import Optional

import strawberry
from strawberry.fastapi import GraphQLRouter

from api.graphql.resolvers import (
    resolve_agent,
    resolve_agents,
    resolve_attack_paths,
    resolve_host,
    resolve_hosts,
    resolve_mission,
    resolve_missions,
    resolve_project,
    resolve_projects,
    resolve_stats,
    resolve_technologies,
    resolve_vulnerabilities,
    resolve_vulnerability,
)


# ---- Types ------------------------------------------------------------------

@strawberry.type
class VulnerabilityType:
    id: str
    name: str
    severity: str
    template_id: Optional[str] = None
    description: Optional[str] = None
    cve_id: Optional[str] = None
    cvss_score: Optional[float] = None
    matched_at: Optional[str] = None
    project_id: str = ""


@strawberry.type
class HostType:
    hostname: str
    ips: list[str]
    ports: list[int]


@strawberry.type
class TechnologyType:
    name: str
    version: Optional[str] = None
    category: Optional[str] = None
    urls: list[str] = strawberry.field(default_factory=list)


@strawberry.type
class AttackPathType:
    path_id: str
    source: str
    target: str
    hops: int
    risk_score: Optional[float] = None
    techniques: list[str] = strawberry.field(default_factory=list)


@strawberry.type
class ProjectType:
    project_id: str
    name: str
    target: Optional[str] = None
    status: Optional[str] = None
    created_at: Optional[str] = None


@strawberry.type
class MissionStatusStats:
    total: int = 0
    planning: int = 0
    running: int = 0
    paused: int = 0
    completed: int = 0
    failed: int = 0


@strawberry.type
class MissionType:
    mission_id: str
    objective: str
    target: str
    status: str
    phase: Optional[str] = None
    created_at: Optional[str] = None
    discovered_hosts: list[str] = strawberry.field(default_factory=list)
    discovered_vulns: list[str] = strawberry.field(default_factory=list)


@strawberry.type
class AgentType:
    agent_id: str
    name: str
    role: str
    status: str = "idle"
    supported_phases: list[str] = strawberry.field(default_factory=list)
    tools: list[str] = strawberry.field(default_factory=list)


@strawberry.type
class StatsType:
    total_projects: int = 0
    total_hosts: int = 0
    total_vulnerabilities: int = 0
    total_critical: int = 0
    total_high: int = 0
    total_medium: int = 0
    total_low: int = 0


# ---- Query ------------------------------------------------------------------

@strawberry.type
class Query:
    @strawberry.field(description="Get all projects")
    async def projects(self, limit: int = 50) -> list[ProjectType]:
        return await resolve_projects(limit)

    @strawberry.field(description="Get a single project by ID")
    async def project(self, project_id: str) -> Optional[ProjectType]:
        return await resolve_project(project_id)

    @strawberry.field(description="Get vulnerabilities for a project")
    async def vulnerabilities(
        self,
        project_id: str,
        severity: Optional[str] = None,
        limit: int = 100,
    ) -> list[VulnerabilityType]:
        return await resolve_vulnerabilities(project_id, severity, limit)

    @strawberry.field(description="Get a single vulnerability by ID")
    async def vulnerability(self, vuln_id: str) -> Optional[VulnerabilityType]:
        return await resolve_vulnerability(vuln_id)

    @strawberry.field(description="Get hosts for a project")
    async def hosts(self, project_id: str, limit: int = 200) -> list[HostType]:
        return await resolve_hosts(project_id, limit)

    @strawberry.field(description="Get a single host by hostname")
    async def host(self, project_id: str, hostname: str) -> Optional[HostType]:
        return await resolve_host(project_id, hostname)

    @strawberry.field(description="Get technologies for a project")
    async def technologies(self, project_id: str) -> list[TechnologyType]:
        return await resolve_technologies(project_id)

    @strawberry.field(description="Get attack paths for a project")
    async def attack_paths(
        self,
        project_id: str,
        limit: int = 50,
    ) -> list[AttackPathType]:
        return await resolve_attack_paths(project_id, limit)

    @strawberry.field(description="Get missions")
    async def missions(self, limit: int = 50) -> list[MissionType]:
        return await resolve_missions(limit)

    @strawberry.field(description="Get a single mission by ID")
    async def mission(self, mission_id: str) -> Optional[MissionType]:
        return await resolve_mission(mission_id)

    @strawberry.field(description="Get all available agents")
    async def agents(self) -> list[AgentType]:
        return await resolve_agents()

    @strawberry.field(description="Get a single agent by ID")
    async def agent(self, agent_id: str) -> Optional[AgentType]:
        return await resolve_agent(agent_id)

    @strawberry.field(description="Get overall statistics")
    async def stats(self, project_id: Optional[str] = None) -> StatsType:
        return await resolve_stats(project_id)


# ---- Build Schema + Router --------------------------------------------------

schema = strawberry.Schema(query=Query)

graphql_router = GraphQLRouter(schema, path="/graphql")
