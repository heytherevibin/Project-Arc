"""
Project Management Endpoints

CRUD operations for penetration testing projects.
"""

from datetime import datetime, timezone
from typing import Annotated
from uuid import uuid4

from fastapi import APIRouter, Depends, Query, status
from pydantic import BaseModel, Field

from api.dependencies import get_current_user
from core.exceptions import ResourceNotFoundError
from graph.client import get_neo4j_client
from graph.utils import node_to_dict


router = APIRouter()


# =============================================================================
# Request/Response Models
# =============================================================================

class ProjectCreate(BaseModel):
    """Request model for creating a project."""
    
    name: str = Field(..., min_length=1, max_length=100, description="Project name")
    description: str | None = Field(None, max_length=500)
    scope: list[str] = Field(
        default_factory=list,
        description="In-scope targets (domains, IPs, CIDRs)"
    )
    out_of_scope: list[str] = Field(
        default_factory=list,
        description="Out-of-scope targets"
    )
    tags: list[str] = Field(default_factory=list)


class ProjectUpdate(BaseModel):
    """Request model for updating a project."""
    
    name: str | None = Field(None, min_length=1, max_length=100)
    description: str | None = Field(None, max_length=500)
    scope: list[str] | None = None
    out_of_scope: list[str] | None = None
    tags: list[str] | None = None
    status: str | None = Field(None, pattern="^(active|paused|completed|archived)$")


class ProjectResponse(BaseModel):
    """Response model for a project."""
    
    project_id: str
    name: str
    description: str | None
    status: str
    scope: list[str]
    out_of_scope: list[str]
    tags: list[str]
    created_at: str
    updated_at: str | None
    owner_id: str
    stats: dict[str, int] | None = None


class ProjectListResponse(BaseModel):
    """Response model for listing projects."""
    
    items: list[ProjectResponse]
    total: int
    page: int
    page_size: int


class ProjectStats(BaseModel):
    """Project statistics."""
    
    domains: int = 0
    subdomains: int = 0
    ips: int = 0
    ports: int = 0
    urls: int = 0
    vulnerabilities: int = 0
    critical_vulns: int = 0
    high_vulns: int = 0
    scans_completed: int = 0


# =============================================================================
# Endpoints
# =============================================================================

@router.post(
    "",
    response_model=ProjectResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create Project",
    description="Create a new penetration testing project.",
)
async def create_project(
    data: ProjectCreate,
    current_user: Annotated[dict, Depends(get_current_user)],
) -> ProjectResponse:
    """Create a new project."""
    client = get_neo4j_client()
    
    project_id = str(uuid4())
    now = datetime.now(timezone.utc).isoformat()
    
    query = """
    CREATE (p:Project {
        project_id: $project_id,
        name: $name,
        description: $description,
        status: 'active',
        scope: $scope,
        out_of_scope: $out_of_scope,
        tags: $tags,
        created_at: $created_at,
        updated_at: null,
        owner_id: $owner_id
    })
    RETURN p
    """
    
    await client.execute_write(
        query,
        {
            "project_id": project_id,
            "name": data.name,
            "description": data.description,
            "scope": data.scope,
            "out_of_scope": data.out_of_scope,
            "tags": data.tags,
            "created_at": now,
            "owner_id": current_user["user_id"],
        },
    )
    
    # Build response from known inputs (Neo4j may return Node objects that don't serialize like dicts)
    return ProjectResponse(
        project_id=project_id,
        name=data.name,
        description=data.description,
        status="active",
        scope=data.scope,
        out_of_scope=data.out_of_scope,
        tags=data.tags,
        created_at=now,
        updated_at=None,
        owner_id=current_user["user_id"],
    )


@router.get(
    "",
    response_model=ProjectListResponse,
    summary="List Projects",
    description="List all projects for the current user.",
)
async def list_projects(
    current_user: Annotated[dict, Depends(get_current_user)],
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    status_filter: str | None = Query(None, alias="status"),
) -> ProjectListResponse:
    """List projects with pagination."""
    client = get_neo4j_client()
    
    # Build query with optional filter
    where_clause = "WHERE p.owner_id = $owner_id"
    if status_filter:
        where_clause += " AND p.status = $status"
    
    # Count total
    count_query = f"""
    MATCH (p:Project)
    {where_clause}
    RETURN count(p) as total
    """
    
    count_result = await client.execute_read(
        count_query,
        {"owner_id": current_user["user_id"], "status": status_filter},
    )
    total = count_result[0]["total"]
    
    # Fetch page
    skip = (page - 1) * page_size
    query = f"""
    MATCH (p:Project)
    {where_clause}
    RETURN p
    ORDER BY p.created_at DESC
    SKIP $skip
    LIMIT $limit
    """
    
    result = await client.execute_read(
        query,
        {
            "owner_id": current_user["user_id"],
            "status": status_filter,
            "skip": skip,
            "limit": page_size,
        },
    )
    
    items = []
    for r in result:
        p = node_to_dict(r.get("p"))
        if not p:
            continue
        items.append(
            ProjectResponse(
                project_id=p["project_id"],
                name=p["name"],
                description=p.get("description"),
                status=p["status"],
                scope=p.get("scope", []),
                out_of_scope=p.get("out_of_scope", []),
                tags=p.get("tags", []),
                created_at=p["created_at"],
                updated_at=p.get("updated_at"),
                owner_id=p["owner_id"],
            )
        )
    
    return ProjectListResponse(
        items=items,
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get(
    "/{project_id}",
    response_model=ProjectResponse,
    summary="Get Project",
    description="Get a project by ID.",
)
async def get_project(
    project_id: str,
    current_user: Annotated[dict, Depends(get_current_user)],
) -> ProjectResponse:
    """Get a single project."""
    client = get_neo4j_client()
    
    query = """
    MATCH (p:Project {project_id: $project_id, owner_id: $owner_id})
    RETURN p
    """
    
    result = await client.execute_read(
        query,
        {"project_id": project_id, "owner_id": current_user["user_id"]},
    )
    
    if not result:
        raise ResourceNotFoundError("Project", project_id)
    
    project = node_to_dict(result[0].get("p"))
    if not project:
        raise ResourceNotFoundError("Project", project_id)
    
    stats = await _get_project_stats(client, project_id)
    
    return ProjectResponse(
        project_id=project["project_id"],
        name=project["name"],
        description=project.get("description"),
        status=project["status"],
        scope=project.get("scope", []),
        out_of_scope=project.get("out_of_scope", []),
        tags=project.get("tags", []),
        created_at=project["created_at"],
        updated_at=project.get("updated_at"),
        owner_id=project["owner_id"],
        stats=stats,
    )


@router.patch(
    "/{project_id}",
    response_model=ProjectResponse,
    summary="Update Project",
    description="Update a project.",
)
async def update_project(
    project_id: str,
    data: ProjectUpdate,
    current_user: Annotated[dict, Depends(get_current_user)],
) -> ProjectResponse:
    """Update a project."""
    client = get_neo4j_client()
    
    # Build dynamic SET clause
    updates = []
    params = {
        "project_id": project_id,
        "owner_id": current_user["user_id"],
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }
    
    if data.name is not None:
        updates.append("p.name = $name")
        params["name"] = data.name
    
    if data.description is not None:
        updates.append("p.description = $description")
        params["description"] = data.description
    
    if data.scope is not None:
        updates.append("p.scope = $scope")
        params["scope"] = data.scope
    
    if data.out_of_scope is not None:
        updates.append("p.out_of_scope = $out_of_scope")
        params["out_of_scope"] = data.out_of_scope
    
    if data.tags is not None:
        updates.append("p.tags = $tags")
        params["tags"] = data.tags
    
    if data.status is not None:
        updates.append("p.status = $status")
        params["status"] = data.status
    
    updates.append("p.updated_at = $updated_at")
    
    if not updates:
        # Nothing to update, just return current state
        return await get_project(project_id, current_user)
    
    query = f"""
    MATCH (p:Project {{project_id: $project_id, owner_id: $owner_id}})
    SET {", ".join(updates)}
    RETURN p
    """
    
    result = await client.execute_write(query, params)
    
    if not result:
        raise ResourceNotFoundError("Project", project_id)
    
    project = node_to_dict(result[0].get("p"))
    if not project:
        raise ResourceNotFoundError("Project", project_id)
    
    return ProjectResponse(
        project_id=project["project_id"],
        name=project["name"],
        description=project.get("description"),
        status=project["status"],
        scope=project.get("scope", []),
        out_of_scope=project.get("out_of_scope", []),
        tags=project.get("tags", []),
        created_at=project["created_at"],
        updated_at=project.get("updated_at"),
        owner_id=project["owner_id"],
    )


@router.delete(
    "/{project_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete Project",
    description="Delete a project and all associated data.",
)
async def delete_project(
    project_id: str,
    current_user: Annotated[dict, Depends(get_current_user)],
) -> None:
    """Delete a project."""
    client = get_neo4j_client()
    
    # Delete project and all related nodes
    query = """
    MATCH (p:Project {project_id: $project_id, owner_id: $owner_id})
    OPTIONAL MATCH (n {project_id: $project_id})
    DETACH DELETE p, n
    """
    
    await client.execute_write(
        query,
        {"project_id": project_id, "owner_id": current_user["user_id"]},
    )


@router.get(
    "/{project_id}/stats",
    response_model=ProjectStats,
    summary="Get Project Statistics",
    description="Get statistics for a project.",
)
async def get_project_statistics(
    project_id: str,
    current_user: Annotated[dict, Depends(get_current_user)],
) -> ProjectStats:
    """Get project statistics."""
    client = get_neo4j_client()
    
    # Verify project access
    verify_query = """
    MATCH (p:Project {project_id: $project_id, owner_id: $owner_id})
    RETURN p
    """
    
    result = await client.execute_read(
        verify_query,
        {"project_id": project_id, "owner_id": current_user["user_id"]},
    )
    
    if not result:
        raise ResourceNotFoundError("Project", project_id)
    
    stats = await _get_project_stats(client, project_id)
    
    return ProjectStats(**stats)


async def _get_project_stats(client: any, project_id: str) -> dict[str, int]:
    """Get statistics for a project."""
    query = """
    MATCH (p:Project {project_id: $project_id})
    OPTIONAL MATCH (d:Domain {project_id: $project_id})
    OPTIONAL MATCH (s:Subdomain {project_id: $project_id})
    OPTIONAL MATCH (i:IP {project_id: $project_id})
    OPTIONAL MATCH (port:Port {project_id: $project_id})
    OPTIONAL MATCH (u:URL {project_id: $project_id})
    OPTIONAL MATCH (v:Vulnerability {project_id: $project_id})
    OPTIONAL MATCH (cv:Vulnerability {project_id: $project_id, severity: 'critical'})
    OPTIONAL MATCH (hv:Vulnerability {project_id: $project_id, severity: 'high'})
    OPTIONAL MATCH (scan:Scan {project_id: $project_id, status: 'completed'})
    RETURN 
        count(DISTINCT d) as domains,
        count(DISTINCT s) as subdomains,
        count(DISTINCT i) as ips,
        count(DISTINCT port) as ports,
        count(DISTINCT u) as urls,
        count(DISTINCT v) as vulnerabilities,
        count(DISTINCT cv) as critical_vulns,
        count(DISTINCT hv) as high_vulns,
        count(DISTINCT scan) as scans_completed
    """
    
    result = await client.execute_read(query, {"project_id": project_id})
    
    if result:
        return result[0]
    
    return {
        "domains": 0,
        "subdomains": 0,
        "ips": 0,
        "ports": 0,
        "urls": 0,
        "vulnerabilities": 0,
        "critical_vulns": 0,
        "high_vulns": 0,
        "scans_completed": 0,
    }
