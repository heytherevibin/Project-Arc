"""
Target Management Endpoints

CRUD operations for scan targets (domains, IPs, URLs).
"""

from datetime import datetime, timezone
from typing import Annotated, Literal
from uuid import uuid4

from fastapi import APIRouter, Depends, Query, status
from pydantic import BaseModel, Field, field_validator

from api.dependencies import ProjectAccess, get_current_user
from core.exceptions import ResourceNotFoundError, ValidationError
from graph.client import get_neo4j_client
from graph.utils import node_to_dict


router = APIRouter()


# =============================================================================
# Request/Response Models
# =============================================================================

TargetType = Literal["domain", "ip", "url", "cidr"]


class TargetCreate(BaseModel):
    """Request model for adding a target."""
    
    value: str = Field(..., min_length=1, max_length=500, description="Target value")
    target_type: TargetType = Field(..., description="Type of target")
    description: str | None = Field(None, max_length=500)
    tags: list[str] = Field(default_factory=list)
    
    @field_validator("value")
    @classmethod
    def validate_value(cls, v: str) -> str:
        """Normalize target value."""
        v = v.strip().lower()
        # Remove protocol for domains/URLs
        for prefix in ["http://", "https://"]:
            if v.startswith(prefix):
                v = v[len(prefix):]
        return v.rstrip("/")


class TargetResponse(BaseModel):
    """Response model for a target."""
    
    target_id: str
    value: str
    target_type: str
    description: str | None
    tags: list[str]
    status: str
    created_at: str
    last_scanned_at: str | None
    findings_count: int


class TargetListResponse(BaseModel):
    """Response model for listing targets."""
    
    items: list[TargetResponse]
    total: int
    page: int
    page_size: int


class DomainDetails(BaseModel):
    """Detailed information about a domain target."""
    
    target_id: str
    value: str
    subdomains_count: int
    ips_count: int
    ports_count: int
    urls_count: int
    vulnerabilities_count: int
    technologies: list[str]
    last_scanned_at: str | None


# =============================================================================
# Endpoints
# =============================================================================

@router.post(
    "",
    response_model=TargetResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Add Target",
    description="Add a new target to a project.",
)
async def add_target(
    data: TargetCreate,
    project_id: str = Query(..., description="Project ID"),
    project: Annotated[dict, Depends(ProjectAccess(require_write=True))] = None,
) -> TargetResponse:
    """Add a new target to a project."""
    client = get_neo4j_client()
    
    # Validate target is in scope
    if project["scope"]:
        in_scope = _is_target_in_scope(data.value, project["scope"])
        if not in_scope:
            raise ValidationError(
                f"Target '{data.value}' is not in project scope",
                field="value",
            )
    
    # Check if target is out of scope
    if project["out_of_scope"]:
        out_of_scope = _is_target_in_scope(data.value, project["out_of_scope"])
        if out_of_scope:
            raise ValidationError(
                f"Target '{data.value}' is explicitly out of scope",
                field="value",
            )
    
    target_id = str(uuid4())
    now = datetime.now(timezone.utc).isoformat()
    
    # Create appropriate node based on target type
    if data.target_type == "domain":
        query = """
        MERGE (d:Domain {name: $value, project_id: $project_id})
        ON CREATE SET
            d.target_id = $target_id,
            d.description = $description,
            d.tags = $tags,
            d.status = 'pending',
            d.created_at = $created_at,
            d.last_scanned_at = null
        ON MATCH SET
            d.description = coalesce($description, d.description),
            d.tags = $tags
        RETURN d
        """
    elif data.target_type == "ip":
        query = """
        MERGE (i:IP {address: $value, project_id: $project_id})
        ON CREATE SET
            i.target_id = $target_id,
            i.description = $description,
            i.tags = $tags,
            i.status = 'pending',
            i.created_at = $created_at,
            i.last_scanned_at = null
        ON MATCH SET
            i.description = coalesce($description, i.description),
            i.tags = $tags
        RETURN i
        """
    else:
        query = """
        MERGE (u:URL {url: $value, project_id: $project_id})
        ON CREATE SET
            u.target_id = $target_id,
            u.description = $description,
            u.tags = $tags,
            u.status = 'pending',
            u.created_at = $created_at,
            u.last_scanned_at = null
        ON MATCH SET
            u.description = coalesce($description, u.description),
            u.tags = $tags
        RETURN u
        """
    
    result = await client.execute_write(
        query,
        {
            "value": data.value,
            "project_id": project_id,
            "target_id": target_id,
            "description": data.description,
            "tags": data.tags,
            "created_at": now,
        },
    )
    
    raw_node = list(result[0].values())[0]
    node = node_to_dict(raw_node)
    
    return TargetResponse(
        target_id=node.get("target_id", target_id),
        value=data.value,
        target_type=data.target_type,
        description=node.get("description"),
        tags=node.get("tags", []),
        status=node.get("status", "pending"),
        created_at=node.get("created_at", now),
        last_scanned_at=node.get("last_scanned_at"),
        findings_count=0,
    )


@router.get(
    "",
    response_model=TargetListResponse,
    summary="List Targets",
    description="List all targets in a project.",
)
async def list_targets(
    project_id: str = Query(..., description="Project ID"),
    project: Annotated[dict, Depends(ProjectAccess())] = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=100),
    target_type: TargetType | None = Query(None),
    status_filter: str | None = Query(None, alias="status"),
) -> TargetListResponse:
    """List targets with pagination and filtering."""
    client = get_neo4j_client()
    
    # Build label filter
    labels = []
    if target_type == "domain":
        labels = ["Domain"]
    elif target_type == "ip":
        labels = ["IP"]
    elif target_type == "url":
        labels = ["URL"]
    else:
        labels = ["Domain", "IP", "URL"]
    
    items = []
    total = 0
    
    for label in labels:
        # Build where clause
        where_parts = [f"n.project_id = $project_id"]
        if status_filter:
            where_parts.append("n.status = $status")
        where_clause = " AND ".join(where_parts)
        
        # Count query
        count_query = f"""
        MATCH (n:{label})
        WHERE {where_clause}
        RETURN count(n) as count
        """
        
        count_result = await client.execute_read(
            count_query,
            {"project_id": project_id, "status": status_filter},
        )
        total += count_result[0]["count"]
        
        # Fetch items
        skip = (page - 1) * page_size
        query = f"""
        MATCH (n:{label})
        WHERE {where_clause}
        OPTIONAL MATCH (n)-[:HAS_VULNERABILITY]->(v:Vulnerability)
        WITH n, count(DISTINCT v) as vuln_count
        RETURN n, vuln_count
        ORDER BY n.created_at DESC
        SKIP $skip
        LIMIT $limit
        """
        
        result = await client.execute_read(
            query,
            {
                "project_id": project_id,
                "status": status_filter,
                "skip": skip,
                "limit": page_size,
            },
        )
        
        for r in result:
            node = node_to_dict(r.get("n"))
            value = node.get("name") or node.get("address") or node.get("url")
            
            items.append(TargetResponse(
                target_id=node.get("target_id", ""),
                value=value,
                target_type=label.lower(),
                description=node.get("description"),
                tags=node.get("tags", []),
                status=node.get("status", "pending"),
                created_at=node.get("created_at", ""),
                last_scanned_at=node.get("last_scanned_at"),
                findings_count=r["vuln_count"],
            ))
    
    # Sort combined results
    items.sort(key=lambda x: x.created_at, reverse=True)
    
    return TargetListResponse(
        items=items[:page_size],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get(
    "/{target_id}",
    response_model=DomainDetails,
    summary="Get Target Details",
    description="Get detailed information about a target.",
)
async def get_target_details(
    target_id: str,
    project_id: str = Query(..., description="Project ID"),
    project: Annotated[dict, Depends(ProjectAccess())] = None,
) -> DomainDetails:
    """Get detailed target information."""
    client = get_neo4j_client()
    
    query = """
    MATCH (n {target_id: $target_id, project_id: $project_id})
    OPTIONAL MATCH (n)-[:HAS_SUBDOMAIN]->(s:Subdomain)
    OPTIONAL MATCH (n)-[:RESOLVES_TO|HAS_SUBDOMAIN*0..2]->(i:IP)
    OPTIONAL MATCH (i)-[:HAS_PORT]->(p:Port)
    OPTIONAL MATCH (n)-[:HAS_SUBDOMAIN|RESOLVES_TO|HAS_PORT|RUNS_SERVICE|SERVES_URL*0..5]->(u:URL)
    OPTIONAL MATCH (n)-[:HAS_VULNERABILITY|HAS_SUBDOMAIN*0..2]->(v:Vulnerability)
    OPTIONAL MATCH (u)-[:USES_TECHNOLOGY]->(t:Technology)
    RETURN 
        n,
        count(DISTINCT s) as subdomains_count,
        count(DISTINCT i) as ips_count,
        count(DISTINCT p) as ports_count,
        count(DISTINCT u) as urls_count,
        count(DISTINCT v) as vulns_count,
        collect(DISTINCT t.name)[0..10] as technologies
    """
    
    result = await client.execute_read(
        query,
        {"target_id": target_id, "project_id": project_id},
    )
    
    if not result:
        raise ResourceNotFoundError("Target", target_id)
    
    r = result[0]
    node = node_to_dict(r.get("n"))
    value = node.get("name") or node.get("address") or node.get("url")
    
    return DomainDetails(
        target_id=target_id,
        value=value,
        subdomains_count=r["subdomains_count"],
        ips_count=r["ips_count"],
        ports_count=r["ports_count"],
        urls_count=r["urls_count"],
        vulnerabilities_count=r["vulns_count"],
        technologies=r["technologies"] or [],
        last_scanned_at=node.get("last_scanned_at"),
    )


@router.delete(
    "/{target_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete Target",
    description="Delete a target and all associated data.",
)
async def delete_target(
    target_id: str,
    project_id: str = Query(..., description="Project ID"),
    project: Annotated[dict, Depends(ProjectAccess(require_write=True))] = None,
) -> None:
    """Delete a target and all related nodes."""
    client = get_neo4j_client()
    
    # Delete target and all related nodes
    query = """
    MATCH (n {target_id: $target_id, project_id: $project_id})
    OPTIONAL MATCH (n)-[*]->(related)
    WHERE related.project_id = $project_id
    DETACH DELETE n, related
    """
    
    await client.execute_write(
        query,
        {"target_id": target_id, "project_id": project_id},
    )


def _is_target_in_scope(target: str, scope_list: list[str]) -> bool:
    """Check if a target matches any scope entry."""
    target = target.lower()
    
    for scope in scope_list:
        scope = scope.lower()
        
        # Wildcard match
        if scope.startswith("*."):
            if target.endswith(scope[1:]) or target == scope[2:]:
                return True
        
        # Exact match or subdomain match
        if target == scope or target.endswith("." + scope):
            return True
        
        # CIDR match (basic)
        if "/" in scope:
            # TODO: Implement proper CIDR matching
            pass
    
    return False
