"""
Vulnerability Management Endpoints

List and filter discovered vulnerabilities.
"""

from typing import Annotated

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field

from api.dependencies import ProjectAccess
from core.constants import Severity
from core.exceptions import ResourceNotFoundError
from graph.client import get_neo4j_client
from graph.utils import node_to_dict


router = APIRouter()


# =============================================================================
# Response Models
# =============================================================================

class VulnerabilityResponse(BaseModel):
    """Response model for a vulnerability."""
    
    vulnerability_id: str
    template_id: str
    name: str
    description: str | None
    severity: str
    cvss_score: float | None
    cve_id: str | None
    cwe_id: str | None
    matched_at: str
    evidence: str | None
    remediation: str | None
    references: list[str]
    created_at: str
    scan_id: str | None


class VulnerabilityListResponse(BaseModel):
    """Response model for listing vulnerabilities."""
    
    items: list[VulnerabilityResponse]
    total: int
    page: int
    page_size: int


class VulnerabilitySummary(BaseModel):
    """Summary of vulnerabilities by severity."""
    
    total: int
    critical: int
    high: int
    medium: int
    low: int
    info: int


# =============================================================================
# Endpoints
# =============================================================================

@router.get(
    "",
    response_model=VulnerabilityListResponse,
    summary="List Vulnerabilities",
    description="List all vulnerabilities in a project with filtering and pagination.",
)
async def list_vulnerabilities(
    project_id: str = Query(..., description="Project ID"),
    project: Annotated[dict, Depends(ProjectAccess())] = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=100),
    severity: str | None = Query(None, description="Filter by severity"),
    search: str | None = Query(None, description="Search in name/description"),
    scan_id: str | None = Query(None, description="Filter by scan ID"),
) -> VulnerabilityListResponse:
    """List vulnerabilities with filtering."""
    client = get_neo4j_client()
    
    # Build where clause
    where_parts = ["v.project_id = $project_id"]
    params: dict = {"project_id": project_id}
    
    if severity:
        where_parts.append("v.severity = $severity")
        params["severity"] = severity.lower()
    
    if search:
        where_parts.append("(v.name CONTAINS $search OR v.description CONTAINS $search)")
        params["search"] = search
    
    if scan_id:
        where_parts.append("scan.scan_id = $scan_id")
        params["scan_id"] = scan_id
    
    where_clause = " AND ".join(where_parts)
    
    # Count total
    count_query = f"""
    MATCH (v:Vulnerability)
    {"OPTIONAL MATCH (scan:Scan)-[:DISCOVERED]->(v)" if scan_id else ""}
    WHERE {where_clause}
    RETURN count(DISTINCT v) as total
    """
    
    count_result = await client.execute_read(count_query, params)
    total = count_result[0]["total"] if count_result else 0
    
    # Fetch page
    skip = (page - 1) * page_size
    params["skip"] = skip
    params["limit"] = page_size
    
    query = f"""
    MATCH (v:Vulnerability)
    OPTIONAL MATCH (scan:Scan)-[:DISCOVERED]->(v)
    WHERE {where_clause}
    RETURN DISTINCT v, scan.scan_id as scan_id
    ORDER BY 
        CASE v.severity 
            WHEN 'critical' THEN 0 
            WHEN 'high' THEN 1 
            WHEN 'medium' THEN 2 
            WHEN 'low' THEN 3 
            ELSE 4 
        END,
        v.created_at DESC
    SKIP $skip
    LIMIT $limit
    """
    
    result = await client.execute_read(query, params)
    
    items = []
    for r in result:
        v = node_to_dict(r.get("v"))
        items.append(VulnerabilityResponse(
            vulnerability_id=v.get("vulnerability_id", v.get("template_id", "")),
            template_id=v.get("template_id", ""),
            name=v.get("name", "Unknown"),
            description=v.get("description"),
            severity=v.get("severity", "unknown"),
            cvss_score=v.get("cvss_score"),
            cve_id=v.get("cve_id"),
            cwe_id=v.get("cwe_id"),
            matched_at=v.get("matched_at", ""),
            evidence=v.get("evidence"),
            remediation=v.get("remediation"),
            references=v.get("references", []),
            created_at=v.get("created_at", ""),
            scan_id=r.get("scan_id"),
        ))
    
    return VulnerabilityListResponse(
        items=items,
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get(
    "/summary",
    response_model=VulnerabilitySummary,
    summary="Get Vulnerability Summary",
    description="Get a summary of vulnerabilities by severity.",
)
async def get_vulnerability_summary(
    project_id: str = Query(..., description="Project ID"),
    project: Annotated[dict, Depends(ProjectAccess())] = None,
) -> VulnerabilitySummary:
    """Get vulnerability counts by severity."""
    client = get_neo4j_client()
    
    query = """
    MATCH (v:Vulnerability {project_id: $project_id})
    RETURN 
        count(v) as total,
        sum(CASE WHEN v.severity = 'critical' THEN 1 ELSE 0 END) as critical,
        sum(CASE WHEN v.severity = 'high' THEN 1 ELSE 0 END) as high,
        sum(CASE WHEN v.severity = 'medium' THEN 1 ELSE 0 END) as medium,
        sum(CASE WHEN v.severity = 'low' THEN 1 ELSE 0 END) as low,
        sum(CASE WHEN v.severity = 'info' THEN 1 ELSE 0 END) as info
    """
    
    result = await client.execute_read(query, {"project_id": project_id})
    
    if result:
        r = result[0]
        return VulnerabilitySummary(
            total=r["total"],
            critical=r["critical"],
            high=r["high"],
            medium=r["medium"],
            low=r["low"],
            info=r["info"],
        )
    
    return VulnerabilitySummary(total=0, critical=0, high=0, medium=0, low=0, info=0)


@router.get(
    "/{vulnerability_id}",
    response_model=VulnerabilityResponse,
    summary="Get Vulnerability",
    description="Get details of a specific vulnerability.",
)
async def get_vulnerability(
    vulnerability_id: str,
    project_id: str = Query(..., description="Project ID"),
    project: Annotated[dict, Depends(ProjectAccess())] = None,
) -> VulnerabilityResponse:
    """Get a single vulnerability by ID."""
    client = get_neo4j_client()
    
    query = """
    MATCH (v:Vulnerability {project_id: $project_id})
    WHERE v.vulnerability_id = $vulnerability_id OR v.template_id = $vulnerability_id
    OPTIONAL MATCH (scan:Scan)-[:DISCOVERED]->(v)
    RETURN v, scan.scan_id as scan_id
    LIMIT 1
    """
    
    result = await client.execute_read(
        query,
        {"vulnerability_id": vulnerability_id, "project_id": project_id},
    )
    
    if not result:
        raise ResourceNotFoundError("Vulnerability", vulnerability_id)
    
    r = result[0]
    v = node_to_dict(r.get("v"))
    
    return VulnerabilityResponse(
        vulnerability_id=v.get("vulnerability_id", v.get("template_id", "")),
        template_id=v.get("template_id", ""),
        name=v.get("name", "Unknown"),
        description=v.get("description"),
        severity=v.get("severity", "unknown"),
        cvss_score=v.get("cvss_score"),
        cve_id=v.get("cve_id"),
        cwe_id=v.get("cwe_id"),
        matched_at=v.get("matched_at", ""),
        evidence=v.get("evidence"),
        remediation=v.get("remediation"),
        references=v.get("references", []),
        created_at=v.get("created_at", ""),
        scan_id=r.get("scan_id"),
    )
