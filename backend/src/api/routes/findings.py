"""
Findings CRUD API

Create, read, update, and delete manual findings (stored as Vulnerability
nodes with source='manual'). Scan-discovered vulnerabilities remain
read-only via the vulnerabilities route.
"""

import uuid
from datetime import datetime, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field

from api.dependencies import ProjectAccess
from core.exceptions import ResourceNotFoundError
from graph.client import get_neo4j_client
from graph.utils import node_to_dict


router = APIRouter()

MANUAL_SOURCE = "manual"


# =============================================================================
# Request / Response Models
# =============================================================================


class FindingCreate(BaseModel):
    """Request body for creating a manual finding."""

    title: str = Field(..., min_length=1, max_length=500)
    description: str | None = Field(None, max_length=10000)
    severity: str = Field("medium", pattern="^(critical|high|medium|low|info)$")
    evidence: str | None = Field(None, max_length=5000)
    remediation: str | None = Field(None, max_length=5000)
    matched_at: str | None = Field(None, description="URL or location (e.g. Manual)")
    references: list[str] = Field(default_factory=list)
    scan_id: str | None = None


class FindingUpdate(BaseModel):
    """Request body for updating a finding (partial)."""

    title: str | None = Field(None, min_length=1, max_length=500)
    description: str | None = None
    severity: str | None = Field(None, pattern="^(critical|high|medium|low|info)$")
    evidence: str | None = None
    remediation: str | None = None
    matched_at: str | None = None
    references: list[str] | None = None


class FindingResponse(BaseModel):
    """Single finding response."""

    finding_id: str
    template_id: str
    name: str
    description: str | None
    severity: str
    matched_at: str
    evidence: str | None
    remediation: str | None
    references: list[str]
    created_at: str
    updated_at: str | None
    scan_id: str | None


class FindingListResponse(BaseModel):
    """Paginated list of findings."""

    items: list[FindingResponse]
    total: int
    page: int
    page_size: int


# =============================================================================
# Helpers
# =============================================================================


def _node_to_finding_response(v: dict, scan_id: str | None = None) -> FindingResponse:
    return FindingResponse(
        finding_id=v.get("vulnerability_id", ""),
        template_id=v.get("template_id", ""),
        name=v.get("name", ""),
        description=v.get("description"),
        severity=v.get("severity", "medium"),
        matched_at=v.get("matched_at", ""),
        evidence=v.get("evidence"),
        remediation=v.get("remediation"),
        references=v.get("references", []),
        created_at=v.get("created_at", ""),
        updated_at=v.get("updated_at"),
        scan_id=scan_id,
    )


# =============================================================================
# Endpoints
# =============================================================================


@router.post(
    "",
    response_model=FindingResponse,
    status_code=201,
    summary="Create Finding",
    description="Create a manual finding for the project.",
)
async def create_finding(
    project_id: str = Query(..., description="Project ID"),
    project: Annotated[dict, Depends(ProjectAccess())] = None,
    body: FindingCreate = ...,
) -> FindingResponse:
    """Create a manual finding (Vulnerability node with source=manual)."""
    client = get_neo4j_client()
    finding_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()
    matched_at = body.matched_at or "Manual"

    params_create = {
        "finding_id": finding_id,
        "matched_at": matched_at,
        "project_id": project_id,
        "name": body.title,
        "description": body.description,
        "severity": body.severity.lower(),
        "evidence": body.evidence,
        "remediation": body.remediation,
        "references": body.references or [],
        "created_at": now,
        "source": MANUAL_SOURCE,
    }
    await client.execute_write(
        """
        CREATE (v:Vulnerability {
            vulnerability_id: $finding_id,
            template_id: 'manual',
            matched_at: $matched_at,
            project_id: $project_id,
            name: $name,
            description: $description,
            severity: $severity,
            evidence: $evidence,
            remediation: $remediation,
            references: $references,
            created_at: $created_at,
            source: $source
        })
        WITH v
        MATCH (p:Project {project_id: $project_id})
        MERGE (p)-[:HAS_FINDING]->(v)
        RETURN v
        """,
        params_create,
    )
    if body.scan_id:
        await client.execute_write(
            """
            MATCH (v:Vulnerability {vulnerability_id: $finding_id, project_id: $project_id})
            MATCH (s:Scan {scan_id: $scan_id})
            MERGE (s)-[:DISCOVERED]->(v)
            """,
            {"finding_id": finding_id, "project_id": project_id, "scan_id": body.scan_id},
        )

    return FindingResponse(
        finding_id=finding_id,
        template_id="manual",
        name=body.title,
        description=body.description,
        severity=body.severity,
        matched_at=matched_at,
        evidence=body.evidence,
        remediation=body.remediation,
        references=body.references,
        created_at=now,
        updated_at=None,
        scan_id=body.scan_id,
    )


@router.get(
    "",
    response_model=FindingListResponse,
    summary="List Findings",
    description="List manual findings for the project with pagination.",
)
async def list_findings(
    project_id: str = Query(..., description="Project ID"),
    project: Annotated[dict, Depends(ProjectAccess())] = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=100),
    severity: str | None = Query(None),
) -> FindingListResponse:
    """List manual findings (source=manual) with optional severity filter."""
    client = get_neo4j_client()
    where = "v.project_id = $project_id AND v.template_id = 'manual'"
    params: dict = {"project_id": project_id}
    if severity:
        where += " AND v.severity = $severity"
        params["severity"] = severity.lower()

    count_result = await client.execute_read(
        f"MATCH (v:Vulnerability) WHERE {where} RETURN count(v) AS total",
        params,
    )
    total = count_result[0]["total"] if count_result else 0

    skip = (page - 1) * page_size
    params["skip"] = skip
    params["limit"] = page_size
    result = await client.execute_read(
        f"""
        MATCH (v:Vulnerability)
        WHERE {where}
        OPTIONAL MATCH (scan:Scan)-[:DISCOVERED]->(v)
        RETURN v, scan.scan_id AS scan_id
        ORDER BY v.created_at DESC
        SKIP $skip LIMIT $limit
        """,
        params,
    )

    items = []
    for r in result:
        v = node_to_dict(r.get("v"))
        items.append(_node_to_finding_response(v, r.get("scan_id")))

    return FindingListResponse(items=items, total=total, page=page, page_size=page_size)


@router.get(
    "/{finding_id}",
    response_model=FindingResponse,
    summary="Get Finding",
    description="Get a single manual finding by ID.",
)
async def get_finding(
    finding_id: str,
    project_id: str = Query(..., description="Project ID"),
    project: Annotated[dict, Depends(ProjectAccess())] = None,
) -> FindingResponse:
    """Get one manual finding."""
    client = get_neo4j_client()
    result = await client.execute_read(
        """
        MATCH (v:Vulnerability {project_id: $project_id, vulnerability_id: $finding_id})
        WHERE v.template_id = 'manual'
        OPTIONAL MATCH (scan:Scan)-[:DISCOVERED]->(v)
        RETURN v, scan.scan_id AS scan_id
        LIMIT 1
        """,
        {"project_id": project_id, "finding_id": finding_id},
    )
    if not result:
        raise ResourceNotFoundError("Finding", finding_id)
    v = node_to_dict(result[0].get("v"))
    return _node_to_finding_response(v, result[0].get("scan_id"))


@router.put(
    "/{finding_id}",
    response_model=FindingResponse,
    summary="Update Finding",
    description="Update a manual finding.",
)
async def update_finding(
    finding_id: str,
    project_id: str = Query(..., description="Project ID"),
    project: Annotated[dict, Depends(ProjectAccess())] = None,
    body: FindingUpdate = ...,
) -> FindingResponse:
    """Update a manual finding (partial update)."""
    client = get_neo4j_client()
    now = datetime.now(timezone.utc).isoformat()

    updates: list[str] = ["v.updated_at = $updated_at"]
    params: dict = {"finding_id": finding_id, "project_id": project_id, "updated_at": now}
    if body.title is not None:
        updates.append("v.name = $name")
        params["name"] = body.title
    if body.description is not None:
        updates.append("v.description = $description")
        params["description"] = body.description
    if body.severity is not None:
        updates.append("v.severity = $severity")
        params["severity"] = body.severity.lower()
    if body.evidence is not None:
        updates.append("v.evidence = $evidence")
        params["evidence"] = body.evidence
    if body.remediation is not None:
        updates.append("v.remediation = $remediation")
        params["remediation"] = body.remediation
    if body.matched_at is not None:
        updates.append("v.matched_at = $matched_at")
        params["matched_at"] = body.matched_at
    if body.references is not None:
        updates.append("v.references = $references")
        params["references"] = body.references

    set_clause = ", ".join(updates)
    await client.execute_write(
        f"""
        MATCH (v:Vulnerability {{project_id: $project_id, vulnerability_id: $finding_id}})
        WHERE v.template_id = 'manual'
        SET {set_clause}
        RETURN v
        """,
        params,
    )

    result = await client.execute_read(
        """
        MATCH (v:Vulnerability {project_id: $project_id, vulnerability_id: $finding_id})
        WHERE v.template_id = 'manual'
        OPTIONAL MATCH (scan:Scan)-[:DISCOVERED]->(v)
        RETURN v, scan.scan_id AS scan_id
        LIMIT 1
        """,
        {"project_id": project_id, "finding_id": finding_id},
    )
    if not result:
        raise ResourceNotFoundError("Finding", finding_id)
    v = node_to_dict(result[0].get("v"))
    return _node_to_finding_response(v, result[0].get("scan_id"))


@router.delete(
    "/{finding_id}",
    status_code=204,
    summary="Delete Finding",
    description="Delete a manual finding.",
)
async def delete_finding(
    finding_id: str,
    project_id: str = Query(..., description="Project ID"),
    project: Annotated[dict, Depends(ProjectAccess())] = None,
) -> None:
    """Delete a manual finding and its relationships."""
    client = get_neo4j_client()
    result = await client.execute_write(
        """
        MATCH (v:Vulnerability {project_id: $project_id, vulnerability_id: $finding_id})
        WHERE v.template_id = 'manual'
        DETACH DELETE v
        RETURN count(v) AS deleted
        """,
        {"project_id": project_id, "finding_id": finding_id},
    )
    if not result or result[0].get("deleted", 0) == 0:
        raise ResourceNotFoundError("Finding", finding_id)
