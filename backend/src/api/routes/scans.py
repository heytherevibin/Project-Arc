"""
Scan Management Endpoints

CRUD operations for reconnaissance scans.
"""

import json
from datetime import datetime, timezone
from typing import Annotated, Literal
from uuid import uuid4

from fastapi import APIRouter, BackgroundTasks, Depends, Query, status
from pydantic import BaseModel, Field

from api.dependencies import ProjectAccess
from core.constants import ScanStatus, ScanType
from core.exceptions import (
    ResourceNotFoundError,
    ScanAlreadyRunningError,
    ValidationError,
)
from graph.client import get_neo4j_client
from graph.utils import node_to_dict


router = APIRouter()


# =============================================================================
# Request/Response Models
# =============================================================================

class ScanCreate(BaseModel):
    """Request model for creating a scan."""
    
    target: str = Field(..., min_length=1, description="Scan target (domain, IP, or URL)")
    scan_type: ScanType = Field(
        ScanType.FULL_RECON,
        description="Type of scan to perform"
    )
    options: dict = Field(
        default_factory=dict,
        description="Scan-specific options"
    )


class ScanResponse(BaseModel):
    """Response model for a scan."""
    
    scan_id: str
    target: str
    scan_type: str
    status: str
    progress: float
    phase: str | None
    started_at: str | None
    completed_at: str | None
    duration_seconds: float | None
    findings_count: int
    error_message: str | None
    created_at: str


class ScanListResponse(BaseModel):
    """Response model for listing scans."""
    
    items: list[ScanResponse]
    total: int
    page: int
    page_size: int


class ScanProgress(BaseModel):
    """Real-time scan progress."""
    
    scan_id: str
    status: str
    progress: float
    phase: str | None
    current_tool: str | None
    items_discovered: int
    vulnerabilities_found: int
    elapsed_seconds: float


class ScanResults(BaseModel):
    """Detailed scan results."""
    
    scan_id: str
    target: str
    scan_type: str
    status: str
    summary: dict
    subdomains: list[dict]
    ips: list[dict]
    ports: list[dict]
    urls: list[dict]
    technologies: list[dict]
    vulnerabilities: list[dict]
    whois_data: list[dict] = []
    shodan_data: list[dict] = []
    api_endpoints: list[dict] = []
    github_repos: list[dict] = []
    github_findings: list[dict] = []
    tool_errors: list[str] | None = None  # Per-phase errors (e.g. MCP unreachable)


# =============================================================================
# Endpoints
# =============================================================================

@router.post(
    "",
    response_model=ScanResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Start Scan",
    description="Start a new reconnaissance scan.",
)
async def start_scan(
    data: ScanCreate,
    background_tasks: BackgroundTasks,
    project_id: str = Query(..., description="Project ID"),
    project: Annotated[dict, Depends(ProjectAccess(require_write=True))] = None,
) -> ScanResponse:
    """Start a new scan."""
    client = get_neo4j_client()
    
    # Check for existing running scan on same target
    existing_query = """
    MATCH (s:Scan {
        target: $target,
        project_id: $project_id,
        status: 'running'
    })
    RETURN s
    LIMIT 1
    """
    
    existing = await client.execute_read(
        existing_query,
        {"target": data.target, "project_id": project_id},
    )
    
    if existing:
        raise ScanAlreadyRunningError(existing[0]["s"]["scan_id"])
    
    scan_id, now = await _create_scan_record(
        client, project_id, data.target, data.scan_type, data.options
    )
    
    # Queue scan execution in background
    background_tasks.add_task(
        _execute_scan_async,
        scan_id=scan_id,
        project_id=project_id,
        target=data.target,
        scan_type=data.scan_type,
        options=data.options,
    )
    
    return ScanResponse(
        scan_id=scan_id,
        target=data.target,
        scan_type=data.scan_type.value,
        status=ScanStatus.QUEUED.value,
        progress=0.0,
        phase="initialization",
        started_at=None,
        completed_at=None,
        duration_seconds=None,
        findings_count=0,
        error_message=None,
        created_at=now,
    )


@router.get(
    "",
    response_model=ScanListResponse,
    summary="List Scans",
    description="List all scans in a project.",
)
async def list_scans(
    project_id: str = Query(..., description="Project ID"),
    project: Annotated[dict, Depends(ProjectAccess())] = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    status_filter: str | None = Query(None, alias="status"),
    target_filter: str | None = Query(None, alias="target"),
) -> ScanListResponse:
    """List scans with pagination."""
    client = get_neo4j_client()
    
    # Build where clause
    where_parts = ["s.project_id = $project_id"]
    params = {"project_id": project_id}
    
    if status_filter:
        where_parts.append("s.status = $status")
        params["status"] = status_filter
    
    if target_filter:
        where_parts.append("s.target CONTAINS $target")
        params["target"] = target_filter
    
    where_clause = " AND ".join(where_parts)
    
    # Count total
    count_query = f"""
    MATCH (s:Scan)
    WHERE {where_clause}
    RETURN count(s) as total
    """
    
    count_result = await client.execute_read(count_query, params)
    total = count_result[0]["total"]
    
    # Fetch page
    skip = (page - 1) * page_size
    params["skip"] = skip
    params["limit"] = page_size
    
    query = f"""
    MATCH (s:Scan)
    WHERE {where_clause}
    RETURN s
    ORDER BY s.created_at DESC
    SKIP $skip
    LIMIT $limit
    """
    
    result = await client.execute_read(query, params)
    
    items = []
    for r in result:
        s = node_to_dict(r.get("s"))
        if not s:
            continue
        items.append(ScanResponse(
            scan_id=s["scan_id"],
            target=s["target"],
            scan_type=s["scan_type"],
            status=s["status"],
            progress=s.get("progress", 0.0),
            phase=s.get("phase"),
            started_at=s.get("started_at"),
            completed_at=s.get("completed_at"),
            duration_seconds=s.get("duration_seconds"),
            findings_count=s.get("findings_count", 0),
            error_message=s.get("error_message"),
            created_at=s["created_at"],
        ))
    
    return ScanListResponse(
        items=items,
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get(
    "/{scan_id}",
    response_model=ScanResponse,
    summary="Get Scan",
    description="Get scan status and details.",
)
async def get_scan(
    scan_id: str,
    project_id: str = Query(..., description="Project ID"),
    project: Annotated[dict, Depends(ProjectAccess())] = None,
) -> ScanResponse:
    """Get scan details."""
    client = get_neo4j_client()
    
    query = """
    MATCH (s:Scan {scan_id: $scan_id, project_id: $project_id})
    RETURN s
    """
    
    result = await client.execute_read(
        query,
        {"scan_id": scan_id, "project_id": project_id},
    )
    
    if not result:
        raise ResourceNotFoundError("Scan", scan_id)
    
    scan = node_to_dict(result[0].get("s"))
    if not scan:
        raise ResourceNotFoundError("Scan", scan_id)
    
    return ScanResponse(
        scan_id=scan["scan_id"],
        target=scan["target"],
        scan_type=scan["scan_type"],
        status=scan["status"],
        progress=scan.get("progress", 0.0),
        phase=scan.get("phase"),
        started_at=scan.get("started_at"),
        completed_at=scan.get("completed_at"),
        duration_seconds=scan.get("duration_seconds"),
        findings_count=scan.get("findings_count", 0),
        error_message=scan.get("error_message"),
        created_at=scan["created_at"],
    )


@router.get(
    "/{scan_id}/progress",
    response_model=ScanProgress,
    summary="Get Scan Progress",
    description="Get real-time scan progress.",
)
async def get_scan_progress(
    scan_id: str,
    project_id: str = Query(..., description="Project ID"),
    project: Annotated[dict, Depends(ProjectAccess())] = None,
) -> ScanProgress:
    """Get real-time scan progress."""
    client = get_neo4j_client()
    
    query = """
    MATCH (s:Scan {scan_id: $scan_id, project_id: $project_id})
    OPTIONAL MATCH (s)-[:DISCOVERED]->(n)
    OPTIONAL MATCH (s)-[:DISCOVERED]->(v:Vulnerability)
    WITH s, count(DISTINCT n) as items, count(DISTINCT v) as vulns
    RETURN s, items, vulns
    """
    
    result = await client.execute_read(
        query,
        {"scan_id": scan_id, "project_id": project_id},
    )
    
    if not result:
        raise ResourceNotFoundError("Scan", scan_id)
    
    r = result[0]
    scan = node_to_dict(r.get("s"))
    if not scan:
        raise ResourceNotFoundError("Scan", scan_id)
    
    # Calculate elapsed time
    elapsed = 0.0
    if scan.get("started_at"):
        start = datetime.fromisoformat(scan["started_at"].replace("Z", "+00:00"))
        if scan.get("completed_at"):
            end = datetime.fromisoformat(scan["completed_at"].replace("Z", "+00:00"))
        else:
            end = datetime.now(timezone.utc)
        elapsed = (end - start).total_seconds()
    
    return ScanProgress(
        scan_id=scan_id,
        status=scan["status"],
        progress=scan.get("progress", 0.0),
        phase=scan.get("phase"),
        current_tool=scan.get("current_tool"),
        items_discovered=r["items"],
        vulnerabilities_found=r["vulns"],
        elapsed_seconds=elapsed,
    )


@router.get(
    "/{scan_id}/results",
    response_model=ScanResults,
    summary="Get Scan Results",
    description="Get detailed scan results.",
)
async def get_scan_results(
    scan_id: str,
    project_id: str = Query(..., description="Project ID"),
    project: Annotated[dict, Depends(ProjectAccess())] = None,
) -> ScanResults:
    """Get comprehensive scan results."""
    client = get_neo4j_client()
    
    # Get scan info
    scan_query = """
    MATCH (s:Scan {scan_id: $scan_id, project_id: $project_id})
    RETURN s
    """
    
    scan_result = await client.execute_read(
        scan_query,
        {"scan_id": scan_id, "project_id": project_id},
    )
    
    if not scan_result:
        raise ResourceNotFoundError("Scan", scan_id)
    
    scan = node_to_dict(scan_result[0].get("s"))
    if not scan:
        raise ResourceNotFoundError("Scan", scan_id)
    
    # Get discovered items (one row per node so we bucket by label correctly)
    results_query = """
    MATCH (s:Scan {scan_id: $scan_id})-[:DISCOVERED]->(n)
    RETURN labels(n) as node_labels, properties(n) as item
    """
    
    results = await client.execute_read(
        results_query,
        {"scan_id": scan_id},
    )
    
    # Organize results by type; normalize each item to a dict for serialization
    subdomains = []
    ips = []
    ports = []
    urls = []
    technologies = []
    vulnerabilities = []
    whois_data = []
    shodan_data = []
    api_endpoints = []
    github_repos = []
    github_findings = []
    
    for r in results:
        raw_labels = r.get("node_labels")
        try:
            labels = list(raw_labels) if raw_labels else []
        except (TypeError, ValueError):
            labels = []
        item = node_to_dict(r.get("item")) if r.get("item") is not None else {}
        if not item:
            continue
        if "Subdomain" in labels:
            subdomains.append(item)
        elif "IP" in labels:
            ips.append(item)
        elif "Port" in labels:
            ports.append(item)
        elif "URL" in labels:
            urls.append(item)
        elif "Technology" in labels:
            technologies.append(item)
        elif "Vulnerability" in labels:
            vulnerabilities.append(item)
        elif "WhoisData" in labels:
            whois_data.append(item)
        elif "ShodanData" in labels:
            shodan_data.append(item)
        elif "ApiEndpoint" in labels:
            api_endpoints.append(item)
        elif "GitHubRepo" in labels:
            github_repos.append(item)
        elif "GitHubFinding" in labels:
            github_findings.append(item)
    
    # Fallback: if no discoveries (e.g. old scan or bootstrap didn't run), show target as subdomain
    target = scan.get("target") or ""
    if not subdomains and not ips and not urls and not technologies and not vulnerabilities and target:
        subdomains = [{"name": target.strip(), "discovery_source": "target"}]
    
    # Build summary
    summary = {
        "subdomains_count": len(subdomains),
        "ips_count": len(ips),
        "ports_count": len(ports),
        "urls_count": len(urls),
        "technologies_count": len(technologies),
        "vulnerabilities_count": len(vulnerabilities),
        "whois_count": len(whois_data),
        "shodan_count": len(shodan_data),
        "api_endpoints_count": len(api_endpoints),
        "github_repos_count": len(github_repos),
        "github_findings_count": len(github_findings),
        "critical_count": sum(1 for v in vulnerabilities if v.get("severity") == "critical"),
        "high_count": sum(1 for v in vulnerabilities if v.get("severity") == "high"),
        "medium_count": sum(1 for v in vulnerabilities if v.get("severity") == "medium"),
        "low_count": sum(1 for v in vulnerabilities if v.get("severity") == "low"),
    }
    
    # Parse tool_errors (stored as JSON string) for UI to show why tools failed
    tool_errors_raw = scan.get("tool_errors")
    tool_errors: list[str] | None = None
    if tool_errors_raw and isinstance(tool_errors_raw, str):
        try:
            parsed = json.loads(tool_errors_raw)
            tool_errors = parsed if isinstance(parsed, list) else [str(parsed)]
        except (json.JSONDecodeError, TypeError):
            tool_errors = [str(tool_errors_raw)]
    elif tool_errors_raw and isinstance(tool_errors_raw, list):
        tool_errors = [str(e) for e in tool_errors_raw]

    return ScanResults(
        scan_id=scan_id,
        target=scan["target"],
        scan_type=scan["scan_type"],
        status=scan["status"],
        summary=summary,
        subdomains=subdomains,
        ips=ips,
        ports=ports,
        urls=urls,
        technologies=technologies,
        vulnerabilities=vulnerabilities,
        whois_data=whois_data,
        shodan_data=shodan_data,
        api_endpoints=api_endpoints,
        github_repos=github_repos,
        github_findings=github_findings,
        tool_errors=tool_errors,
    )


@router.post(
    "/{scan_id}/stop",
    response_model=ScanResponse,
    summary="Stop Scan",
    description="Stop a running scan.",
)
async def stop_scan(
    scan_id: str,
    project_id: str = Query(..., description="Project ID"),
    project: Annotated[dict, Depends(ProjectAccess(require_write=True))] = None,
) -> ScanResponse:
    """Stop a running scan."""
    client = get_neo4j_client()
    
    # Update scan status
    query = """
    MATCH (s:Scan {scan_id: $scan_id, project_id: $project_id})
    WHERE s.status IN ['queued', 'running']
    SET s.status = 'cancelled',
        s.completed_at = $completed_at
    RETURN s
    """
    
    result = await client.execute_write(
        query,
        {
            "scan_id": scan_id,
            "project_id": project_id,
            "completed_at": datetime.now(timezone.utc).isoformat(),
        },
    )
    
    if not result:
        raise ResourceNotFoundError("Scan", scan_id)
    
    scan = node_to_dict(result[0].get("s"))
    if not scan:
        raise ResourceNotFoundError("Scan", scan_id)
    
    # TODO: Actually stop the running scan process
    
    return ScanResponse(
        scan_id=scan["scan_id"],
        target=scan["target"],
        scan_type=scan["scan_type"],
        status=scan["status"],
        progress=scan.get("progress", 0.0),
        phase=scan.get("phase"),
        started_at=scan.get("started_at"),
        completed_at=scan.get("completed_at"),
        duration_seconds=scan.get("duration_seconds"),
        findings_count=scan.get("findings_count", 0),
        error_message=scan.get("error_message"),
        created_at=scan["created_at"],
    )


@router.delete(
    "/{scan_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete Scan",
    description="Delete a scan and its results.",
)
async def delete_scan(
    scan_id: str,
    project_id: str = Query(..., description="Project ID"),
    project: Annotated[dict, Depends(ProjectAccess(require_write=True))] = None,
) -> None:
    """Delete a scan and associated results."""
    client = get_neo4j_client()
    
    # Don't delete running scans
    check_query = """
    MATCH (s:Scan {scan_id: $scan_id, project_id: $project_id})
    RETURN s.status as status
    """
    
    check = await client.execute_read(
        check_query,
        {"scan_id": scan_id, "project_id": project_id},
    )
    
    if check and check[0]["status"] == "running":
        raise ValidationError("Cannot delete a running scan")
    
    # Delete scan and discovered relationships
    query = """
    MATCH (s:Scan {scan_id: $scan_id, project_id: $project_id})
    OPTIONAL MATCH (s)-[r:DISCOVERED]->()
    DELETE r, s
    """
    
    await client.execute_write(
        query,
        {"scan_id": scan_id, "project_id": project_id},
    )


async def _create_scan_record(client, project_id: str, target: str, scan_type: ScanType, options: dict):
    """Create scan and Domain nodes; return (scan_id, created_at). Used by start_scan and monitoring."""
    scan_id = str(uuid4())
    now = datetime.now(timezone.utc).isoformat()
    await client.execute_write(
        """
        CREATE (s:Scan {
            scan_id: $scan_id,
            project_id: $project_id,
            target: $target,
            scan_type: $scan_type,
            status: $status,
            progress: 0.0,
            phase: 'initialization',
            options: $options,
            created_at: $created_at,
            started_at: null,
            completed_at: null,
            duration_seconds: null,
            findings_count: 0,
            error_message: null
        })
        RETURN s
        """,
        {
            "scan_id": scan_id,
            "project_id": project_id,
            "target": target,
            "scan_type": scan_type.value,
            "status": ScanStatus.QUEUED.value,
            "options": str(options),
            "created_at": now,
        },
    )
    await client.execute_write(
        """
        MERGE (d:Domain {name: $target, project_id: $project_id})
        ON CREATE SET d.created_at = $created_at
        """,
        {"target": target, "project_id": project_id, "created_at": now},
    )
    return scan_id, now


async def _execute_scan_async(
    scan_id: str,
    project_id: str,
    target: str,
    scan_type: ScanType,
    options: dict,
) -> None:
    """
    Execute scan in background.
    Sets status to 'running' immediately so UI shows progress; pipeline runs next.
    """
    from recon.pipeline import ReconPipeline
    from core.logging import get_logger
    
    logger = get_logger(__name__)
    
    # Mark running as soon as the background task starts (so UI doesn't stay on "queued")
    client = get_neo4j_client()
    now = datetime.now(timezone.utc).isoformat()
    try:
        await client.execute_write(
            """
            MATCH (s:Scan {scan_id: $scan_id})
            SET s.status = 'running',
                s.started_at = $started_at,
                s.phase = 'initialization'
            """,
            {"scan_id": scan_id, "started_at": now},
        )
    except Exception as e:
        logger.exception("Failed to set scan running", scan_id=scan_id, error=str(e))
    
    try:
        pipeline = ReconPipeline(
            scan_id=scan_id,
            project_id=project_id,
            target=target,
            scan_type=scan_type,
            options=options,
        )
        
        await pipeline.execute()
        
    except Exception as e:
        logger.exception(
            "Scan execution failed",
            scan_id=scan_id,
            error=str(e),
        )
        
        # Update scan status to failed
        client = get_neo4j_client()
        await client.execute_write(
            """
            MATCH (s:Scan {scan_id: $scan_id})
            SET s.status = 'failed',
                s.error_message = $error,
                s.completed_at = $completed_at
            """,
            {
                "scan_id": scan_id,
                "error": str(e)[:500],
                "completed_at": datetime.now(timezone.utc).isoformat(),
            },
        )
