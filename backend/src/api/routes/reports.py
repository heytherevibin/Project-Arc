"""
Reporting Endpoints

Generate reports for projects and scans.
"""

from datetime import datetime, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from api.dependencies import ProjectAccess
from core.exceptions import ResourceNotFoundError
from graph.client import get_neo4j_client
from graph.utils import node_to_dict


router = APIRouter()


# =============================================================================
# Response Models
# =============================================================================

class VulnerabilitySummary(BaseModel):
    """Vulnerability summary for reports."""
    
    total: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0


class AssetSummary(BaseModel):
    """Asset summary for reports."""
    
    domains: int = 0
    subdomains: int = 0
    ips: int = 0
    ports: int = 0
    urls: int = 0
    technologies: int = 0


class TopVulnerability(BaseModel):
    """Top vulnerability for reports."""
    
    name: str
    severity: str
    count: int
    cve_id: str | None = None


class TopTechnology(BaseModel):
    """Top technology for reports."""
    
    name: str
    count: int


class ScanSummary(BaseModel):
    """Scan summary for reports."""
    
    total: int = 0
    completed: int = 0
    failed: int = 0
    running: int = 0


class WhoisEntry(BaseModel):
    """WHOIS data entry for reports."""
    domain_name: str
    raw: str | None = None


class ShodanEntry(BaseModel):
    """Shodan data entry for reports."""
    ip: str
    data_json: str | None = None


class ProjectReportResponse(BaseModel):
    """Complete project report response."""
    
    project_id: str
    project_name: str
    generated_at: str
    scope: list[str]
    assets: AssetSummary
    vulnerabilities: VulnerabilitySummary
    scans: ScanSummary
    top_vulnerabilities: list[TopVulnerability]
    top_technologies: list[TopTechnology]
    risk_score: float
    risk_level: str
    whois_entries: list[WhoisEntry] = []
    shodan_entries: list[ShodanEntry] = []


class ScanReportResponse(BaseModel):
    """Complete scan report response."""
    
    scan_id: str
    target: str
    scan_type: str
    status: str
    started_at: str | None
    completed_at: str | None
    duration_seconds: float | None
    generated_at: str
    assets: AssetSummary
    vulnerabilities: VulnerabilitySummary
    vulnerability_list: list[dict]
    findings_summary: str
    whois_entries: list[WhoisEntry] = []
    shodan_entries: list[ShodanEntry] = []


# =============================================================================
# Endpoints
# =============================================================================

@router.get(
    "/project/{project_id}",
    response_model=ProjectReportResponse,
    summary="Generate Project Report",
    description="Generate a comprehensive report for a project.",
)
async def generate_project_report(
    project_id: str,
    project: Annotated[dict, Depends(ProjectAccess())] = None,
) -> ProjectReportResponse:
    """Generate a full project report."""
    client = get_neo4j_client()
    
    # Get project info
    project_query = """
    MATCH (p:Project {project_id: $project_id})
    RETURN p
    """
    project_result = await client.execute_read(project_query, {"project_id": project_id})
    
    if not project_result:
        raise ResourceNotFoundError("Project", project_id)
    
    project_data = node_to_dict(project_result[0].get("p"))
    if not project_data:
        raise ResourceNotFoundError("Project", project_id)
    
    # Get asset counts
    assets_query = """
    MATCH (p:Project {project_id: $project_id})
    OPTIONAL MATCH (d:Domain {project_id: $project_id})
    OPTIONAL MATCH (s:Subdomain {project_id: $project_id})
    OPTIONAL MATCH (i:IP {project_id: $project_id})
    OPTIONAL MATCH (port:Port {project_id: $project_id})
    OPTIONAL MATCH (u:URL {project_id: $project_id})
    OPTIONAL MATCH (t:Technology {project_id: $project_id})
    RETURN 
        count(DISTINCT d) as domains,
        count(DISTINCT s) as subdomains,
        count(DISTINCT i) as ips,
        count(DISTINCT port) as ports,
        count(DISTINCT u) as urls,
        count(DISTINCT t) as technologies
    """
    assets_result = await client.execute_read(assets_query, {"project_id": project_id})
    assets = assets_result[0] if assets_result else {}
    
    # Get vulnerability counts
    vuln_query = """
    MATCH (v:Vulnerability {project_id: $project_id})
    RETURN 
        count(v) as total,
        sum(CASE WHEN v.severity = 'critical' THEN 1 ELSE 0 END) as critical,
        sum(CASE WHEN v.severity = 'high' THEN 1 ELSE 0 END) as high,
        sum(CASE WHEN v.severity = 'medium' THEN 1 ELSE 0 END) as medium,
        sum(CASE WHEN v.severity = 'low' THEN 1 ELSE 0 END) as low,
        sum(CASE WHEN v.severity = 'info' THEN 1 ELSE 0 END) as info
    """
    vuln_result = await client.execute_read(vuln_query, {"project_id": project_id})
    vulns = vuln_result[0] if vuln_result else {}
    
    # Get scan counts
    scan_query = """
    MATCH (s:Scan {project_id: $project_id})
    RETURN 
        count(s) as total,
        sum(CASE WHEN s.status = 'completed' THEN 1 ELSE 0 END) as completed,
        sum(CASE WHEN s.status = 'failed' THEN 1 ELSE 0 END) as failed,
        sum(CASE WHEN s.status = 'running' THEN 1 ELSE 0 END) as running
    """
    scan_result = await client.execute_read(scan_query, {"project_id": project_id})
    scans = scan_result[0] if scan_result else {}
    
    # Get top vulnerabilities
    top_vuln_query = """
    MATCH (v:Vulnerability {project_id: $project_id})
    WITH v.name as name, v.severity as severity, v.cve_id as cve_id, count(*) as count
    RETURN name, severity, cve_id, count
    ORDER BY 
        CASE severity 
            WHEN 'critical' THEN 0 
            WHEN 'high' THEN 1 
            WHEN 'medium' THEN 2 
            ELSE 3 
        END,
        count DESC
    LIMIT 10
    """
    top_vuln_result = await client.execute_read(top_vuln_query, {"project_id": project_id})
    top_vulns = [
        TopVulnerability(
            name=r["name"],
            severity=r["severity"],
            count=r["count"],
            cve_id=r["cve_id"],
        )
        for r in top_vuln_result
    ]
    
    # Get top technologies
    top_tech_query = """
    MATCH (t:Technology {project_id: $project_id})
    WITH t.name as name, count(*) as count
    RETURN name, count
    ORDER BY count DESC
    LIMIT 10
    """
    top_tech_result = await client.execute_read(top_tech_query, {"project_id": project_id})
    top_techs = [
        TopTechnology(name=r["name"], count=r["count"])
        for r in top_tech_result
    ]
    
    # Extended recon: WHOIS and Shodan data for project
    whois_query = """
    MATCH (w:WhoisData {project_id: $project_id})
    RETURN w.domain_name as domain_name, w.raw as raw
    LIMIT 100
    """
    whois_result = await client.execute_read(whois_query, {"project_id": project_id})
    whois_entries = [
        WhoisEntry(domain_name=r["domain_name"], raw=r.get("raw"))
        for r in whois_result
    ]
    shodan_query = """
    MATCH (s:ShodanData {project_id: $project_id})
    RETURN s.ip as ip, s.data_json as data_json
    LIMIT 100
    """
    shodan_result = await client.execute_read(shodan_query, {"project_id": project_id})
    shodan_entries = [
        ShodanEntry(ip=r["ip"], data_json=r.get("data_json"))
        for r in shodan_result
    ]
    
    # Calculate risk score (0-100)
    critical_count = vulns.get("critical", 0)
    high_count = vulns.get("high", 0)
    medium_count = vulns.get("medium", 0)
    low_count = vulns.get("low", 0)
    
    risk_score = min(100, (
        critical_count * 25 +
        high_count * 10 +
        medium_count * 3 +
        low_count * 1
    ))
    
    if risk_score >= 75:
        risk_level = "Critical"
    elif risk_score >= 50:
        risk_level = "High"
    elif risk_score >= 25:
        risk_level = "Medium"
    elif risk_score > 0:
        risk_level = "Low"
    else:
        risk_level = "None"
    
    return ProjectReportResponse(
        project_id=project_id,
        project_name=project_data.get("name", "Unknown"),
        generated_at=datetime.now(timezone.utc).isoformat(),
        scope=project_data.get("scope", []),
        assets=AssetSummary(
            domains=assets.get("domains", 0),
            subdomains=assets.get("subdomains", 0),
            ips=assets.get("ips", 0),
            ports=assets.get("ports", 0),
            urls=assets.get("urls", 0),
            technologies=assets.get("technologies", 0),
        ),
        vulnerabilities=VulnerabilitySummary(
            total=vulns.get("total", 0),
            critical=vulns.get("critical", 0),
            high=vulns.get("high", 0),
            medium=vulns.get("medium", 0),
            low=vulns.get("low", 0),
            info=vulns.get("info", 0),
        ),
        scans=ScanSummary(
            total=scans.get("total", 0),
            completed=scans.get("completed", 0),
            failed=scans.get("failed", 0),
            running=scans.get("running", 0),
        ),
        top_vulnerabilities=top_vulns,
        top_technologies=top_techs,
        risk_score=risk_score,
        risk_level=risk_level,
        whois_entries=whois_entries,
        shodan_entries=shodan_entries,
    )


@router.get(
    "/scan/{scan_id}",
    response_model=ScanReportResponse,
    summary="Generate Scan Report",
    description="Generate a report for a specific scan.",
)
async def generate_scan_report(
    scan_id: str,
    project_id: str = Query(..., description="Project ID"),
    project: Annotated[dict, Depends(ProjectAccess())] = None,
) -> ScanReportResponse:
    """Generate a scan report."""
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
    
    # Get discovered assets
    assets_query = """
    MATCH (scan:Scan {scan_id: $scan_id})-[:DISCOVERED]->(n)
    WITH labels(n) as node_labels, n
    RETURN 
        sum(CASE WHEN 'Subdomain' IN node_labels THEN 1 ELSE 0 END) as subdomains,
        sum(CASE WHEN 'IP' IN node_labels THEN 1 ELSE 0 END) as ips,
        sum(CASE WHEN 'Port' IN node_labels THEN 1 ELSE 0 END) as ports,
        sum(CASE WHEN 'URL' IN node_labels THEN 1 ELSE 0 END) as urls,
        sum(CASE WHEN 'Technology' IN node_labels THEN 1 ELSE 0 END) as technologies
    """
    assets_result = await client.execute_read(assets_query, {"scan_id": scan_id})
    assets = assets_result[0] if assets_result else {}
    
    # Get vulnerabilities for this scan
    vuln_query = """
    MATCH (scan:Scan {scan_id: $scan_id})-[:DISCOVERED]->(v:Vulnerability)
    RETURN v
    ORDER BY 
        CASE v.severity 
            WHEN 'critical' THEN 0 
            WHEN 'high' THEN 1 
            WHEN 'medium' THEN 2 
            ELSE 3 
        END
    """
    vuln_result = await client.execute_read(vuln_query, {"scan_id": scan_id})
    
    vulnerability_list = []
    vuln_counts = {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    
    for r in vuln_result:
        v = r["v"]
        severity = v.get("severity", "unknown")
        vuln_counts["total"] += 1
        if severity in vuln_counts:
            vuln_counts[severity] += 1
        
        vulnerability_list.append({
            "name": v.get("name", "Unknown"),
            "severity": severity,
            "matched_at": v.get("matched_at", ""),
            "cve_id": v.get("cve_id"),
            "description": v.get("description"),
        })
    
    # Generate findings summary
    findings_parts = []
    if vuln_counts["critical"] > 0:
        findings_parts.append(f"{vuln_counts['critical']} critical")
    if vuln_counts["high"] > 0:
        findings_parts.append(f"{vuln_counts['high']} high")
    if vuln_counts["medium"] > 0:
        findings_parts.append(f"{vuln_counts['medium']} medium")
    if vuln_counts["low"] > 0:
        findings_parts.append(f"{vuln_counts['low']} low")
    
    if findings_parts:
        findings_summary = f"Found {', '.join(findings_parts)} severity vulnerabilities."
    else:
        findings_summary = "No vulnerabilities found in this scan."
    
    # Extended recon: WHOIS and Shodan discovered by this scan
    whois_scan_query = """
    MATCH (scan:Scan {scan_id: $scan_id})-[:DISCOVERED]->(w:WhoisData)
    RETURN w.domain_name as domain_name, w.raw as raw
    """
    whois_scan_result = await client.execute_read(whois_scan_query, {"scan_id": scan_id})
    whois_entries = [
        WhoisEntry(domain_name=r["domain_name"], raw=r.get("raw"))
        for r in whois_scan_result
    ]
    shodan_scan_query = """
    MATCH (scan:Scan {scan_id: $scan_id})-[:DISCOVERED]->(s:ShodanData)
    RETURN s.ip as ip, s.data_json as data_json
    """
    shodan_scan_result = await client.execute_read(shodan_scan_query, {"scan_id": scan_id})
    shodan_entries = [
        ShodanEntry(ip=r["ip"], data_json=r.get("data_json"))
        for r in shodan_scan_result
    ]
    
    return ScanReportResponse(
        scan_id=scan_id,
        target=scan.get("target", ""),
        scan_type=scan.get("scan_type", ""),
        status=scan.get("status", ""),
        started_at=scan.get("started_at"),
        completed_at=scan.get("completed_at"),
        duration_seconds=scan.get("duration_seconds"),
        generated_at=datetime.now(timezone.utc).isoformat(),
        assets=AssetSummary(
            domains=0,
            subdomains=assets.get("subdomains", 0),
            ips=assets.get("ips", 0),
            ports=assets.get("ports", 0),
            urls=assets.get("urls", 0),
            technologies=assets.get("technologies", 0),
        ),
        vulnerabilities=VulnerabilitySummary(**vuln_counts),
        vulnerability_list=vulnerability_list,
        findings_summary=findings_summary,
        whois_entries=whois_entries,
        shodan_entries=shodan_entries,
    )
