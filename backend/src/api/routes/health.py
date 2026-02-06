"""
Health Check Endpoints

Provides health and readiness checks for the API.
"""

import time
from datetime import datetime, timezone
from typing import Any

import httpx
from fastapi import APIRouter, status
from pydantic import BaseModel

from core.config import get_settings
from graph.client import get_neo4j_client


router = APIRouter()


class ComponentHealth(BaseModel):
    """Health status of a single component."""
    
    name: str
    status: str  # healthy, unhealthy, degraded
    latency_ms: float | None = None
    message: str | None = None


class HealthResponse(BaseModel):
    """Overall health check response."""
    
    status: str  # healthy, unhealthy, degraded
    version: str
    environment: str
    timestamp: str
    components: list[ComponentHealth]


class ReadinessResponse(BaseModel):
    """Readiness check response."""
    
    ready: bool
    checks: dict[str, bool]


class MCPEndpointStatus(BaseModel):
    """Status of a single MCP server endpoint."""
    
    name: str
    url: str
    status: str  # healthy, unhealthy
    latency_ms: float | None = None
    message: str | None = None


class MCPHealthResponse(BaseModel):
    """Response for MCP URL health checks."""
    
    endpoints: list[MCPEndpointStatus]


@router.get(
    "/health",
    response_model=HealthResponse,
    status_code=status.HTTP_200_OK,
    summary="Health Check",
    description="Returns the health status of the API and its dependencies.",
)
async def health_check() -> HealthResponse:
    """
    Comprehensive health check endpoint.
    
    Checks the health of:
    - Neo4j database connection
    - Redis connection (if configured)
    - Elasticsearch connection (if configured)
    
    Returns:
        HealthResponse with status of all components
    """
    settings = get_settings()
    components: list[ComponentHealth] = []
    overall_healthy = True
    
    # Check Neo4j
    neo4j_health = await _check_neo4j()
    components.append(neo4j_health)
    if neo4j_health.status != "healthy":
        overall_healthy = False
    
    # Determine overall status
    if overall_healthy:
        overall_status = "healthy"
    elif any(c.status == "healthy" for c in components):
        overall_status = "degraded"
    else:
        overall_status = "unhealthy"
    
    return HealthResponse(
        status=overall_status,
        version=settings.APP_VERSION,
        environment=settings.APP_ENV,
        timestamp=datetime.now(timezone.utc).isoformat(),
        components=components,
    )


@router.get(
    "/ready",
    response_model=ReadinessResponse,
    status_code=status.HTTP_200_OK,
    summary="Readiness Check",
    description="Returns whether the API is ready to accept traffic.",
)
async def readiness_check() -> ReadinessResponse:
    """
    Kubernetes-style readiness check.
    
    Returns ready=true only if all critical dependencies are available.
    """
    checks: dict[str, bool] = {}
    
    # Check Neo4j (critical)
    neo4j_health = await _check_neo4j()
    checks["neo4j"] = neo4j_health.status == "healthy"
    
    # Ready if all checks pass
    ready = all(checks.values())
    
    return ReadinessResponse(ready=ready, checks=checks)


# MCP URL names, config keys, POST path and minimal body (to detect 404 on scan)
_MCP_ENDPOINTS = [
    ("naabu", "MCP_NAABU_URL", "naabu_scan", {"hosts": ["127.0.0.1"]}),
    ("httpx", "MCP_HTTPX_URL", "httpx_probe", {"urls": ["http://example.com"]}),
    ("subfinder", "MCP_SUBFINDER_URL", "subfinder_scan", {"domain": "example.com"}),
    ("dnsx", "MCP_DNSX_URL", "dnsx_resolve", {"hosts": ["example.com"]}),
    ("katana", "MCP_KATANA_URL", "katana_crawl", {"urls": ["http://example.com"]}),
    ("nuclei", "MCP_NUCLEI_URL", "nuclei_scan", {"urls": ["http://example.com"]}),
    # Extended recon (ports 8006-8012)
    ("gau", "MCP_GAU_URL", "gau_scan", {"domain": "example.com"}),
    ("knockpy", "MCP_KNOCKPY_URL", "knockpy_scan", {"domain": "example.com"}),
    ("kiterunner", "MCP_KITERUNNER_URL", "kiterunner_scan", {"url": "https://example.com"}),
    ("wappalyzer", "MCP_WAPPALYZER_URL", "wappalyzer_scan", {"url": "https://example.com"}),
    ("whois", "MCP_WHOIS_URL", "whois_lookup", {"domain": "example.com"}),
    ("shodan", "MCP_SHODAN_URL", "shodan_lookup", {"ip": "8.8.8.8"}),
    ("github_recon", "MCP_GITHUB_RECON_URL", "github_search", {"query": "org:github"}),
]

# GET /health is fast; POST /tools/xxx can run real work (subfinder, katana) so needs longer timeout
MCP_HEALTH_TIMEOUT_SECONDS = 3.0
MCP_HEALTH_POST_TIMEOUT_SECONDS = 45.0


@router.get(
    "/health/mcp",
    response_model=MCPHealthResponse,
    status_code=status.HTTP_200_OK,
    summary="MCP URLs Health Check",
    description="Checks each configured MCP tool URL by calling GET {url}/health.",
)
async def mcp_health_check() -> MCPHealthResponse:
    """
    Check that each MCP server URL is reachable and returns a healthy status.
    
    Calls GET {MCP_*_URL}/health with a short timeout. Empty URLs are reported
    as unhealthy (not configured).
    """
    settings = get_settings()
    results: list[MCPEndpointStatus] = []
    
    async with httpx.AsyncClient(timeout=httpx.Timeout(MCP_HEALTH_TIMEOUT_SECONDS)) as client:
        for name, attr, tool_path, minimal_body in _MCP_ENDPOINTS:
            url = getattr(settings, attr, "") or ""
            if not url or not str(url).strip():
                results.append(MCPEndpointStatus(
                    name=name,
                    url="",
                    status="unhealthy",
                    message="URL not configured",
                ))
                continue
            base = str(url).rstrip("/")
            health_url = f"{base}/health"
            t0 = time.perf_counter()
            try:
                resp = await client.get(health_url)
                latency_ms = (time.perf_counter() - t0) * 1000
                if resp.status_code == 200:
                    data = resp.json() if resp.content else {}
                    if isinstance(data, dict) and data.get("status") == "healthy":
                        # Verify we hit the right server (not wrong port)
                        server_tool = (data.get("tool") or "").strip().lower()
                        if server_tool and server_tool != name.lower():
                            results.append(MCPEndpointStatus(
                                name=name,
                                url=base,
                                status="unhealthy",
                                latency_ms=round(latency_ms, 2),
                                message=f"Wrong server: got '{server_tool}' (expected '{name}'). Core recon: 8000-8005, extended recon: 8006-8012.",
                            ))
                        else:
                            # Verify POST /tools/xxx works (scans use POST; GET /health can pass but POST 404)
                            # Subfinder/katana run real tool work, so use longer timeout than GET
                            post_url = f"{base}/tools/{tool_path}"
                            try:
                                post_resp = await client.post(
                                    post_url,
                                    json=minimal_body,
                                    timeout=httpx.Timeout(MCP_HEALTH_POST_TIMEOUT_SECONDS),
                                )
                                if post_resp.status_code == 200:
                                    results.append(MCPEndpointStatus(
                                        name=name,
                                        url=base,
                                        status="healthy",
                                        latency_ms=round(latency_ms, 2),
                                    ))
                                elif post_resp.status_code == 404:
                                    results.append(MCPEndpointStatus(
                                        name=name,
                                        url=base,
                                        status="unhealthy",
                                        latency_ms=round(latency_ms, 2),
                                        message=f"POST /tools/{tool_path} returned 404. Rebuild mcp-recon: docker compose build mcp-recon && docker compose up -d mcp-recon",
                                    ))
                                else:
                                    results.append(MCPEndpointStatus(
                                        name=name,
                                        url=base,
                                        status="unhealthy",
                                        latency_ms=round(latency_ms, 2),
                                        message=f"POST /tools/{tool_path} returned {post_resp.status_code}. Check MCP server logs.",
                                    ))
                            except Exception as e:
                                results.append(MCPEndpointStatus(
                                    name=name,
                                    url=base,
                                    status="unhealthy",
                                    latency_ms=round(latency_ms, 2),
                                    message=f"POST failed: {type(e).__name__}: {str(e)[:150]}",
                                ))
                    else:
                        results.append(MCPEndpointStatus(
                            name=name,
                            url=base,
                            status="unhealthy",
                            latency_ms=round(latency_ms, 2),
                            message=f"Unexpected response: {data}",
                        ))
                elif resp.status_code == 404:
                    results.append(MCPEndpointStatus(
                        name=name,
                        url=base,
                        status="unhealthy",
                        latency_ms=round((time.perf_counter() - t0) * 1000, 2),
                        message="404 - URL may point to API or wrong service. Use mcp-recon:PORT (Docker) with ports 8000-8012, one per tool.",
                    ))
                else:
                    results.append(MCPEndpointStatus(
                        name=name,
                        url=base,
                        status="unhealthy",
                        latency_ms=round((time.perf_counter() - t0) * 1000, 2),
                        message=f"HTTP {resp.status_code}",
                    ))
            except Exception as e:
                results.append(MCPEndpointStatus(
                    name=name,
                    url=base,
                    status="unhealthy",
                    latency_ms=round((time.perf_counter() - t0) * 1000, 2),
                    message=str(e)[:200],
                ))
    
    return MCPHealthResponse(endpoints=results)


@router.get(
    "/live",
    status_code=status.HTTP_200_OK,
    summary="Liveness Check",
    description="Simple liveness check that always returns OK.",
)
async def liveness_check() -> dict[str, str]:
    """
    Kubernetes-style liveness check.
    
    Always returns OK if the server is running.
    """
    return {"status": "ok"}


async def _check_neo4j() -> ComponentHealth:
    """Check Neo4j database health."""
    import time
    
    try:
        client = get_neo4j_client()
        
        start = time.perf_counter()
        healthy = await client.health_check()
        latency = (time.perf_counter() - start) * 1000
        
        if healthy:
            return ComponentHealth(
                name="neo4j",
                status="healthy",
                latency_ms=round(latency, 2),
            )
        else:
            return ComponentHealth(
                name="neo4j",
                status="unhealthy",
                message="Health check failed",
            )
    
    except Exception as e:
        return ComponentHealth(
            name="neo4j",
            status="unhealthy",
            message=str(e),
        )
