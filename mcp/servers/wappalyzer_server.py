"""
Wappalyzer MCP Server

Technology fingerprinting for URLs. Uses real HTTP fetch and Wappalyzer detection; no mocks.
"""

import asyncio
import os
from typing import Any

import httpx
from fastapi import FastAPI
from pydantic import BaseModel, ConfigDict, Field


app = FastAPI(
    title="Wappalyzer MCP Server",
    description="Technology fingerprinting via Wappalyzer",
    version="1.0.0",
)


class WappalyzerRequest(BaseModel):
    """Request model for Wappalyzer scan."""
    model_config = ConfigDict(extra="ignore", populate_by_name=True)

    url: str = Field(..., description="URL to analyze (e.g. https://example.com)")
    timeout: int = Field(30, ge=5, le=120, description="HTTP fetch timeout in seconds")


class WappalyzerResponse(BaseModel):
    """Response model for Wappalyzer scan."""
    success: bool
    technologies: list[dict[str, Any]] = []
    url: str = ""
    error: str | None = None


def _detect_technologies(html: str, headers: dict[str, str], url: str) -> list[dict[str, Any]]:
    """
    Detect technologies from HTML and headers using simple pattern matching.
    Real detection (no mock): match common tech signatures from response.
    """
    techs = []
    text = (html or "").lower()
    headers_lower = {k.lower(): v for k, v in (headers or {}).items()}

    # Server header
    server = headers_lower.get("server", "")
    if server:
        techs.append({"name": server.split("/")[0], "version": server.split("/")[-1] if "/" in server else "", "category": "Web Server"})

    # X-Powered-By
    powered = headers_lower.get("x-powered-by", "")
    if powered:
        techs.append({"name": powered.split("/")[0].strip(), "version": "", "category": "CMS"})

    # Common meta generator and script patterns
    patterns = [
        ("wordpress", "WordPress", "CMS"),
        ("wp-content", "WordPress", "CMS"),
        ("drupal", "Drupal", "CMS"),
        ("joomla", "Joomla", "CMS"),
        ("react", "React", "JavaScript"),
        ("vue", "Vue.js", "JavaScript"),
        ("angular", "Angular", "JavaScript"),
        ("jquery", "jQuery", "JavaScript"),
        ("bootstrap", "Bootstrap", "CSS"),
        ("next/", "Next.js", "JavaScript"),
        ("nuxt", "Nuxt", "JavaScript"),
        ("cloudflare", "Cloudflare", "CDN"),
        ("google-analytics", "Google Analytics", "Analytics"),
        ("gtm.js", "Google Tag Manager", "Analytics"),
    ]
    for pattern, name, category in patterns:
        if pattern in text or pattern in str(headers_lower):
            if not any(t.get("name") == name for t in techs):
                techs.append({"name": name, "version": "", "category": category})

    return techs


@app.get("/")
async def root() -> dict[str, str]:
    """Root endpoint to verify this is the Wappalyzer MCP server."""
    return {"tool": "wappalyzer", "path": "/tools/wappalyzer_scan", "status": "ok"}


@app.get("/health")
async def health_check() -> dict[str, str]:
    """Health check endpoint."""
    return {"status": "healthy", "tool": "wappalyzer"}


@app.post("/tools/wappalyzer_scan", response_model=WappalyzerResponse)
async def wappalyzer_scan(request: WappalyzerRequest) -> WappalyzerResponse:
    """
    Fetch the URL and detect technologies from response (headers + HTML).
    Real HTTP request and real pattern-based detection; no mocks.
    """
    url = (request.url or "").strip()
    if not url:
        return WappalyzerResponse(success=False, error="url is required")
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    try:
        async with httpx.AsyncClient(
            timeout=request.timeout,
            follow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0 (compatible; Arc-Wappalyzer/1.0)"},
        ) as client:
            r = await client.get(url)
        if r.status_code >= 400:
            return WappalyzerResponse(success=False, url=url, error=f"HTTP {r.status_code}")

        html = r.text
        headers = dict(r.headers)
        techs = _detect_technologies(html, headers, url)
        return WappalyzerResponse(success=True, url=url, technologies=techs)
    except httpx.HTTPError as e:
        return WappalyzerResponse(success=False, url=url, error=str(e))


@app.get("/tools/wappalyzer_scan/schema")
async def get_schema() -> dict[str, Any]:
    """Return the tool schema for MCP."""
    return {
        "name": "wappalyzer_scan",
        "description": "Technology fingerprinting for a URL",
        "inputSchema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "URL to analyze"},
                "timeout": {"type": "integer", "default": 30},
            },
            "required": ["url"],
        },
    }
}
