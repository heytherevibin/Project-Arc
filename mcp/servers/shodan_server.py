"""
Shodan MCP Server

Passive recon via Shodan InternetDB (no key) or Shodan API (with SHODAN_API_KEY).
Real HTTP requests only; no mocks.
"""

import os
from typing import Any

import httpx
from fastapi import FastAPI
from pydantic import BaseModel, ConfigDict, Field


app = FastAPI(
    title="Shodan MCP Server",
    description="Passive recon via Shodan InternetDB or Shodan API",
    version="1.0.0",
)

INTERNETDB_URL = "https://internetdb.shodan.io"
SHODAN_API_URL = "https://api.shodan.io"


class ShodanRequest(BaseModel):
    """Request model for Shodan lookup."""
    model_config = ConfigDict(extra="ignore", populate_by_name=True)

    ip: str | None = Field(None, description="IP address to look up (InternetDB or API)")
    domain: str | None = Field(None, description="Domain to resolve and look up (API only with key)")


class ShodanResponse(BaseModel):
    """Response model for Shodan lookup."""
    success: bool
    data: dict[str, Any] = {}
    error: str | None = None


@app.get("/")
async def root() -> dict[str, str]:
    """Root endpoint to verify this is the Shodan MCP server."""
    return {"tool": "shodan", "path": "/tools/shodan_lookup", "status": "ok"}


@app.get("/health")
async def health_check() -> dict[str, str]:
    """Health check endpoint."""
    return {"status": "healthy", "tool": "shodan"}


@app.post("/tools/shodan_lookup", response_model=ShodanResponse)
async def shodan_lookup(request: ShodanRequest) -> ShodanResponse:
    """
    Look up IP or domain using Shodan InternetDB (no key) or Shodan API (with key).
    Real HTTP requests to Shodan services.
    """
    ip = (request.ip or "").strip() if request.ip else ""
    domain = (request.domain or "").strip() if request.domain else ""
    api_key = (os.environ.get("SHODAN_API_KEY") or "").strip()

    if not ip and not domain:
        return ShodanResponse(success=False, error="Either 'ip' or 'domain' is required")

    # Prefer IP for InternetDB (no key required)
    if ip:
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                r = await client.get(f"{INTERNETDB_URL}/{ip}")
            if r.status_code == 200:
                data = r.json()
                return ShodanResponse(success=True, data=data)
            if r.status_code == 404:
                return ShodanResponse(success=True, data={"ip": ip, "message": "No data in InternetDB"})
            return ShodanResponse(success=False, error=f"InternetDB returned {r.status_code}: {r.text[:300]}")
        except httpx.HTTPError as e:
            return ShodanResponse(success=False, error=str(e))

    # Domain or IP with API: use Shodan API if key is set
    if domain and api_key:
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                r = await client.get(
                    f"{SHODAN_API_URL}/dns/resolve",
                    params={"key": api_key, "hostnames": domain},
                )
                if r.status_code != 200:
                    return ShodanResponse(success=False, error=f"Shodan API resolve: {r.status_code} {r.text[:300]}")
                j = r.json()
                if domain in j:
                    ip_from_domain = j[domain]
                    r2 = await client.get(f"{INTERNETDB_URL}/{ip_from_domain}")
                    if r2.status_code == 200:
                        return ShodanResponse(success=True, data={"domain": domain, "ip": ip_from_domain, **r2.json()})
                return ShodanResponse(success=True, data={"domain": domain, "resolved": j})
        except httpx.HTTPError as e:
            return ShodanResponse(success=False, error=str(e))

    if domain:
        return ShodanResponse(
            success=False,
            error="Domain lookups require SHODAN_API_KEY in environment. Set SHODAN_API_KEY in .env for Shodan API.",
        )
    return ShodanResponse(success=False, error="Provide 'ip' for InternetDB (no key) or 'domain' with SHODAN_API_KEY set.")


@app.get("/tools/shodan_lookup/schema")
async def get_schema() -> dict[str, Any]:
    """Return the tool schema for MCP."""
    return {
        "name": "shodan_lookup",
        "description": "Passive recon via Shodan InternetDB or Shodan API",
        "inputSchema": {
            "type": "object",
            "properties": {
                "ip": {"type": "string", "description": "IP to look up (InternetDB, no key)"},
                "domain": {"type": "string", "description": "Domain to resolve and look up (API with key)"},
            },
        },
    }
