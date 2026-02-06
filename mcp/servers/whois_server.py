"""
Whois MCP Server

WHOIS lookups for domains. Uses python-whois for real lookups; no mocks.
"""

import asyncio
from typing import Any

from fastapi import FastAPI
from pydantic import BaseModel, ConfigDict, Field


app = FastAPI(
    title="Whois MCP Server",
    description="WHOIS lookups via python-whois",
    version="1.0.0",
)

try:
    import whois as whois_lib
    HAS_WHOIS = True
except ImportError:
    whois_lib = None
    HAS_WHOIS = False


class WhoisRequest(BaseModel):
    """Request model for WHOIS lookup."""
    model_config = ConfigDict(extra="ignore", populate_by_name=True)

    domain: str = Field(..., description="Domain to look up")


class WhoisResponse(BaseModel):
    """Response model for WHOIS lookup."""
    success: bool
    whois: dict[str, str] = {}
    raw: str | None = None
    error: str | None = None


def _whois_result_to_dict(w: Any) -> dict[str, str]:
    """Convert python-whois result to a serializable dict."""
    if w is None:
        return {}
    out: dict[str, str] = {}
    for k, v in w.__dict__.items():
        if k.startswith("_"):
            continue
        if v is None:
            out[k] = ""
        elif isinstance(v, (list, set)):
            out[k] = ", ".join(str(x) for x in v)
        elif isinstance(v, str):
            out[k] = v
        else:
            out[k] = str(v)
    return out


@app.get("/")
async def root() -> dict[str, str]:
    """Root endpoint to verify this is the Whois MCP server."""
    return {"tool": "whois", "path": "/tools/whois_lookup", "status": "ok"}


@app.get("/health")
async def health_check() -> dict[str, str]:
    """Health check endpoint."""
    return {"status": "healthy", "tool": "whois", "python_whois": "available" if HAS_WHOIS else "not installed"}


@app.post("/tools/whois_lookup", response_model=WhoisResponse)
async def whois_lookup(request: WhoisRequest) -> WhoisResponse:
    """
    Perform WHOIS lookup for the given domain.
    Uses python-whois library for real lookups.
    """
    if not HAS_WHOIS:
        return WhoisResponse(
            success=False,
            error="python-whois not installed. pip install python-whois",
        )

    domain = (request.domain or "").strip()
    if not domain:
        return WhoisResponse(success=False, error="domain is required")

    def _do_lookup() -> tuple[dict[str, str], str | None]:
        w = whois_lib.whois(domain)
        raw = str(w) if w else None
        return _whois_result_to_dict(w), raw

    try:
        # whois.whois() can block; run in executor
        loop = asyncio.get_event_loop()
        data, raw = await asyncio.wait_for(
            loop.run_in_executor(None, _do_lookup),
            timeout=30.0,
        )
        return WhoisResponse(success=True, whois=data, raw=raw)
    except asyncio.TimeoutError:
        return WhoisResponse(success=False, error="WHOIS lookup timed out")
    except Exception as e:
        return WhoisResponse(success=False, error=str(e))


@app.get("/tools/whois_lookup/schema")
async def get_schema() -> dict[str, Any]:
    """Return the tool schema for MCP."""
    return {
        "name": "whois_lookup",
        "description": "WHOIS lookup for a domain",
        "inputSchema": {
            "type": "object",
            "properties": {"domain": {"type": "string", "description": "Domain to look up"}},
            "required": ["domain"],
        },
    }
