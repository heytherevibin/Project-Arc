"""
GAU MCP Server

URL discovery from Wayback Machine, Common Crawl, and other sources.
Runs the real gau (GetAllURLs) or getallurls binary; no mocks.
"""

import asyncio
import os
from typing import Any

from fastapi import FastAPI
from pydantic import BaseModel, ConfigDict, Field


app = FastAPI(
    title="GAU MCP Server",
    description="URL discovery via GAU (GetAllURLs) from Wayback, Common Crawl, etc.",
    version="1.0.0",
)


class GauRequest(BaseModel):
    """Request model for GAU URL discovery."""
    model_config = ConfigDict(extra="ignore", populate_by_name=True)

    domain: str = Field(..., description="Target domain to fetch URLs for")
    timeout: int = Field(300, ge=30, le=3600, description="Timeout in seconds")


class GauResponse(BaseModel):
    """Response model for GAU scan."""
    success: bool
    urls: list[str] = []
    count: int = 0
    error: str | None = None


def _gau_binary() -> str | None:
    """Return path to gau binary (gau or getallurls on Kali). No hardcoding; check PATH or GAU_BINARY env."""
    import shutil
    path = os.environ.get("GAU_BINARY", "").strip()
    if path and shutil.which(path):
        return path
    for name in ("gau", "getallurls"):
        if shutil.which(name):
            return name
    return None


@app.get("/")
async def root() -> dict[str, str]:
    """Root endpoint to verify this is the GAU MCP server."""
    return {"tool": "gau", "path": "/tools/gau_scan", "status": "ok"}


@app.get("/health")
async def health_check() -> dict[str, str]:
    """Health check endpoint."""
    binary = _gau_binary()
    return {"status": "healthy", "tool": "gau", "binary": binary or "not found"}


@app.post("/tools/gau_scan", response_model=GauResponse)
async def gau_scan(request: GauRequest) -> GauResponse:
    """
    Execute GAU URL discovery for the given domain.
    Runs the real gau/getallurls binary; returns discovered URLs.
    """
    binary = _gau_binary()
    if not binary:
        return GauResponse(
            success=False,
            error="GAU not installed: neither 'gau' nor 'getallurls' found in PATH. Install from https://github.com/lc/gau/releases or apt install getallurls (Kali).",
        )

    try:
        # gau <domain> outputs one URL per line; getallurls same
        cmd = [binary, request.domain, "--threads", "5"]
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=request.timeout,
            )
        except asyncio.TimeoutError:
            process.kill()
            await process.wait()
            return GauResponse(success=False, error=f"GAU timed out after {request.timeout} seconds")

        if process.returncode != 0:
            err = (stderr or b"").decode("utf-8", errors="replace").strip()
            return GauResponse(success=False, error=f"GAU failed: {err[:500]}" if err else "GAU exited with non-zero code")

        output = (stdout or b"").decode("utf-8", errors="replace")
        urls = [line.strip() for line in output.splitlines() if line.strip()]
        # Deduplicate and sort
        seen: set[str] = set()
        unique: list[str] = []
        for u in urls:
            if u and u not in seen:
                seen.add(u)
                unique.append(u)
        unique.sort()
        return GauResponse(success=True, urls=unique, count=len(unique))
    except FileNotFoundError:
        return GauResponse(success=False, error="GAU binary not found or not executable")
    except Exception as e:
        return GauResponse(success=False, error=str(e))


@app.get("/tools/gau_scan/schema")
async def get_schema() -> dict[str, Any]:
    """Return the tool schema for MCP."""
    return {
        "name": "gau_scan",
        "description": "URL discovery using GAU (Wayback, Common Crawl, etc.)",
        "inputSchema": {
            "type": "object",
            "properties": {
                "domain": {"type": "string", "description": "Target domain"},
                "timeout": {"type": "integer", "description": "Timeout in seconds", "default": 300},
            },
            "required": ["domain"],
        },
    }
