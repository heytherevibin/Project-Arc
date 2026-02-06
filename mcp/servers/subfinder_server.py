"""
Subfinder MCP Server

FastMCP server for passive subdomain discovery.
"""

import asyncio
import json
import subprocess
from typing import Any

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, ConfigDict, Field


app = FastAPI(
    title="Subfinder MCP Server",
    description="Passive subdomain discovery via Subfinder",
    version="1.0.0",
)


class SubfinderRequest(BaseModel):
    """Request model for Subfinder scan."""
    model_config = ConfigDict(extra="ignore", populate_by_name=True)

    domain: str = Field(..., description="Target domain")
    all_sources: bool = Field(True, alias="all", description="Use all sources")
    recursive: bool = Field(False, description="Recursive subdomain discovery")
    timeout: int = Field(300, ge=30, le=3600, description="Timeout in seconds")


class SubfinderResponse(BaseModel):
    """Response model for Subfinder scan."""
    
    success: bool
    subdomains: list[str] = []
    count: int = 0
    error: str | None = None


@app.get("/")
async def root() -> dict[str, str]:
    """Root endpoint to verify this is the Subfinder MCP server."""
    return {"tool": "subfinder", "path": "/tools/subfinder_scan", "status": "ok"}


@app.get("/health")
async def health_check() -> dict[str, str]:
    """Health check endpoint."""
    return {"status": "healthy", "tool": "subfinder"}


@app.post("/tools/subfinder_scan", response_model=SubfinderResponse)
async def subfinder_scan(request: SubfinderRequest) -> SubfinderResponse:
    """
    Execute Subfinder subdomain enumeration.
    
    Args:
        request: Scan request parameters
    
    Returns:
        Discovered subdomains
    """
    try:
        # Build command
        cmd = [
            "subfinder",
            "-d", request.domain,
            "-silent",
            "-json",
            "-o", "-",
        ]
        
        if request.all_sources:
            cmd.append("-all")
        
        if request.recursive:
            cmd.append("-recursive")
        
        # Execute command
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
            return SubfinderResponse(
                success=False,
                error=f"Scan timed out after {request.timeout} seconds",
            )
        
        if process.returncode != 0:
            error_msg = stderr.decode("utf-8", errors="replace")
            return SubfinderResponse(
                success=False,
                error=f"Subfinder failed: {error_msg[:500]}",
            )
        
        # Parse output
        subdomains = set()
        output = stdout.decode("utf-8", errors="replace")
        
        for line in output.strip().split("\n"):
            if not line:
                continue
            
            try:
                data = json.loads(line)
                if isinstance(data, dict) and "host" in data:
                    subdomains.add(data["host"].lower())
                elif isinstance(data, str):
                    subdomains.add(data.lower())
            except json.JSONDecodeError:
                # Plain text line
                subdomain = line.strip().lower()
                if subdomain and "." in subdomain:
                    subdomains.add(subdomain)
        
        return SubfinderResponse(
            success=True,
            subdomains=sorted(list(subdomains)),
            count=len(subdomains),
        )
    
    except FileNotFoundError:
        return SubfinderResponse(
            success=False,
            error="Subfinder not installed or not in PATH",
        )
    
    except Exception as e:
        return SubfinderResponse(
            success=False,
            error=str(e),
        )


@app.get("/tools/subfinder_scan/schema")
async def get_schema() -> dict[str, Any]:
    """Return the tool schema for MCP."""
    return {
        "name": "subfinder_scan",
        "description": "Passive subdomain discovery using Subfinder",
        "inputSchema": {
            "type": "object",
            "properties": {
                "domain": {
                    "type": "string",
                    "description": "Target domain to enumerate subdomains for",
                },
                "all": {
                    "type": "boolean",
                    "description": "Use all passive sources",
                    "default": True,
                },
                "recursive": {
                    "type": "boolean",
                    "description": "Enable recursive subdomain discovery",
                    "default": False,
                },
                "timeout": {
                    "type": "integer",
                    "description": "Timeout in seconds",
                    "default": 300,
                    "minimum": 30,
                    "maximum": 3600,
                },
            },
            "required": ["domain"],
        },
    }
