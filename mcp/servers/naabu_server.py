"""
Naabu MCP Server

FastMCP server for fast port scanning.
"""

import asyncio
import json
from typing import Any

from fastapi import FastAPI
from pydantic import BaseModel, ConfigDict, Field


app = FastAPI(
    title="Naabu MCP Server",
    description="Fast port scanning via Naabu",
    version="1.0.0",
)


class NaabuRequest(BaseModel):
    """Request model for Naabu scan."""
    model_config = ConfigDict(extra="ignore")

    hosts: list[str] = Field(..., min_length=1, description="Target hosts or IPs")
    ports: str = Field("top-1000", description="Port specification")
    rate: int = Field(1000, ge=1, le=10000, description="Packets per second")
    scan_all_ips: bool = Field(True, description="Scan all IPs for hostname")
    timeout: int = Field(600, ge=60, le=3600, description="Timeout in seconds")


class NaabuResponse(BaseModel):
    """Response model for Naabu scan."""
    
    success: bool
    ports: dict[str, list[int]] = {}
    hosts_scanned: int = 0
    total_open_ports: int = 0
    error: str | None = None


@app.get("/")
async def root() -> dict[str, str]:
    return {"tool": "naabu", "path": "/tools/naabu_scan", "status": "ok"}


@app.get("/health")
async def health_check() -> dict[str, str]:
    """Health check endpoint."""
    return {"status": "healthy", "tool": "naabu"}


@app.post("/tools/naabu_scan", response_model=NaabuResponse)
async def naabu_scan(request: NaabuRequest) -> NaabuResponse:
    """
    Execute Naabu port scan.
    
    Args:
        request: Scan request parameters
    
    Returns:
        Discovered open ports per host
    """
    try:
        # Build command
        cmd = [
            "naabu",
            "-silent",
            "-json",
            "-rate", str(request.rate),
        ]
        
        # Port specification
        if request.ports == "top-1000":
            cmd.extend(["-top-ports", "1000"])
        elif request.ports == "top-100":
            cmd.extend(["-top-ports", "100"])
        else:
            cmd.extend(["-p", request.ports])
        
        if request.scan_all_ips:
            cmd.append("-scan-all-ips")
        
        # Create input data
        input_data = "\n".join(request.hosts)
        
        # Execute command
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        
        try:
            stdout, stderr = await asyncio.wait_for(
                process.communicate(input=input_data.encode()),
                timeout=request.timeout,
            )
        except asyncio.TimeoutError:
            process.kill()
            await process.wait()
            return NaabuResponse(
                success=False,
                error=f"Scan timed out after {request.timeout} seconds",
            )
        
        if process.returncode != 0:
            error_msg = stderr.decode("utf-8", errors="replace")
            return NaabuResponse(
                success=False,
                error=f"Naabu failed: {error_msg[:500]}",
            )
        
        # Parse output
        ports: dict[str, list[int]] = {}
        output = stdout.decode("utf-8", errors="replace")
        
        for line in output.strip().split("\n"):
            if not line:
                continue
            
            try:
                data = json.loads(line)
                host = data.get("host") or data.get("ip", "")
                port = data.get("port")
                
                if host and port:
                    if host not in ports:
                        ports[host] = []
                    if port not in ports[host]:
                        ports[host].append(port)
            except json.JSONDecodeError:
                # Try host:port format
                if ":" in line:
                    parts = line.strip().split(":")
                    if len(parts) == 2:
                        try:
                            host = parts[0]
                            port = int(parts[1])
                            if host not in ports:
                                ports[host] = []
                            if port not in ports[host]:
                                ports[host].append(port)
                        except ValueError:
                            continue
        
        # Sort ports
        for host in ports:
            ports[host].sort()
        
        total_ports = sum(len(p) for p in ports.values())
        
        return NaabuResponse(
            success=True,
            ports=ports,
            hosts_scanned=len(ports),
            total_open_ports=total_ports,
        )
    
    except FileNotFoundError:
        return NaabuResponse(
            success=False,
            error="Naabu not installed or not in PATH",
        )
    
    except Exception as e:
        return NaabuResponse(
            success=False,
            error=str(e),
        )


@app.get("/tools/naabu_scan/schema")
async def get_schema() -> dict[str, Any]:
    """Return the tool schema for MCP."""
    return {
        "name": "naabu_scan",
        "description": "Fast port scanning using Naabu",
        "inputSchema": {
            "type": "object",
            "properties": {
                "hosts": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Target hosts or IP addresses",
                },
                "ports": {
                    "type": "string",
                    "description": "Port specification (e.g., '80,443', '1-1000', 'top-1000')",
                    "default": "top-1000",
                },
                "rate": {
                    "type": "integer",
                    "description": "Packets per second rate limit",
                    "default": 1000,
                },
            },
            "required": ["hosts"],
        },
    }
