"""
dnsx MCP Server

FastMCP server for DNS resolution.
"""

import asyncio
import json
from typing import Any

from fastapi import FastAPI
from pydantic import BaseModel, ConfigDict, Field


app = FastAPI(title="dnsx MCP Server", version="1.0.0")


class DnsxRequest(BaseModel):
    model_config = ConfigDict(extra="ignore")

    hosts: list[str] = Field(..., min_length=1)
    a: bool = Field(True, description="Resolve A records")
    aaaa: bool = Field(True, description="Resolve AAAA records")
    cname: bool = Field(True, description="Resolve CNAME records")
    timeout: int = Field(300, ge=30, le=1800)


class DnsxResponse(BaseModel):
    success: bool
    resolved: dict[str, list[str]] = {}
    resolved_count: int = 0
    error: str | None = None


@app.get("/")
async def root() -> dict[str, str]:
    return {"tool": "dnsx", "path": "/tools/dnsx_resolve", "status": "ok"}


@app.get("/health")
async def health_check() -> dict[str, str]:
    return {"status": "healthy", "tool": "dnsx"}


@app.post("/tools/dnsx_resolve", response_model=DnsxResponse)
async def dnsx_resolve(request: DnsxRequest) -> DnsxResponse:
    try:
        cmd = ["dnsx", "-silent", "-json", "-resp"]
        
        if request.a:
            cmd.append("-a")
        if request.aaaa:
            cmd.append("-aaaa")
        if request.cname:
            cmd.append("-cname")
        
        input_data = "\n".join(request.hosts)
        
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
            return DnsxResponse(success=False, error="Timeout")
        
        resolved: dict[str, list[str]] = {}
        output = stdout.decode("utf-8", errors="replace")
        
        for line in output.strip().split("\n"):
            if not line:
                continue
            try:
                data = json.loads(line)
                host = data.get("host", "").lower()
                if not host:
                    continue
                
                ips = []
                ips.extend(data.get("a", []))
                ips.extend(data.get("aaaa", []))
                
                if ips:
                    resolved[host] = list(set(ips))
            except json.JSONDecodeError:
                continue
        
        return DnsxResponse(
            success=True,
            resolved=resolved,
            resolved_count=len(resolved),
        )
    
    except FileNotFoundError:
        return DnsxResponse(success=False, error="dnsx not installed")
    except Exception as e:
        return DnsxResponse(success=False, error=str(e))
