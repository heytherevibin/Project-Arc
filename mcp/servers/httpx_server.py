"""
Httpx MCP Server

FastMCP server for HTTP probing and technology detection.
"""

import asyncio
import json
from typing import Any

from fastapi import FastAPI
from pydantic import BaseModel, ConfigDict, Field


app = FastAPI(
    title="Httpx MCP Server",
    description="HTTP probing via Httpx",
    version="1.0.0",
)


class HttpxRequest(BaseModel):
    """Request model for Httpx probe."""
    model_config = ConfigDict(extra="ignore")

    urls: list[str] = Field(..., min_length=1, description="URLs to probe")
    follow_redirects: bool = Field(True, description="Follow redirects")
    threads: int = Field(50, ge=1, le=200, description="Concurrent threads")
    tech_detect: bool = Field(True, description="Detect technologies")
    timeout: int = Field(600, ge=60, le=3600, description="Timeout in seconds")


class ProbeResult(BaseModel):
    """Single probe result."""
    
    url: str
    status_code: int | None = None
    title: str | None = None
    content_type: str | None = None
    content_length: int | None = None
    server: str | None = None
    technologies: list[str] = []


class HttpxResponse(BaseModel):
    """Response model for Httpx probe."""
    
    success: bool
    probed: list[ProbeResult] = []
    live_urls: list[str] = []
    probed_count: int = 0
    live_count: int = 0
    error: str | None = None


@app.get("/")
async def root() -> dict[str, str]:
    return {"tool": "httpx", "path": "/tools/httpx_probe", "status": "ok"}


@app.get("/health")
async def health_check() -> dict[str, str]:
    """Health check endpoint."""
    return {"status": "healthy", "tool": "httpx"}


@app.post("/tools/httpx_probe", response_model=HttpxResponse)
async def httpx_probe(request: HttpxRequest) -> HttpxResponse:
    """Execute Httpx HTTP probing."""
    try:
        cmd = [
            "httpx",
            "-silent",
            "-json",
            "-threads", str(request.threads),
            "-status-code",
            "-title",
            "-content-length",
            "-content-type",
            "-server",
        ]
        
        if request.tech_detect:
            cmd.append("-tech-detect")
        
        if request.follow_redirects:
            cmd.append("-follow-redirects")
        
        input_data = "\n".join(request.urls)
        
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
            return HttpxResponse(success=False, error=f"Timeout after {request.timeout}s")
        
        probed: list[ProbeResult] = []
        live_urls: list[str] = []
        output = stdout.decode("utf-8", errors="replace")
        
        for line in output.strip().split("\n"):
            if not line:
                continue
            
            try:
                data = json.loads(line)
                url = data.get("url", "")
                status_code = data.get("status_code", 0)
                
                result = ProbeResult(
                    url=url,
                    status_code=status_code,
                    title=data.get("title", ""),
                    content_type=data.get("content_type", ""),
                    content_length=data.get("content_length"),
                    server=data.get("webserver", data.get("server", "")),
                    technologies=data.get("tech", []),
                )
                
                probed.append(result)
                
                if 200 <= status_code < 400:
                    live_urls.append(url)
            except json.JSONDecodeError:
                continue
        
        return HttpxResponse(
            success=True,
            probed=probed,
            live_urls=live_urls,
            probed_count=len(probed),
            live_count=len(live_urls),
        )
    
    except FileNotFoundError:
        return HttpxResponse(success=False, error="Httpx not installed")
    except Exception as e:
        return HttpxResponse(success=False, error=str(e))
