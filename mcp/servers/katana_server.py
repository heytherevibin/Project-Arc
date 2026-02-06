"""
Katana MCP Server

FastMCP server for web crawling.
"""

import asyncio
import json
from typing import Any

from fastapi import FastAPI
from pydantic import BaseModel, ConfigDict, Field


app = FastAPI(title="Katana MCP Server", version="1.0.0")


class KatanaRequest(BaseModel):
    model_config = ConfigDict(extra="ignore")

    urls: list[str] = Field(..., min_length=1)
    depth: int = Field(3, ge=1, le=10)
    js_crawl: bool = Field(True)
    timeout: int = Field(600, ge=60, le=3600)


class KatanaResponse(BaseModel):
    success: bool
    discovered_urls: list[str] = []
    js_files: list[str] = []
    total_urls: int = 0
    error: str | None = None


@app.get("/")
async def root() -> dict[str, str]:
    return {"tool": "katana", "path": "/tools/katana_crawl", "status": "ok"}


@app.get("/health")
async def health_check() -> dict[str, str]:
    return {"status": "healthy", "tool": "katana"}


@app.post("/tools/katana_crawl", response_model=KatanaResponse)
async def katana_crawl(request: KatanaRequest) -> KatanaResponse:
    try:
        cmd = [
            "katana",
            "-silent",
            "-json",
            "-depth", str(request.depth),
        ]
        
        if request.js_crawl:
            cmd.append("-js-crawl")
        
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
            return KatanaResponse(success=False, error="Timeout")
        
        discovered_urls: set[str] = set()
        js_files: set[str] = set()
        output = stdout.decode("utf-8", errors="replace")
        
        for line in output.strip().split("\n"):
            if not line:
                continue
            try:
                data = json.loads(line)
                url = data.get("request", {}).get("url") or data.get("url", "")
                if url:
                    discovered_urls.add(url)
                    if url.endswith(".js") or ".js?" in url:
                        js_files.add(url)
            except json.JSONDecodeError:
                url = line.strip()
                if url.startswith(("http://", "https://")):
                    discovered_urls.add(url)
        
        return KatanaResponse(
            success=True,
            discovered_urls=sorted(list(discovered_urls)),
            js_files=sorted(list(js_files)),
            total_urls=len(discovered_urls),
        )
    
    except FileNotFoundError:
        return KatanaResponse(success=False, error="Katana not installed")
    except Exception as e:
        return KatanaResponse(success=False, error=str(e))
