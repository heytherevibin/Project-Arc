"""
Kiterunner MCP Server

API endpoint discovery. Runs the real kr (kiterunner) binary; no mocks.
"""

import asyncio
import os
import shutil
from typing import Any

from fastapi import FastAPI
from pydantic import BaseModel, ConfigDict, Field


app = FastAPI(
    title="Kiterunner MCP Server",
    description="API endpoint discovery via Kiterunner (kr)",
    version="1.0.0",
)


class KiterunnerRequest(BaseModel):
    """Request model for Kiterunner scan."""
    model_config = ConfigDict(extra="ignore", populate_by_name=True)

    url: str = Field(..., description="Base URL to scan (e.g. https://api.example.com)")
    timeout: int = Field(600, ge=60, le=3600, description="Timeout in seconds")


class KiterunnerResponse(BaseModel):
    """Response model for Kiterunner scan."""
    success: bool
    endpoints: list[dict[str, str]] = []
    count: int = 0
    error: str | None = None


def _kr_binary() -> str | None:
    """Return kr or kiterunner binary from PATH or env. No hardcoding."""
    path = (os.environ.get("KITERUNNER_BINARY") or "").strip()
    if path and shutil.which(path):
        return path
    for name in ("kr", "kiterunner"):
        if shutil.which(name):
            return name
    return None


@app.get("/")
async def root() -> dict[str, str]:
    """Root endpoint to verify this is the Kiterunner MCP server."""
    return {"tool": "kiterunner", "path": "/tools/kiterunner_scan", "status": "ok"}


@app.get("/health")
async def health_check() -> dict[str, str]:
    """Health check endpoint."""
    return {"status": "healthy", "tool": "kiterunner", "binary": _kr_binary() or "not found"}


@app.post("/tools/kiterunner_scan", response_model=KiterunnerResponse)
async def kiterunner_scan(request: KiterunnerRequest) -> KiterunnerResponse:
    """
    Run API endpoint discovery using Kiterunner (kr).
    Executes the real kr binary against the given URL.
    """
    binary = _kr_binary()
    if not binary:
        return KiterunnerResponse(
            success=False,
            error="Kiterunner (kr) not found in PATH. Install from https://github.com/assetnote/kiterunner/releases and set KITERUNNER_BINARY or add to PATH.",
        )

    url = (request.url or "").strip().rstrip("/")
    if not url:
        return KiterunnerResponse(success=False, error="url is required")

    # kr scan <url> or kr <url> depending on version
    cmd = [binary, "scan", url]
    try:
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
            return KiterunnerResponse(success=False, error=f"Kiterunner timed out after {request.timeout}s")

        if process.returncode != 0:
            err = (stderr or b"").decode("utf-8", errors="replace").strip()
            return KiterunnerResponse(success=False, error=f"kr failed: {err[:500]}" if err else "kr exited non-zero")

        output = (stdout or b"").decode("utf-8", errors="replace")
        endpoints = []
        for line in output.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            # kr typically outputs method path [status] or similar
            parts = line.split()
            if len(parts) >= 2:
                method = parts[0] if parts[0].upper() in ("GET", "POST", "PUT", "DELETE", "PATCH") else "GET"
                path = parts[1] if len(parts) > 1 else line
                endpoints.append({"method": method, "path": path})
            else:
                endpoints.append({"method": "GET", "path": line})
        # Deduplicate by path
        seen = set()
        unique = []
        for e in endpoints:
            k = (e.get("method"), e.get("path"))
            if k not in seen:
                seen.add(k)
                unique.append(e)
        return KiterunnerResponse(success=True, endpoints=unique, count=len(unique))
    except FileNotFoundError:
        return KiterunnerResponse(success=False, error="kr binary not found")
    except Exception as e:
        return KiterunnerResponse(success=False, error=str(e))


@app.get("/tools/kiterunner_scan/schema")
async def get_schema() -> dict[str, Any]:
    """Return the tool schema for MCP."""
    return {
        "name": "kiterunner_scan",
        "description": "API endpoint discovery using Kiterunner",
        "inputSchema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Base URL to scan"},
                "timeout": {"type": "integer", "default": 600},
            },
            "required": ["url"],
        },
    }
}
