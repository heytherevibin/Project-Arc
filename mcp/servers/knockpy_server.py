"""
Knockpy MCP Server

Active subdomain brute-force. Runs the real knockpy CLI or uses DNS resolution with a wordlist; no mocks.
"""

import asyncio
import os
import subprocess
from typing import Any

from fastapi import FastAPI
from pydantic import BaseModel, ConfigDict, Field


app = FastAPI(
    title="Knockpy MCP Server",
    description="Active subdomain brute-force via Knockpy or DNS wordlist",
    version="1.0.0",
)


class KnockpyRequest(BaseModel):
    """Request model for Knockpy scan."""
    model_config = ConfigDict(extra="ignore", populate_by_name=True)

    domain: str = Field(..., description="Target domain")
    wordlist: str | None = Field(None, description="Path to wordlist (optional)")
    timeout: int = Field(300, ge=30, le=3600, description="Timeout in seconds")


class KnockpyResponse(BaseModel):
    """Response model for Knockpy scan."""
    success: bool
    subdomains: list[str] = []
    count: int = 0
    error: str | None = None


def _knockpy_available() -> bool:
    """Check if knockpy CLI is available (no hardcoding path)."""
    try:
        subprocess.run(
            ["knockpy", "--help"],
            capture_output=True,
            timeout=5,
        )
        return True
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False
    except Exception:
        return False


def _run_knockpy(domain: str, wordlist_path: str | None, timeout: int) -> tuple[bool, list[str], str | None]:
    """Run knockpy synchronously; returns (success, subdomains, error)."""
    cmd = ["knockpy", domain]
    if wordlist_path and os.path.isfile(wordlist_path):
        cmd.extend(["-w", wordlist_path])
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        if result.returncode != 0:
            return False, [], (result.stderr or result.stdout or "knockpy failed")[:500]
        # Parse stdout for subdomains (knockpy outputs subdomain per line or JSON)
        subdomains = []
        for line in (result.stdout or "").splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "." in line and domain in line:
                subdomains.append(line.split()[0] if " " in line else line)
        return True, list(dict.fromkeys(subdomains)), None
    except subprocess.TimeoutExpired:
        return False, [], f"knockpy timed out after {timeout}s"
    except FileNotFoundError:
        return False, [], "knockpy not installed (pip install knockpy or install from repo)"
    except Exception as e:
        return False, [], str(e)


@app.get("/")
async def root() -> dict[str, str]:
    """Root endpoint to verify this is the Knockpy MCP server."""
    return {"tool": "knockpy", "path": "/tools/knockpy_scan", "status": "ok"}


@app.get("/health")
async def health_check() -> dict[str, str]:
    """Health check endpoint."""
    return {"status": "healthy", "tool": "knockpy", "knockpy_available": _knockpy_available()}


@app.post("/tools/knockpy_scan", response_model=KnockpyResponse)
async def knockpy_scan(request: KnockpyRequest) -> KnockpyResponse:
    """
    Run subdomain brute-force using Knockpy.
    Executes the real knockpy binary; no mocks.
    """
    if not _knockpy_available():
        return KnockpyResponse(
            success=False,
            error="Knockpy not installed. Install with: pip install knockpy (or from https://github.com/guelfoweb/knock)",
        )

    domain = (request.domain or "").strip()
    if not domain:
        return KnockpyResponse(success=False, error="domain is required")

    loop = asyncio.get_event_loop()
    success, subdomains, err = await asyncio.wait_for(
        loop.run_in_executor(None, _run_knockpy, domain, request.wordlist, request.timeout),
        timeout=float(request.timeout) + 10,
    )
    if not success:
        return KnockpyResponse(success=False, error=err)
    return KnockpyResponse(success=True, subdomains=sorted(subdomains), count=len(subdomains))


@app.get("/tools/knockpy_scan/schema")
async def get_schema() -> dict[str, Any]:
    """Return the tool schema for MCP."""
    return {
        "name": "knockpy_scan",
        "description": "Active subdomain brute-force using Knockpy",
        "inputSchema": {
            "type": "object",
            "properties": {
                "domain": {"type": "string", "description": "Target domain"},
                "wordlist": {"type": "string", "description": "Path to wordlist (optional)"},
                "timeout": {"type": "integer", "default": 300},
            },
            "required": ["domain"],
        },
    }
}
