"""
BloodHound MCP Server

FastAPI server for Active Directory enumeration via SharpHound/BloodHound.
"""

import asyncio
import json
from typing import Any

from fastapi import FastAPI
from pydantic import BaseModel, ConfigDict, Field


app = FastAPI(
    title="BloodHound MCP Server",
    description="AD enumeration via BloodHound/SharpHound",
    version="1.0.0",
)


class BloodHoundRequest(BaseModel):
    model_config = ConfigDict(extra="ignore")

    domain: str = Field(..., description="Target AD domain")
    collection_method: str = Field("All", description="Collection method: All, DCOnly, Session, etc.")
    domain_controller: str = Field("", description="Specific DC to query")
    username: str = Field("", description="Domain username")
    password: str = Field("", description="Domain password")
    timeout: int = Field(600, ge=60, le=3600)


class BloodHoundResponse(BaseModel):
    success: bool
    users: int = 0
    groups: int = 0
    computers: int = 0
    domains: int = 0
    gpos: int = 0
    ous: int = 0
    relationships: int = 0
    output_path: str | None = None
    error: str | None = None


@app.get("/")
async def root() -> dict[str, str]:
    return {"tool": "bloodhound", "path": "/tools/bloodhound_collect", "status": "ok"}


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "healthy", "tool": "bloodhound"}


@app.post("/tools/bloodhound_collect", response_model=BloodHoundResponse)
async def bloodhound_collect(request: BloodHoundRequest) -> BloodHoundResponse:
    """Run BloodHound/SharpHound collection against an AD domain."""
    try:
        # Use bloodhound-python (Python collector)
        cmd = [
            "bloodhound-python",
            "-d", request.domain,
            "-c", request.collection_method,
            "--zip",
            "-o", "/app/output/bloodhound",
        ]

        if request.domain_controller:
            cmd.extend(["-dc", request.domain_controller])
        if request.username:
            cmd.extend(["-u", request.username])
        if request.password:
            cmd.extend(["-p", request.password])

        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        try:
            stdout, stderr = await asyncio.wait_for(
                process.communicate(), timeout=request.timeout,
            )
        except asyncio.TimeoutError:
            process.kill()
            await process.wait()
            return BloodHoundResponse(success=False, error="Collection timed out")

        output = stdout.decode("utf-8", errors="replace")
        errors = stderr.decode("utf-8", errors="replace")

        # Parse collection stats from output
        users = groups = computers = 0
        for line in (output + errors).split("\n"):
            line_lower = line.lower()
            if "user" in line_lower and "found" in line_lower:
                try:
                    users = int("".join(c for c in line.split()[0] if c.isdigit()) or "0")
                except ValueError:
                    pass
            if "group" in line_lower and "found" in line_lower:
                try:
                    groups = int("".join(c for c in line.split()[0] if c.isdigit()) or "0")
                except ValueError:
                    pass
            if "computer" in line_lower and "found" in line_lower:
                try:
                    computers = int("".join(c for c in line.split()[0] if c.isdigit()) or "0")
                except ValueError:
                    pass

        return BloodHoundResponse(
            success=process.returncode == 0,
            users=users,
            groups=groups,
            computers=computers,
            output_path="/app/output/bloodhound",
            error=errors[:500] if process.returncode != 0 else None,
        )

    except FileNotFoundError:
        return BloodHoundResponse(success=False, error="bloodhound-python not installed")
    except Exception as e:
        return BloodHoundResponse(success=False, error=str(e)[:500])


@app.get("/tools/bloodhound_collect/schema")
async def get_schema() -> dict[str, Any]:
    return {
        "name": "bloodhound_collect",
        "description": "Active Directory enumeration via BloodHound",
        "inputSchema": {
            "type": "object",
            "properties": {
                "domain": {"type": "string", "description": "Target AD domain"},
                "collection_method": {"type": "string", "description": "Collection method"},
                "username": {"type": "string", "description": "Domain username"},
                "password": {"type": "string", "description": "Domain password"},
            },
            "required": ["domain"],
        },
    }
