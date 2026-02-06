"""
CrackMapExec MCP Server

FastAPI server for AD enumeration, password spraying, and command execution.
"""

import asyncio
import json
from typing import Any

from fastapi import FastAPI
from pydantic import BaseModel, ConfigDict, Field


app = FastAPI(
    title="CrackMapExec MCP Server",
    description="AD enumeration and password spraying via CrackMapExec",
    version="1.0.0",
)


class CMERequest(BaseModel):
    model_config = ConfigDict(extra="ignore")

    target: str = Field(..., description="Target host, IP, or CIDR range")
    protocol: str = Field("smb", description="Protocol: smb, ldap, winrm, ssh, mssql")
    username: str = Field("", description="Username")
    password: str = Field("", description="Password")
    nt_hash: str = Field("", description="NT hash for PtH")
    domain: str = Field("", description="Domain name")
    action: str = Field("enum", description="Action: enum, spray, exec, shares, users")
    command: str = Field("", description="Command to execute (for exec action)")
    password_list: list[str] = Field(default_factory=list, description="Passwords for spraying")
    timeout: int = Field(120, ge=10, le=600)


class CMEResponse(BaseModel):
    success: bool
    results: list[dict[str, Any]] = []
    output: str = ""
    error: str | None = None


@app.get("/")
async def root() -> dict[str, str]:
    return {"tool": "crackmapexec", "path": "/tools/cme_run", "status": "ok"}


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "healthy", "tool": "crackmapexec"}


@app.post("/tools/cme_run", response_model=CMEResponse)
async def cme_run(request: CMERequest) -> CMEResponse:
    """Run CrackMapExec against a target."""
    try:
        cmd = ["crackmapexec", request.protocol, request.target]

        if request.username:
            cmd.extend(["-u", request.username])
        if request.password:
            cmd.extend(["-p", request.password])
        elif request.nt_hash:
            cmd.extend(["-H", request.nt_hash])
        if request.domain:
            cmd.extend(["-d", request.domain])

        # Action-specific flags
        if request.action == "shares":
            cmd.append("--shares")
        elif request.action == "users":
            cmd.append("--users")
        elif request.action == "exec" and request.command:
            cmd.extend(["-x", request.command])
        elif request.action == "spray" and request.password_list:
            # Password spraying (one user, many passwords)
            cmd.extend(["-p"] + request.password_list[:20])

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
            return CMEResponse(success=False, error="CrackMapExec timed out")

        output = stdout.decode("utf-8", errors="replace")

        return CMEResponse(
            success=True,
            output=output[:10000],
            error=stderr.decode("utf-8", errors="replace")[:2000] if process.returncode != 0 else None,
        )

    except FileNotFoundError:
        return CMEResponse(success=False, error="CrackMapExec not installed")
    except Exception as e:
        return CMEResponse(success=False, error=str(e)[:500])


@app.get("/tools/cme_run/schema")
async def get_schema() -> dict[str, Any]:
    return {
        "name": "cme_run",
        "description": "AD enumeration, password spraying, and command execution via CrackMapExec",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target host/IP/CIDR"},
                "protocol": {"type": "string", "description": "Protocol: smb, ldap, winrm"},
                "username": {"type": "string", "description": "Username"},
                "action": {"type": "string", "description": "Action: enum, spray, exec, shares, users"},
            },
            "required": ["target"],
        },
    }
