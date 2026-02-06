"""
Metasploit MCP Server

FastAPI server wrapping Metasploit Framework RPC for exploitation.
Requires msfrpcd running in the container.
"""

import asyncio
import json
from typing import Any

from fastapi import FastAPI
from pydantic import BaseModel, ConfigDict, Field


app = FastAPI(
    title="Metasploit MCP Server",
    description="Exploitation via Metasploit Framework",
    version="1.0.0",
)


class ExploitRequest(BaseModel):
    """Request model for Metasploit exploit."""
    model_config = ConfigDict(extra="ignore")

    module: str = Field(..., description="Metasploit module path (e.g., exploit/windows/smb/ms17_010_eternalblue)")
    target_host: str = Field(..., description="Target host or IP")
    target_port: int = Field(0, description="Target port (0 = module default)")
    payload: str = Field("", description="Payload module (empty = auto-select)")
    options: dict[str, Any] = Field(default_factory=dict, description="Additional module options")
    timeout: int = Field(300, ge=30, le=3600, description="Timeout in seconds")


class ExploitResponse(BaseModel):
    success: bool
    session_id: str | None = None
    session_type: str | None = None
    host: str | None = None
    exploit_module: str | None = None
    output: str | None = None
    error: str | None = None


class ModuleSearchRequest(BaseModel):
    query: str = Field(..., description="Search query for modules")
    module_type: str = Field("exploit", description="Module type: exploit, auxiliary, post")


@app.get("/")
async def root() -> dict[str, str]:
    return {"tool": "metasploit", "path": "/tools/msf_exploit", "status": "ok"}


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "healthy", "tool": "metasploit"}


@app.post("/tools/msf_exploit", response_model=ExploitResponse)
async def msf_exploit(request: ExploitRequest) -> ExploitResponse:
    """Run a Metasploit exploit module against a target."""
    try:
        # Build msfconsole resource script
        rc_lines = [
            f"use {request.module}",
            f"set RHOSTS {request.target_host}",
        ]
        if request.target_port > 0:
            rc_lines.append(f"set RPORT {request.target_port}")
        if request.payload:
            rc_lines.append(f"set PAYLOAD {request.payload}")
        for key, val in request.options.items():
            rc_lines.append(f"set {key} {val}")
        rc_lines.append("exploit -j -z")
        rc_lines.append("sleep 10")
        rc_lines.append("sessions -l")

        rc_script = "\n".join(rc_lines)

        process = await asyncio.create_subprocess_exec(
            "msfconsole", "-q", "-x", rc_script,
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
            return ExploitResponse(success=False, error="Exploit timed out")

        output = stdout.decode("utf-8", errors="replace")

        # Parse for session creation
        session_id = None
        for line in output.split("\n"):
            if "session" in line.lower() and "opened" in line.lower():
                # Extract session ID
                parts = line.split()
                for i, part in enumerate(parts):
                    if part.lower() == "session" and i + 1 < len(parts):
                        sid = parts[i + 1].strip("():")
                        if sid.isdigit():
                            session_id = sid
                            break

        return ExploitResponse(
            success=session_id is not None,
            session_id=session_id,
            host=request.target_host,
            exploit_module=request.module,
            output=output[:5000],
        )

    except FileNotFoundError:
        return ExploitResponse(success=False, error="Metasploit not installed")
    except Exception as e:
        return ExploitResponse(success=False, error=str(e)[:500])


@app.post("/tools/msf_search")
async def msf_search(request: ModuleSearchRequest) -> dict[str, Any]:
    """Search for Metasploit modules."""
    try:
        process = await asyncio.create_subprocess_exec(
            "msfconsole", "-q", "-x", f"search {request.query}; exit",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(process.communicate(), timeout=60)
        output = stdout.decode("utf-8", errors="replace")
        return {"success": True, "output": output[:10000]}
    except Exception as e:
        return {"success": False, "error": str(e)}


@app.get("/tools/msf_exploit/schema")
async def get_schema() -> dict[str, Any]:
    return {
        "name": "msf_exploit",
        "description": "Run Metasploit exploit module against a target",
        "inputSchema": {
            "type": "object",
            "properties": {
                "module": {"type": "string", "description": "Metasploit module path"},
                "target_host": {"type": "string", "description": "Target host/IP"},
                "target_port": {"type": "integer", "description": "Target port"},
                "payload": {"type": "string", "description": "Payload module"},
            },
            "required": ["module", "target_host"],
        },
    }
