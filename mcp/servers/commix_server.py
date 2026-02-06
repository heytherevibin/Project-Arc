"""
Commix MCP Server

FastAPI server wrapping Commix for automated OS command injection
detection and exploitation.
"""

import asyncio
from typing import Any

from fastapi import FastAPI
from pydantic import BaseModel, ConfigDict, Field


app = FastAPI(
    title="Commix MCP Server",
    description="Automated command injection via Commix",
    version="1.0.0",
)


class CommixRequest(BaseModel):
    model_config = ConfigDict(extra="ignore")

    url: str = Field(..., description="Target URL with injectable parameter")
    data: str = Field("", description="POST data (for POST injections)")
    cookie: str = Field("", description="HTTP cookie header")
    level: int = Field(1, ge=1, le=3, description="Level of tests (1-3)")
    technique: str = Field(
        "", description="Injection techniques to use (e.g., 'CBT' for classic, blind, time-based)",
    )
    os_cmd: str = Field("", description="Execute OS command after finding injection")
    batch: bool = Field(True, description="Non-interactive mode")
    timeout: int = Field(600, ge=60, le=3600)


class CommixResponse(BaseModel):
    success: bool
    injectable: bool = False
    technique: str | None = None
    os_type: str | None = None
    command_output: str | None = None
    output: str | None = None
    error: str | None = None


@app.get("/")
async def root() -> dict[str, str]:
    return {"tool": "commix", "path": "/tools/commix_scan", "status": "ok"}


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "healthy", "tool": "commix"}


@app.post("/run")
async def run(body: dict[str, Any]) -> dict[str, Any]:
    """MCP executor dispatch endpoint."""
    args = body.get("args", {})
    req = CommixRequest(**args)
    result = await commix_scan(req)
    return result.model_dump()


@app.post("/tools/commix_scan", response_model=CommixResponse)
async def commix_scan(request: CommixRequest) -> CommixResponse:
    """Run Commix against a target URL."""
    try:
        cmd = [
            "commix", "--url", request.url,
            "--level", str(request.level),
        ]

        if request.batch:
            cmd.append("--batch")
        if request.data:
            cmd.extend(["--data", request.data])
        if request.cookie:
            cmd.extend(["--cookie", request.cookie])
        if request.technique:
            cmd.extend(["--technique", request.technique])
        if request.os_cmd:
            cmd.extend(["--os-cmd", request.os_cmd])

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
            return CommixResponse(success=False, error="Commix timed out")

        output = stdout.decode("utf-8", errors="replace")

        injectable = (
            "is vulnerable" in output.lower()
            or "command injection" in output.lower()
        )
        technique = None
        os_type = None
        cmd_output = None

        for line in output.split("\n"):
            line_lower = line.lower()
            if "technique:" in line_lower:
                technique = line.split(":")[-1].strip()
            if "operating system:" in line_lower or "os:" in line_lower:
                os_type = line.split(":")[-1].strip()
            if request.os_cmd and "response" in line_lower:
                cmd_output = line

        return CommixResponse(
            success=True,
            injectable=injectable,
            technique=technique,
            os_type=os_type,
            command_output=cmd_output,
            output=output[:5000],
        )

    except FileNotFoundError:
        return CommixResponse(success=False, error="Commix not installed")
    except Exception as e:
        return CommixResponse(success=False, error=str(e)[:500])


@app.get("/tools/commix_scan/schema")
async def get_schema() -> dict[str, Any]:
    return {
        "name": "commix_scan",
        "description": "Automated OS command injection detection and exploitation",
        "inputSchema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Target URL"},
                "data": {"type": "string", "description": "POST data"},
                "level": {"type": "integer", "description": "Test level 1-3"},
                "os_cmd": {"type": "string", "description": "OS command to execute"},
            },
            "required": ["url"],
        },
    }
