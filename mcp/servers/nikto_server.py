"""
Nikto MCP Server

FastAPI server wrapping Nikto web server scanner for identifying
dangerous files, outdated server versions, and configuration issues.
"""

import asyncio
import json
from typing import Any

from fastapi import FastAPI
from pydantic import BaseModel, ConfigDict, Field


app = FastAPI(
    title="Nikto MCP Server",
    description="Web server vulnerability scanning via Nikto",
    version="1.0.0",
)


class NiktoRequest(BaseModel):
    model_config = ConfigDict(extra="ignore")

    target: str = Field(..., description="Target URL or host")
    port: int = Field(0, description="Port (0 = auto-detect from URL)")
    ssl: bool = Field(False, description="Force SSL")
    tuning: str = Field("", description="Nikto tuning options (e.g., '123bde')")
    plugins: str = Field("", description="Comma-separated plugin list")
    max_time: int = Field(600, ge=60, le=3600, description="Max scan time in seconds")
    timeout: int = Field(900, ge=60, le=3600)


class NiktoFinding(BaseModel):
    id: str = ""
    method: str = ""
    url: str = ""
    message: str = ""
    osvdb: str = ""


class NiktoResponse(BaseModel):
    success: bool
    target: str = ""
    port: int = 0
    server: str | None = None
    findings: list[NiktoFinding] = []
    total_findings: int = 0
    output: str | None = None
    error: str | None = None


@app.get("/")
async def root() -> dict[str, str]:
    return {"tool": "nikto", "path": "/tools/nikto_scan", "status": "ok"}


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "healthy", "tool": "nikto"}


@app.post("/run")
async def run(body: dict[str, Any]) -> dict[str, Any]:
    """MCP executor dispatch endpoint."""
    args = body.get("args", {})
    req = NiktoRequest(**args)
    result = await nikto_scan(req)
    return result.model_dump()


@app.post("/tools/nikto_scan", response_model=NiktoResponse)
async def nikto_scan(request: NiktoRequest) -> NiktoResponse:
    """Run Nikto against a web server."""
    try:
        cmd = [
            "nikto", "-h", request.target,
            "-Format", "json",
            "-output", "/tmp/nikto_output.json",
            "-maxtime", str(request.max_time),
        ]

        if request.port:
            cmd.extend(["-p", str(request.port)])
        if request.ssl:
            cmd.append("-ssl")
        if request.tuning:
            cmd.extend(["-Tuning", request.tuning])
        if request.plugins:
            cmd.extend(["-Plugins", request.plugins])

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
            return NiktoResponse(success=False, error="Nikto timed out")

        output = stdout.decode("utf-8", errors="replace")

        # Try to parse JSON output
        findings: list[NiktoFinding] = []
        try:
            with open("/tmp/nikto_output.json") as f:
                data = json.load(f)

            server = None
            if isinstance(data, list) and data:
                host_data = data[0]
                server = host_data.get("banner")
                for vuln in host_data.get("vulnerabilities", []):
                    findings.append(NiktoFinding(
                        id=str(vuln.get("id", "")),
                        method=vuln.get("method", "GET"),
                        url=vuln.get("url", ""),
                        message=vuln.get("msg", ""),
                        osvdb=str(vuln.get("OSVDB", "")),
                    ))

            return NiktoResponse(
                success=True,
                target=request.target,
                port=request.port,
                server=server,
                findings=findings,
                total_findings=len(findings),
                output=output[:5000],
            )
        except (FileNotFoundError, json.JSONDecodeError):
            # Fallback to parsing stdout
            return NiktoResponse(
                success=True,
                target=request.target,
                output=output[:5000],
            )

    except FileNotFoundError:
        return NiktoResponse(success=False, error="Nikto not installed")
    except Exception as e:
        return NiktoResponse(success=False, error=str(e)[:500])


@app.get("/tools/nikto_scan/schema")
async def get_schema() -> dict[str, Any]:
    return {
        "name": "nikto_scan",
        "description": "Web server vulnerability scanning with Nikto",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target URL or host"},
                "port": {"type": "integer", "description": "Port number"},
                "ssl": {"type": "boolean", "description": "Force SSL"},
            },
            "required": ["target"],
        },
    }
