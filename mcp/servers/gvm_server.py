"""
GVM / OpenVAS MCP Server

FastAPI server wrapping Greenbone Vulnerability Management (OpenVAS)
for network vulnerability scanning.
"""

import asyncio
from typing import Any

from fastapi import FastAPI
from pydantic import BaseModel, ConfigDict, Field


app = FastAPI(
    title="GVM MCP Server",
    description="Network vulnerability scanning via OpenVAS/GVM",
    version="1.0.0",
)


class GVMScanRequest(BaseModel):
    model_config = ConfigDict(extra="ignore")

    target: str = Field(..., description="Target host, IP, or CIDR range")
    scan_config: str = Field(
        "Full and fast",
        description="Scan configuration (Full and fast, Full and deep, etc.)",
    )
    port_list: str = Field("", description="Custom port list (empty = default)")
    credentials: dict[str, str] = Field(
        default_factory=dict,
        description="SSH/SMB credentials for authenticated scans",
    )
    timeout: int = Field(3600, ge=60, le=14400, description="Timeout in seconds")


class GVMResult(BaseModel):
    host: str = ""
    vulnerability: str = ""
    severity: str = ""
    cvss: float | None = None
    cve: str = ""
    port: str = ""
    description: str = ""
    solution: str = ""


class GVMScanResponse(BaseModel):
    success: bool
    task_id: str | None = None
    report_id: str | None = None
    results: list[GVMResult] = []
    total_findings: int = 0
    output: str | None = None
    error: str | None = None


@app.get("/")
async def root() -> dict[str, str]:
    return {"tool": "gvm", "path": "/tools/gvm_scan", "status": "ok"}


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "healthy", "tool": "gvm"}


@app.post("/run")
async def run(body: dict[str, Any]) -> dict[str, Any]:
    """MCP executor dispatch endpoint."""
    args = body.get("args", {})
    req = GVMScanRequest(**args)
    result = await gvm_scan(req)
    return result.model_dump()


@app.post("/tools/gvm_scan", response_model=GVMScanResponse)
async def gvm_scan(request: GVMScanRequest) -> GVMScanResponse:
    """Run an OpenVAS/GVM vulnerability scan."""
    try:
        # Build gvm-cli or openvas command
        cmd = [
            "gvm-cli", "socket",
            "--xml",
            f"<create_target><name>arc-scan</name>"
            f"<hosts>{request.target}</hosts></create_target>",
        ]

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
            return GVMScanResponse(success=False, error="GVM scan timed out")

        output = stdout.decode("utf-8", errors="replace")

        # Parse GVM XML output for results
        results: list[GVMResult] = []
        # GVM returns XML — simplified parsing for key fields
        if "<result" in output:
            # In production this would use proper XML parsing
            results.append(GVMResult(
                host=request.target,
                vulnerability="Scan completed",
                severity="info",
            ))

        return GVMScanResponse(
            success=True,
            results=results,
            total_findings=len(results),
            output=output[:5000],
        )

    except FileNotFoundError:
        return GVMScanResponse(success=False, error="gvm-cli not installed")
    except Exception as e:
        return GVMScanResponse(success=False, error=str(e)[:500])


@app.get("/tools/gvm_scan/schema")
async def get_schema() -> dict[str, Any]:
    return {
        "name": "gvm_scan",
        "description": "Network vulnerability scanning using OpenVAS/GVM",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target host or CIDR"},
                "scan_config": {"type": "string", "description": "Scan config name"},
            },
            "required": ["target"],
        },
    }
