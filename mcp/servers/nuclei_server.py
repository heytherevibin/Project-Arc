"""
Nuclei MCP Server

FastMCP server for vulnerability scanning.
"""

import asyncio
import json
from typing import Any

from fastapi import FastAPI
from pydantic import BaseModel, ConfigDict, Field


app = FastAPI(title="Nuclei MCP Server", version="1.0.0")


class NucleiRequest(BaseModel):
    model_config = ConfigDict(extra="ignore")

    urls: list[str] = Field(..., min_length=1)
    severity: list[str] = Field(["critical", "high", "medium"])
    tags: list[str] | None = None
    rate_limit: int = Field(150, ge=1, le=1000)
    timeout: int = Field(1800, ge=60, le=7200)


class VulnResult(BaseModel):
    template_id: str
    name: str
    severity: str
    matched_at: str
    description: str | None = None
    cve_id: str | None = None


class NucleiResponse(BaseModel):
    success: bool
    vulnerabilities: list[VulnResult] = []
    total: int = 0
    by_severity: dict[str, int] = {}
    error: str | None = None


@app.get("/")
async def root() -> dict[str, str]:
    return {"tool": "nuclei", "path": "/tools/nuclei_scan", "status": "ok"}


@app.get("/health")
async def health_check() -> dict[str, str]:
    return {"status": "healthy", "tool": "nuclei"}


@app.post("/tools/nuclei_scan", response_model=NucleiResponse)
async def nuclei_scan(request: NucleiRequest) -> NucleiResponse:
    try:
        cmd = [
            "nuclei",
            "-silent",
            "-json",
            "-rate-limit", str(request.rate_limit),
            "-severity", ",".join(request.severity),
            "-automatic-scan",
        ]
        
        if request.tags:
            cmd.extend(["-tags", ",".join(request.tags)])
        
        input_data = "\n".join(request.urls)
        
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        
        try:
            stdout, stderr = await asyncio.wait_for(
                process.communicate(input=input_data.encode()),
                timeout=request.timeout,
            )
        except asyncio.TimeoutError:
            process.kill()
            await process.wait()
            return NucleiResponse(success=False, error="Timeout")
        
        vulnerabilities: list[VulnResult] = []
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        output = stdout.decode("utf-8", errors="replace")
        
        for line in output.strip().split("\n"):
            if not line:
                continue
            try:
                data = json.loads(line)
                info = data.get("info", {})
                severity = info.get("severity", "unknown").lower()
                
                # Extract CVE
                cve_id = None
                classification = info.get("classification", {})
                cve_list = classification.get("cve-id", [])
                if cve_list:
                    cve_id = cve_list[0] if isinstance(cve_list, list) else cve_list
                
                vuln = VulnResult(
                    template_id=data.get("template-id", data.get("templateID", "unknown")),
                    name=info.get("name", "Unknown"),
                    severity=severity,
                    matched_at=data.get("matched-at", data.get("host", "")),
                    description=info.get("description"),
                    cve_id=cve_id,
                )
                vulnerabilities.append(vuln)
                
                if severity in severity_counts:
                    severity_counts[severity] += 1
            except json.JSONDecodeError:
                continue
        
        # Sort by severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        vulnerabilities.sort(key=lambda v: severity_order.get(v.severity, 5))
        
        return NucleiResponse(
            success=True,
            vulnerabilities=vulnerabilities,
            total=len(vulnerabilities),
            by_severity=severity_counts,
        )
    
    except FileNotFoundError:
        return NucleiResponse(success=False, error="Nuclei not installed")
    except Exception as e:
        return NucleiResponse(success=False, error=str(e))
