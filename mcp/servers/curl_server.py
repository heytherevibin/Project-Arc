"""
Curl Utility MCP Server

FastAPI server wrapping curl for arbitrary HTTP requests,
useful for manual verification, API probing, and custom requests.
"""

import asyncio
from typing import Any

from fastapi import FastAPI
from pydantic import BaseModel, ConfigDict, Field


app = FastAPI(
    title="Curl MCP Server",
    description="HTTP request utility via curl",
    version="1.0.0",
)


class CurlRequest(BaseModel):
    model_config = ConfigDict(extra="ignore")

    url: str = Field(..., description="Target URL")
    method: str = Field("GET", description="HTTP method")
    headers: dict[str, str] = Field(default_factory=dict, description="Custom headers")
    data: str = Field("", description="Request body data")
    follow_redirects: bool = Field(True, description="Follow HTTP redirects")
    max_redirects: int = Field(10, ge=0, le=50)
    insecure: bool = Field(False, description="Skip TLS verification")
    proxy: str = Field("", description="Proxy URL (e.g., socks5://127.0.0.1:9050)")
    user_agent: str = Field("", description="Custom User-Agent")
    include_headers: bool = Field(True, description="Include response headers")
    timeout: int = Field(30, ge=5, le=300)


class CurlResponse(BaseModel):
    success: bool
    status_code: int | None = None
    response_headers: dict[str, str] = {}
    body: str | None = None
    content_type: str | None = None
    redirect_url: str | None = None
    total_time: str | None = None
    error: str | None = None


@app.get("/")
async def root() -> dict[str, str]:
    return {"tool": "curl", "path": "/tools/curl_request", "status": "ok"}


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "healthy", "tool": "curl"}


@app.post("/run")
async def run(body: dict[str, Any]) -> dict[str, Any]:
    """MCP executor dispatch endpoint."""
    args = body.get("args", {})
    req = CurlRequest(**args)
    result = await curl_request(req)
    return result.model_dump()


@app.post("/tools/curl_request", response_model=CurlResponse)
async def curl_request(request: CurlRequest) -> CurlResponse:
    """Execute an HTTP request via curl."""
    try:
        cmd = [
            "curl", "-s",
            "-o", "/tmp/curl_body",
            "-D", "/tmp/curl_headers",
            "-w", "%{http_code}\\n%{content_type}\\n%{redirect_url}\\n%{time_total}",
            "-X", request.method.upper(),
            "--max-time", str(request.timeout),
            "--max-redirs", str(request.max_redirects),
        ]

        if request.follow_redirects:
            cmd.append("-L")
        if request.insecure:
            cmd.append("-k")
        if request.data:
            cmd.extend(["-d", request.data])
        if request.proxy:
            cmd.extend(["-x", request.proxy])
        if request.user_agent:
            cmd.extend(["-A", request.user_agent])

        for key, value in request.headers.items():
            cmd.extend(["-H", f"{key}: {value}"])

        cmd.append(request.url)

        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        try:
            stdout, stderr = await asyncio.wait_for(
                process.communicate(), timeout=request.timeout + 5,
            )
        except asyncio.TimeoutError:
            process.kill()
            await process.wait()
            return CurlResponse(success=False, error="Request timed out")

        write_output = stdout.decode("utf-8", errors="replace").strip().split("\n")

        status_code = int(write_output[0]) if write_output and write_output[0].isdigit() else None
        content_type = write_output[1] if len(write_output) > 1 else None
        redirect_url = write_output[2] if len(write_output) > 2 and write_output[2] else None
        total_time = write_output[3] if len(write_output) > 3 else None

        # Read response body
        body = None
        try:
            with open("/tmp/curl_body", "r", errors="replace") as f:
                body = f.read()[:10000]
        except FileNotFoundError:
            pass

        # Read response headers
        resp_headers: dict[str, str] = {}
        if request.include_headers:
            try:
                with open("/tmp/curl_headers", "r", errors="replace") as f:
                    for line in f:
                        if ":" in line:
                            k, v = line.split(":", 1)
                            resp_headers[k.strip()] = v.strip()
            except FileNotFoundError:
                pass

        return CurlResponse(
            success=status_code is not None,
            status_code=status_code,
            response_headers=resp_headers,
            body=body,
            content_type=content_type,
            redirect_url=redirect_url,
            total_time=total_time,
        )

    except FileNotFoundError:
        return CurlResponse(success=False, error="curl not installed")
    except Exception as e:
        return CurlResponse(success=False, error=str(e)[:500])


@app.get("/tools/curl_request/schema")
async def get_schema() -> dict[str, Any]:
    return {
        "name": "curl_request",
        "description": "Execute HTTP requests via curl for manual verification and API probing",
        "inputSchema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Target URL"},
                "method": {"type": "string", "description": "HTTP method"},
                "headers": {"type": "object", "description": "Custom headers"},
                "data": {"type": "string", "description": "Request body"},
            },
            "required": ["url"],
        },
    }
