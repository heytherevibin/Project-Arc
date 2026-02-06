"""
Proxychains Utility MCP Server

FastAPI server for routing tool traffic through proxy chains
(SOCKS4/5, HTTP) for stealth scanning and pivoting through
compromised hosts.
"""

import asyncio
import tempfile
from typing import Any

from fastapi import FastAPI
from pydantic import BaseModel, ConfigDict, Field


app = FastAPI(
    title="Proxychains MCP Server",
    description="Traffic routing through proxy chains for stealth operations",
    version="1.0.0",
)


class ProxyConfig(BaseModel):
    """Single proxy in the chain."""
    type: str = Field("socks5", description="Proxy type: socks4, socks5, http")
    host: str = Field(..., description="Proxy host")
    port: int = Field(1080, description="Proxy port")
    username: str = Field("", description="Auth username")
    password: str = Field("", description="Auth password")


class ProxychainRequest(BaseModel):
    model_config = ConfigDict(extra="ignore")

    command: str = Field(..., description="Command to execute through proxy chain")
    args: list[str] = Field(default_factory=list, description="Command arguments")
    proxies: list[ProxyConfig] = Field(
        default_factory=list,
        description="Ordered list of proxies (chain); empty = use default config",
    )
    chain_type: str = Field(
        "strict",
        description="Chain type: strict, dynamic, random, round_robin",
    )
    dns_through_proxy: bool = Field(True, description="Resolve DNS through proxy")
    quiet: bool = Field(True, description="Suppress proxychains output")
    timeout: int = Field(120, ge=10, le=600)


class ProxychainResponse(BaseModel):
    success: bool
    command: str = ""
    exit_code: int | None = None
    stdout: str | None = None
    stderr: str | None = None
    proxies_used: int = 0
    error: str | None = None


@app.get("/")
async def root() -> dict[str, str]:
    return {"tool": "proxychains", "path": "/tools/proxychains_exec", "status": "ok"}


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "healthy", "tool": "proxychains"}


@app.post("/run")
async def run(body: dict[str, Any]) -> dict[str, Any]:
    """MCP executor dispatch endpoint."""
    args = body.get("args", {})
    req = ProxychainRequest(**args)
    result = await proxychains_exec(req)
    return result.model_dump()


@app.post("/tools/proxychains_exec", response_model=ProxychainResponse)
async def proxychains_exec(request: ProxychainRequest) -> ProxychainResponse:
    """Execute a command through proxychains."""
    try:
        # Build proxychains config if custom proxies provided
        config_path = None
        if request.proxies:
            config_path = _generate_config(request)

        cmd: list[str] = ["proxychains4"]

        if request.quiet:
            cmd.append("-q")
        if config_path:
            cmd.extend(["-f", config_path])

        # Append the actual command
        cmd.append(request.command)
        cmd.extend(request.args)

        # Safety: block dangerous commands
        blocked = {"rm", "dd", "mkfs", "shutdown", "reboot", "init"}
        base_cmd = request.command.split("/")[-1]
        if base_cmd in blocked:
            return ProxychainResponse(
                success=False,
                command=request.command,
                error=f"Blocked command: {base_cmd}",
            )

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
            return ProxychainResponse(
                success=False,
                command=request.command,
                error="Proxychains execution timed out",
            )

        return ProxychainResponse(
            success=process.returncode == 0,
            command=request.command,
            exit_code=process.returncode,
            stdout=stdout.decode("utf-8", errors="replace")[:10000],
            stderr=stderr.decode("utf-8", errors="replace")[:5000],
            proxies_used=len(request.proxies) if request.proxies else 0,
        )

    except FileNotFoundError:
        return ProxychainResponse(
            success=False,
            command=request.command,
            error="proxychains4 not installed",
        )
    except Exception as e:
        return ProxychainResponse(
            success=False,
            command=request.command,
            error=str(e)[:500],
        )


def _generate_config(request: ProxychainRequest) -> str:
    """Generate a temporary proxychains config file."""
    lines = [
        f"{request.chain_type}_chain",
        f"proxy_dns" if request.dns_through_proxy else "",
        "tcp_read_time_out 15000",
        "tcp_connect_time_out 8000",
        "",
        "[ProxyList]",
    ]

    for proxy in request.proxies:
        entry = f"{proxy.type}\t{proxy.host}\t{proxy.port}"
        if proxy.username and proxy.password:
            entry += f"\t{proxy.username}\t{proxy.password}"
        lines.append(entry)

    # Write to temp file
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".conf", prefix="proxychains_",
        dir="/tmp", delete=False,
    ) as f:
        f.write("\n".join(lines))
        return f.name


@app.get("/tools/proxychains_exec/schema")
async def get_schema() -> dict[str, Any]:
    return {
        "name": "proxychains_exec",
        "description": "Execute commands through proxy chains for stealth scanning and pivoting",
        "inputSchema": {
            "type": "object",
            "properties": {
                "command": {"type": "string", "description": "Command to execute"},
                "args": {"type": "array", "description": "Command arguments"},
                "proxies": {
                    "type": "array",
                    "description": "Proxy chain configuration",
                    "items": {
                        "type": "object",
                        "properties": {
                            "type": {"type": "string"},
                            "host": {"type": "string"},
                            "port": {"type": "integer"},
                        },
                    },
                },
            },
            "required": ["command"],
        },
    }
