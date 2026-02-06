"""
Tor Utility MCP Server

Manages Tor SOCKS proxy: check status, renew circuit.
Port: 8052
"""

from __future__ import annotations

import asyncio
import os
import subprocess
from typing import Any

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

app = FastAPI(
    title="Arc MCP - Tor Utility",
    description="Tor SOCKS proxy management",
    version="1.0.0",
)


class TorRequest(BaseModel):
    action: str = "check"  # "check" | "new_circuit"
    control_port: int = 9051
    control_password: str = ""


class TorResponse(BaseModel):
    success: bool
    action: str
    data: dict[str, Any] = {}
    error: str | None = None


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "healthy", "service": "tor"}


@app.post("/tools/tor_check")
async def tor_check() -> TorResponse:
    """Check if Tor is running and reachable."""
    try:
        # Check if the Tor SOCKS proxy is responding
        result = subprocess.run(
            ["curl", "--socks5-hostname", "127.0.0.1:9050",
             "https://check.torproject.org/api/ip", "--max-time", "10"],
            capture_output=True, text=True, timeout=15,
        )

        if result.returncode == 0:
            return TorResponse(
                success=True,
                action="check",
                data={"status": "running", "output": result.stdout.strip()},
            )
        else:
            return TorResponse(
                success=False,
                action="check",
                data={"status": "not_reachable"},
                error=result.stderr.strip() or "Tor proxy not reachable",
            )
    except subprocess.TimeoutExpired:
        return TorResponse(
            success=False, action="check",
            error="Tor check timed out",
        )
    except FileNotFoundError:
        return TorResponse(
            success=False, action="check",
            error="curl not found",
        )


@app.post("/tools/tor_new_circuit")
async def tor_new_circuit(request: TorRequest) -> TorResponse:
    """Request a new Tor circuit (new exit node)."""
    try:
        # Use the Tor control protocol to request a new circuit
        password = request.control_password or os.getenv("TOR_CONTROL_PASSWORD", "")

        # Send SIGNAL NEWNYM via the control port
        proc = await asyncio.create_subprocess_exec(
            "bash", "-c",
            f'(echo "AUTHENTICATE \\"{password}\\""; echo "SIGNAL NEWNYM"; echo "QUIT") | nc 127.0.0.1 {request.control_port}',
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=10)

        output = stdout.decode().strip()
        if "250 OK" in output:
            return TorResponse(
                success=True,
                action="new_circuit",
                data={"output": output},
            )
        else:
            return TorResponse(
                success=False,
                action="new_circuit",
                data={"output": output},
                error=stderr.decode().strip() or "Circuit renewal failed",
            )
    except asyncio.TimeoutError:
        return TorResponse(
            success=False, action="new_circuit",
            error="Control port connection timed out",
        )
    except Exception as exc:
        return TorResponse(
            success=False, action="new_circuit",
            error=str(exc),
        )


@app.post("/run")
async def run(request: TorRequest) -> TorResponse:
    """Generic run endpoint (dispatches to check or new_circuit)."""
    if request.action == "new_circuit":
        return await tor_new_circuit(request)
    return await tor_check()
