"""
SQLMap MCP Server

FastAPI server for automated SQL injection detection and exploitation.
"""

import asyncio
import json
from typing import Any

from fastapi import FastAPI
from pydantic import BaseModel, ConfigDict, Field


app = FastAPI(
    title="SQLMap MCP Server",
    description="Automated SQL injection via SQLMap",
    version="1.0.0",
)


class SQLMapRequest(BaseModel):
    model_config = ConfigDict(extra="ignore")

    url: str = Field(..., description="Target URL with injectable parameter")
    method: str = Field("GET", description="HTTP method")
    data: str = Field("", description="POST data")
    cookie: str = Field("", description="HTTP cookie")
    level: int = Field(1, ge=1, le=5, description="Test level (1-5)")
    risk: int = Field(1, ge=1, le=3, description="Risk level (1-3)")
    batch: bool = Field(True, description="Never ask for user input")
    dump: bool = Field(False, description="Dump database contents")
    timeout: int = Field(600, ge=60, le=3600)


class SQLMapResponse(BaseModel):
    success: bool
    injectable: bool = False
    dbms: str | None = None
    databases: list[str] = []
    tables: list[str] = []
    output: str | None = None
    error: str | None = None


@app.get("/")
async def root() -> dict[str, str]:
    return {"tool": "sqlmap", "path": "/tools/sqlmap_scan", "status": "ok"}


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "healthy", "tool": "sqlmap"}


@app.post("/tools/sqlmap_scan", response_model=SQLMapResponse)
async def sqlmap_scan(request: SQLMapRequest) -> SQLMapResponse:
    """Run SQLMap against a target URL."""
    try:
        cmd = [
            "sqlmap", "-u", request.url,
            "--level", str(request.level),
            "--risk", str(request.risk),
            "--output-dir=/tmp/sqlmap_output",
        ]

        if request.batch:
            cmd.append("--batch")
        if request.data:
            cmd.extend(["--data", request.data])
        if request.cookie:
            cmd.extend(["--cookie", request.cookie])
        if request.dump:
            cmd.append("--dump")

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
            return SQLMapResponse(success=False, error="SQLMap timed out")

        output = stdout.decode("utf-8", errors="replace")

        injectable = "is vulnerable" in output.lower() or "injectable" in output.lower()
        dbms = None
        for line in output.split("\n"):
            if "back-end DBMS" in line:
                dbms = line.split(":")[-1].strip() if ":" in line else None

        return SQLMapResponse(
            success=True,
            injectable=injectable,
            dbms=dbms,
            output=output[:5000],
        )

    except FileNotFoundError:
        return SQLMapResponse(success=False, error="SQLMap not installed")
    except Exception as e:
        return SQLMapResponse(success=False, error=str(e)[:500])


@app.get("/tools/sqlmap_scan/schema")
async def get_schema() -> dict[str, Any]:
    return {
        "name": "sqlmap_scan",
        "description": "Automated SQL injection detection and exploitation",
        "inputSchema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Target URL"},
                "level": {"type": "integer", "description": "Test level 1-5"},
                "risk": {"type": "integer", "description": "Risk level 1-3"},
            },
            "required": ["url"],
        },
    }
