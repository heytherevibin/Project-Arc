"""
Base Tool Class

Abstract base class for all reconnaissance tools.
"""

import asyncio
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Generic, TypeVar

import httpx

from core.config import get_settings
from core.exceptions import MCPConnectionError, MCPToolError, ToolTimeoutError
from core.logging import get_logger, log_tool_execution


logger = get_logger(__name__)

T = TypeVar("T")


@dataclass
class ToolResult(Generic[T]):
    """Result from a tool execution."""
    
    success: bool
    data: T | None = None
    error: str | None = None
    duration_ms: float = 0.0
    raw_output: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


class BaseTool(ABC):
    """
    Abstract base class for reconnaissance tools.
    
    Provides common functionality for executing tools via MCP servers
    or direct command execution.
    """
    
    # Tool identification
    name: str = "base_tool"
    description: str = "Base tool class"
    
    # Execution settings
    timeout_seconds: int = 300  # 5 minutes default
    retry_attempts: int = 3
    retry_delay_seconds: float = 1.0
    
    def __init__(self) -> None:
        self._settings = get_settings()
        self._http_client: httpx.AsyncClient | None = None
    
    async def _get_http_client(self) -> httpx.AsyncClient:
        """Get or create HTTP client for MCP communication."""
        if self._http_client is None:
            self._http_client = httpx.AsyncClient(
                timeout=httpx.Timeout(self.timeout_seconds),
            )
        return self._http_client
    
    async def close(self) -> None:
        """Close HTTP client."""
        if self._http_client:
            await self._http_client.aclose()
            self._http_client = None
    
    @property
    @abstractmethod
    def mcp_url(self) -> str:
        """Get the MCP server URL for this tool."""
        pass
    
    @abstractmethod
    async def run(self, target: Any) -> ToolResult:
        """
        Execute the tool against the target.
        
        Args:
            target: Target to scan (domain, IP, URL list, etc.)
        
        Returns:
            ToolResult with execution results
        """
        pass
    
    @abstractmethod
    def parse_output(self, raw_output: str) -> dict[str, Any]:
        """
        Parse tool output into structured data.
        
        Args:
            raw_output: Raw output from tool execution
        
        Returns:
            Parsed data dictionary
        """
        pass
    
    async def call_mcp(
        self,
        tool_name: str,
        arguments: dict[str, Any],
    ) -> ToolResult:
        """
        Call an MCP tool endpoint.
        
        Args:
            tool_name: Name of the MCP tool
            arguments: Arguments to pass to the tool
        
        Returns:
            ToolResult with execution results
        """
        raw_url = (self.mcp_url or "").strip()
        if not raw_url:
            logger.warning("call_mcp skipped: MCP URL not configured", tool_name=tool_name)
            raise MCPConnectionError("MCP URL not configured")
        # Normalize base URL (no trailing slash) so path is exactly /tools/{tool_name}
        base = raw_url.rstrip("/")
        tool_url = f"{base}/tools/{tool_name}"
        start_time = time.perf_counter()
        # Log so "docker compose logs api | grep call_mcp" or "grep tool_url" shows URL used
        logger.info(
            "call_mcp posting to tool_url",
            tool_name=tool_name,
            mcp_base=base,
            tool_url=tool_url,
        )

        for attempt in range(self.retry_attempts):
            try:
                client = await self._get_http_client()

                # MCP servers expect the request body at top level (not wrapped in "arguments")
                response = await client.post(
                    tool_url,
                    json=arguments,
                )
                
                duration_ms = (time.perf_counter() - start_time) * 1000
                
                if response.status_code == 200:
                    result_data = response.json()
                    # MCP servers return structured JSON (success, subdomains/ports/resolved/...)
                    if isinstance(result_data, dict) and "success" in result_data:
                        log_tool_execution(
                            logger,
                            tool_name=self.name,
                            target=str(arguments.get("target", arguments.get("domain", arguments.get("hosts", [""])[0] if arguments.get("hosts") else "")))[:100],
                            success=result_data.get("success", True),
                            duration_ms=duration_ms,
                            error=result_data.get("error"),
                        )
                        return ToolResult(
                            success=result_data.get("success", True),
                            data=result_data,
                            error=result_data.get("error"),
                            duration_ms=duration_ms,
                            raw_output=str(result_data),
                            metadata={
                                "mcp_url": self.mcp_url,
                                "tool_name": tool_name,
                                "attempt": attempt + 1,
                            },
                        )
                    # Legacy: raw "result" string for parse_output
                    parsed = self.parse_output(result_data.get("result", ""))
                    log_tool_execution(
                        logger,
                        tool_name=self.name,
                        target=str(arguments.get("target", ""))[:100],
                        success=True,
                        duration_ms=duration_ms,
                    )
                    return ToolResult(
                        success=True,
                        data=parsed,
                        duration_ms=duration_ms,
                        raw_output=result_data.get("result"),
                        metadata={
                            "mcp_url": self.mcp_url,
                            "tool_name": tool_name,
                            "attempt": attempt + 1,
                        },
                    )
                
                else:
                    error_msg = response.text
                    if response.status_code == 404:
                        logger.warning(
                            "MCP POST returned 404; URL used by scan may differ from health check",
                            tool_name=tool_name,
                            tool_url=tool_url,
                            mcp_base=base,
                        )
                        # Diagnose: GET root to see what server is at this URL (scans use POST; GET /health can pass)
                        try:
                            root_resp = await client.get(f"{base}/")
                            root_preview = (root_resp.text or "")[:200] if root_resp.text else f"status={root_resp.status_code}"
                            error_msg = (
                                f"POST {tool_url} returned 404 (GET {base}/ returned: {root_preview}). "
                                "Rebuild mcp-recon so POST /tools/xxx exists: docker compose build mcp-recon && docker compose up -d mcp-recon"
                            )
                        except Exception:
                            error_msg = (
                                f"POST {tool_url} returned 404. "
                                "Rebuild mcp-recon: docker compose build mcp-recon && docker compose up -d mcp-recon"
                            )
                    if response.status_code >= 500:
                        # Server error - retry
                        logger.warning(
                            "MCP server error, retrying",
                            tool=self.name,
                            status=response.status_code,
                            attempt=attempt + 1,
                        )
                        await asyncio.sleep(self.retry_delay_seconds * (attempt + 1))
                        continue

                    # Client error - don't retry
                    log_tool_execution(
                        logger,
                        tool_name=self.name,
                        target=str(arguments.get("target", ""))[:100],
                        success=False,
                        duration_ms=duration_ms,
                        error=error_msg[:200] if error_msg else str(response.status_code),
                    )

                    return ToolResult(
                        success=False,
                        error=f"MCP error ({response.status_code}): {error_msg}",
                        duration_ms=duration_ms,
                    )
            
            except httpx.ConnectError as e:
                logger.warning(
                    "MCP connection failed, retrying",
                    tool=self.name,
                    url=self.mcp_url,
                    attempt=attempt + 1,
                    error=str(e),
                )
                
                if attempt < self.retry_attempts - 1:
                    await asyncio.sleep(self.retry_delay_seconds * (attempt + 1))
                    continue
                
                raise MCPConnectionError(
                    server_name=self.name,
                    url=self.mcp_url,
                ) from e
            
            except httpx.TimeoutException as e:
                duration_ms = (time.perf_counter() - start_time) * 1000
                
                log_tool_execution(
                    logger,
                    tool_name=self.name,
                    target=str(arguments.get("target", ""))[:100],
                    success=False,
                    duration_ms=duration_ms,
                    error="Timeout",
                )
                
                raise ToolTimeoutError(
                    tool_name=self.name,
                    timeout_seconds=self.timeout_seconds,
                ) from e
            
            except Exception as e:
                duration_ms = (time.perf_counter() - start_time) * 1000
                
                logger.exception(
                    "MCP call failed",
                    tool=self.name,
                    error=str(e),
                )
                
                return ToolResult(
                    success=False,
                    error=str(e),
                    duration_ms=duration_ms,
                )
        
        # All retries exhausted
        duration_ms = (time.perf_counter() - start_time) * 1000
        
        return ToolResult(
            success=False,
            error=f"All {self.retry_attempts} retry attempts exhausted",
            duration_ms=duration_ms,
        )
    
    async def execute_command(
        self,
        command: list[str],
        input_data: str | None = None,
    ) -> ToolResult:
        """
        Execute a tool directly as a subprocess.
        
        This is a fallback when MCP is not available.
        
        Args:
            command: Command and arguments to execute
            input_data: Optional stdin input
        
        Returns:
            ToolResult with execution results
        """
        start_time = time.perf_counter()
        
        try:
            process = await asyncio.create_subprocess_exec(
                *command,
                stdin=asyncio.subprocess.PIPE if input_data else None,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            
            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(
                        input=input_data.encode() if input_data else None
                    ),
                    timeout=self.timeout_seconds,
                )
            except asyncio.TimeoutError:
                process.kill()
                await process.wait()
                raise ToolTimeoutError(
                    tool_name=self.name,
                    timeout_seconds=self.timeout_seconds,
                )
            
            duration_ms = (time.perf_counter() - start_time) * 1000
            
            if process.returncode == 0:
                output = stdout.decode("utf-8", errors="replace")
                parsed = self.parse_output(output)
                
                log_tool_execution(
                    logger,
                    tool_name=self.name,
                    target=command[1] if len(command) > 1 else "",
                    success=True,
                    duration_ms=duration_ms,
                )
                
                return ToolResult(
                    success=True,
                    data=parsed,
                    duration_ms=duration_ms,
                    raw_output=output,
                )
            
            else:
                error = stderr.decode("utf-8", errors="replace")
                
                log_tool_execution(
                    logger,
                    tool_name=self.name,
                    target=command[1] if len(command) > 1 else "",
                    success=False,
                    duration_ms=duration_ms,
                    error=error[:100],
                )
                
                return ToolResult(
                    success=False,
                    error=f"Exit code {process.returncode}: {error[:500]}",
                    duration_ms=duration_ms,
                )
        
        except FileNotFoundError:
            return ToolResult(
                success=False,
                error=f"Tool not found: {command[0]}",
                duration_ms=(time.perf_counter() - start_time) * 1000,
            )
        
        except Exception as e:
            logger.exception(
                "Command execution failed",
                tool=self.name,
                command=command[0],
            )
            
            return ToolResult(
                success=False,
                error=str(e),
                duration_ms=(time.perf_counter() - start_time) * 1000,
            )
