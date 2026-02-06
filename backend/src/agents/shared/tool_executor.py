"""
MCP Tool Executor

Bridge between Arc agents and MCP tool servers.  Each tool is exposed
as an HTTP microservice (FastAPI) — this module provides a unified async
client that dispatches tool calls to the correct MCP server URL.
"""

from __future__ import annotations

import asyncio
from typing import Any

import httpx

from agents.shared.base_agent import ToolCall
from core.config import get_settings
from core.logging import get_logger

logger = get_logger(__name__)

# Default timeout for MCP calls (seconds)
_MCP_TIMEOUT = 300


class MCPToolExecutor:
    """
    Dispatches tool calls to MCP microservices over HTTP.

    Each MCP tool is a separate FastAPI server (or a port on the single
    mcp-recon container).  The executor resolves tool_name → URL from
    the application settings, sends a POST with the tool args, and
    returns the parsed JSON response.
    """

    def __init__(self, timeout: float = _MCP_TIMEOUT) -> None:
        self._settings = get_settings()
        self._timeout = timeout
        self._client: httpx.AsyncClient | None = None

    # ------------------------------------------------------------------
    # Tool-name → MCP URL mapping
    # ------------------------------------------------------------------

    def _resolve_url(self, tool_name: str) -> str | None:
        """Map a tool name to its MCP server URL (from settings / env)."""
        mapping: dict[str, str] = {
            # Core recon
            "naabu": self._settings.MCP_NAABU_URL,
            "naabu_scan": self._settings.MCP_NAABU_URL,
            "httpx": self._settings.MCP_HTTPX_URL,
            "httpx_probe": self._settings.MCP_HTTPX_URL,
            "subfinder": self._settings.MCP_SUBFINDER_URL,
            "dnsx": self._settings.MCP_DNSX_URL,
            "katana": self._settings.MCP_KATANA_URL,
            "nuclei": self._settings.MCP_NUCLEI_URL,
            "nuclei_scan": self._settings.MCP_NUCLEI_URL,
            # Extended recon
            "gau": getattr(self._settings, "MCP_GAU_URL", ""),
            "knockpy": getattr(self._settings, "MCP_KNOCKPY_URL", ""),
            "kiterunner": getattr(self._settings, "MCP_KITERUNNER_URL", ""),
            "wappalyzer": getattr(self._settings, "MCP_WAPPALYZER_URL", ""),
            "whois": getattr(self._settings, "MCP_WHOIS_URL", ""),
            "shodan": getattr(self._settings, "MCP_SHODAN_URL", ""),
            "github_recon": getattr(self._settings, "MCP_GITHUB_RECON_URL", ""),
            # Exploitation
            "metasploit": getattr(self._settings, "MCP_METASPLOIT_URL", ""),
            "metasploit_exploit": getattr(self._settings, "MCP_METASPLOIT_URL", ""),
            "sqlmap": getattr(self._settings, "MCP_SQLMAP_URL", ""),
            "sqlmap_inject": getattr(self._settings, "MCP_SQLMAP_URL", ""),
            "commix": getattr(self._settings, "MCP_COMMIX_URL", ""),
            "commix_scan": getattr(self._settings, "MCP_COMMIX_URL", ""),
            # Vulnerability scanning
            "gvm": getattr(self._settings, "MCP_GVM_URL", ""),
            "gvm_scan": getattr(self._settings, "MCP_GVM_URL", ""),
            "nikto": getattr(self._settings, "MCP_NIKTO_URL", ""),
            "nikto_scan": getattr(self._settings, "MCP_NIKTO_URL", ""),
            # C2
            "sliver": getattr(self._settings, "MCP_SLIVER_URL", ""),
            "sliver_implant": getattr(self._settings, "MCP_SLIVER_URL", ""),
            "havoc": getattr(self._settings, "MCP_HAVOC_URL", ""),
            "havoc_c2": getattr(self._settings, "MCP_HAVOC_URL", ""),
            # AD / Identity
            "bloodhound": getattr(self._settings, "MCP_BLOODHOUND_URL", ""),
            "bloodhound_collect": getattr(self._settings, "MCP_BLOODHOUND_URL", ""),
            "certipy": getattr(self._settings, "MCP_CERTIPY_URL", ""),
            "certipy_find": getattr(self._settings, "MCP_CERTIPY_URL", ""),
            "impacket": getattr(self._settings, "MCP_IMPACKET_URL", ""),
            "crackmapexec": getattr(self._settings, "MCP_CRACKMAPEXEC_URL", ""),
            # Utilities
            "curl": getattr(self._settings, "MCP_CURL_URL", ""),
            "curl_request": getattr(self._settings, "MCP_CURL_URL", ""),
            "proxychains": getattr(self._settings, "MCP_PROXYCHAINS_URL", ""),
            "proxychains_exec": getattr(self._settings, "MCP_PROXYCHAINS_URL", ""),
        }
        url = mapping.get(tool_name, "")
        return url if url else None

    # ------------------------------------------------------------------
    # Execution
    # ------------------------------------------------------------------

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(timeout=self._timeout)
        return self._client

    async def execute(self, tool_call: ToolCall) -> dict[str, Any]:
        """
        Execute a tool call against its MCP server.

        Returns the parsed JSON response body.

        Raises:
            ToolExecutionError: if the MCP server is unreachable or
                returns a non-2xx response.
        """
        url = self._resolve_url(tool_call.tool_name)
        if not url:
            raise ToolExecutionError(
                f"No MCP URL configured for tool '{tool_call.tool_name}'"
            )

        # MCP convention: POST /run with JSON body
        endpoint = f"{url.rstrip('/')}/run"

        logger.info(
            "Dispatching tool call to MCP",
            tool=tool_call.tool_name,
            endpoint=endpoint,
        )

        client = await self._get_client()

        try:
            response = await client.post(
                endpoint,
                json={
                    "tool": tool_call.tool_name,
                    "args": tool_call.args,
                },
            )
            response.raise_for_status()
            data = response.json()

            logger.info(
                "MCP tool response received",
                tool=tool_call.tool_name,
                status=response.status_code,
            )

            return data

        except httpx.TimeoutException as exc:
            raise ToolExecutionError(
                f"Timeout calling MCP tool '{tool_call.tool_name}' at {endpoint}"
            ) from exc
        except httpx.HTTPStatusError as exc:
            body = exc.response.text[:500] if exc.response else ""
            raise ToolExecutionError(
                f"MCP tool '{tool_call.tool_name}' returned {exc.response.status_code}: {body}"
            ) from exc
        except httpx.ConnectError as exc:
            raise ToolExecutionError(
                f"Cannot reach MCP server for '{tool_call.tool_name}' at {url}"
            ) from exc

    async def health_check(self, tool_name: str) -> bool:
        """Check if a specific MCP server is healthy."""
        url = self._resolve_url(tool_name)
        if not url:
            return False

        try:
            client = await self._get_client()
            resp = await client.get(f"{url.rstrip('/')}/health", timeout=5.0)
            return resp.status_code == 200
        except Exception:
            return False

    async def close(self) -> None:
        """Close the underlying HTTP client."""
        if self._client and not self._client.is_closed:
            await self._client.aclose()
            self._client = None


class ToolExecutionError(Exception):
    """Raised when a tool execution fails at the MCP layer."""


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------

_executor: MCPToolExecutor | None = None


def get_tool_executor() -> MCPToolExecutor:
    """Get or create the global tool executor."""
    global _executor
    if _executor is None:
        _executor = MCPToolExecutor()
    return _executor
