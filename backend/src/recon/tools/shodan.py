"""
Shodan Tool

Passive recon via Shodan InternetDB or Shodan API. Uses MCP server only.
"""

from typing import Any

from core.config import get_settings
from recon.tools.base import BaseTool, ToolResult


class ShodanTool(BaseTool):
    """Shodan passive recon tool. Uses MCP server only."""

    name = "shodan"
    description = "Passive recon (InternetDB / Shodan API)"
    timeout_seconds = 30

    @property
    def mcp_url(self) -> str:
        return get_settings().MCP_SHODAN_URL

    async def run(self, target: str) -> ToolResult:
        """Look up IP or domain. Target can be an IP (InternetDB) or domain (requires SHODAN_API_KEY on MCP)."""
        t = (target or "").strip()
        if not t:
            return ToolResult(success=False, error="target (ip or domain) is required")
        # Use ip param for IPv4 (dotted quad) or IPv6 (contains colon); else domain
        parts = t.split(".")
        if len(parts) == 4 and all(p.isdigit() and len(p) and 0 <= int(p) <= 255 for p in parts):
            return await self.call_mcp(tool_name="shodan_lookup", arguments={"ip": t})
        if ":" in t:
            return await self.call_mcp(tool_name="shodan_lookup", arguments={"ip": t})
        return await self.call_mcp(tool_name="shodan_lookup", arguments={"domain": t})

    def parse_output(self, raw_output: str) -> dict[str, Any]:
        """Parse raw output (MCP returns structured JSON; fallback only)."""
        return {"data": {}}
