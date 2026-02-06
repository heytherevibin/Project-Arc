"""
Whois Tool

WHOIS lookups via MCP server.
"""

from typing import Any

from core.config import get_settings
from recon.tools.base import BaseTool, ToolResult


class WhoisTool(BaseTool):
    """Whois lookup tool. Uses MCP server only."""

    name = "whois"
    description = "WHOIS lookup"
    timeout_seconds = 30

    @property
    def mcp_url(self) -> str:
        return get_settings().MCP_WHOIS_URL

    async def run(self, target: str) -> ToolResult:
        """Run WHOIS lookup for a domain. Target is the domain."""
        return await self.call_mcp(
            tool_name="whois_lookup",
            arguments={
                "domain": (target or "").strip(),
            },
        )

    def parse_output(self, raw_output: str) -> dict[str, Any]:
        """Parse raw output (MCP returns structured JSON; fallback only)."""
        return {"whois": {}, "raw": raw_output}
