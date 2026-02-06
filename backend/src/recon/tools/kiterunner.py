"""
Kiterunner Tool

API endpoint discovery via MCP server.
"""

from typing import Any

from core.config import get_settings
from recon.tools.base import BaseTool, ToolResult


class KiterunnerTool(BaseTool):
    """Kiterunner API discovery tool. Uses MCP server only."""

    name = "kiterunner"
    description = "API endpoint discovery"
    timeout_seconds = 900

    @property
    def mcp_url(self) -> str:
        return get_settings().MCP_KITERUNNER_URL

    async def run(self, target: str) -> ToolResult:
        """Run Kiterunner against a base URL. Target is the URL to scan."""
        url = (target or "").strip()
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        return await self.call_mcp(
            tool_name="kiterunner_scan",
            arguments={
                "url": url,
                "timeout": 600,
            },
        )

    def parse_output(self, raw_output: str) -> dict[str, Any]:
        """Parse raw output (MCP returns structured JSON; fallback only)."""
        return {"endpoints": [], "count": 0}
