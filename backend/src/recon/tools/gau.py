"""
GAU Tool

URL discovery from Wayback Machine, Common Crawl, etc. via MCP server.
"""

from typing import Any

from core.config import get_settings
from recon.tools.base import BaseTool, ToolResult


class GauTool(BaseTool):
    """GAU URL discovery tool. Uses MCP server only; no hardcoded URLs."""

    name = "gau"
    description = "URL discovery (Wayback, Common Crawl)"
    timeout_seconds = 600

    @property
    def mcp_url(self) -> str:
        return get_settings().MCP_GAU_URL

    async def run(self, target: str) -> ToolResult:
        """Run GAU against a domain. Target is the domain to fetch URLs for."""
        return await self.call_mcp(
            tool_name="gau_scan",
            arguments={
                "domain": (target or "").strip(),
                "timeout": 300,
            },
        )

    def parse_output(self, raw_output: str) -> dict[str, Any]:
        """Parse raw output (MCP returns structured JSON; fallback only)."""
        return {"urls": [], "count": 0}
