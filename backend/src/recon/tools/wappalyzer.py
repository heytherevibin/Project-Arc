"""
Wappalyzer Tool

Technology fingerprinting via MCP server.
"""

from typing import Any

from core.config import get_settings
from recon.tools.base import BaseTool, ToolResult


class WappalyzerTool(BaseTool):
    """Wappalyzer technology fingerprinting tool. Uses MCP server only."""

    name = "wappalyzer"
    description = "Technology fingerprinting"
    timeout_seconds = 60

    @property
    def mcp_url(self) -> str:
        return get_settings().MCP_WAPPALYZER_URL

    async def run(self, target: str) -> ToolResult:
        """Run Wappalyzer against a URL. Target is the URL to analyze."""
        url = (target or "").strip()
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        return await self.call_mcp(
            tool_name="wappalyzer_scan",
            arguments={
                "url": url,
                "timeout": 30,
            },
        )

    def parse_output(self, raw_output: str) -> dict[str, Any]:
        """Parse raw output (MCP returns structured JSON; fallback only)."""
        return {"technologies": [], "url": ""}
