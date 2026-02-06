"""
Knockpy Tool

Active subdomain brute-force via MCP server.
"""

from typing import Any

from core.config import get_settings
from recon.tools.base import BaseTool, ToolResult


class KnockpyTool(BaseTool):
    """Knockpy subdomain brute-force tool. Uses MCP server only."""

    name = "knockpy"
    description = "Active subdomain brute-force"
    timeout_seconds = 600

    @property
    def mcp_url(self) -> str:
        return get_settings().MCP_KNOCKPY_URL

    async def run(self, target: str) -> ToolResult:
        """Run Knockpy against a domain."""
        return await self.call_mcp(
            tool_name="knockpy_scan",
            arguments={
                "domain": (target or "").strip(),
                "timeout": 300,
            },
        )

    def parse_output(self, raw_output: str) -> dict[str, Any]:
        """Parse raw output (MCP returns structured JSON; fallback only)."""
        return {"subdomains": [], "count": 0}
