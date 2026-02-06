"""
GitHub Recon Tool

GitHub repo/code search via MCP server. Uses GITHUB_TOKEN on MCP side.
"""

from typing import Any

from core.config import get_settings
from recon.tools.base import BaseTool, ToolResult


class GitHubReconTool(BaseTool):
    """GitHub recon tool. Uses MCP server only (MCP reads GITHUB_TOKEN from env)."""

    name = "github_recon"
    description = "GitHub repo/code search"
    timeout_seconds = 30

    @property
    def mcp_url(self) -> str:
        return get_settings().MCP_GITHUB_RECON_URL

    async def run(self, target: str) -> ToolResult:
        """Search GitHub. Target is the search query (e.g. org:company, repo:user/repo)."""
        query = (target or "").strip()
        if not query:
            return ToolResult(success=False, error="query is required")
        return await self.call_mcp(
            tool_name="github_search",
            arguments={
                "query": query,
                "search_type": "repositories",
                "per_page": 30,
            },
        )

    def parse_output(self, raw_output: str) -> dict[str, Any]:
        """Parse raw output (MCP returns structured JSON; fallback only)."""
        return {"repos": [], "findings": [], "total_count": 0}
