"""
Subfinder Tool

Passive subdomain discovery using Subfinder.
"""

import json
from typing import Any

from core.config import get_settings
from recon.tools.base import BaseTool, ToolResult


class SubfinderTool(BaseTool):
    """
    Subfinder subdomain enumeration tool.
    
    Uses passive sources to discover subdomains for a given domain.
    Does not actively probe targets.
    """
    
    name = "subfinder"
    description = "Passive subdomain discovery"
    timeout_seconds = 600  # 10 minutes
    
    @property
    def mcp_url(self) -> str:
        return get_settings().MCP_SUBFINDER_URL
    
    async def run(self, target: str) -> ToolResult:
        """
        Run Subfinder against a domain.
        
        Args:
            target: Domain to enumerate subdomains for
        
        Returns:
            ToolResult with discovered subdomains
        """
        # Try MCP first
        try:
            return await self.call_mcp(
                tool_name="subfinder_scan",
                arguments={
                    "domain": target,
                    "all": True,
                    "recursive": True,
                },
            )
        except Exception:
            # Fall back to direct execution
            return await self._run_direct(target)
    
    async def _run_direct(self, target: str) -> ToolResult:
        """Run Subfinder directly as subprocess."""
        command = [
            "subfinder",
            "-d", target,
            "-all",
            "-silent",
            "-json",
            "-o", "-",
        ]
        
        return await self.execute_command(command)
    
    def parse_output(self, raw_output: str) -> dict[str, Any]:
        """
        Parse Subfinder JSON output.
        
        Args:
            raw_output: JSON lines output from Subfinder
        
        Returns:
            Dictionary with discovered subdomains
        """
        subdomains = set()
        
        for line in raw_output.strip().split("\n"):
            if not line:
                continue
            
            try:
                data = json.loads(line)
                
                if isinstance(data, dict):
                    # JSON format with metadata
                    host = data.get("host")
                    if host:
                        subdomains.add(host.lower())
                
                elif isinstance(data, str):
                    # Plain domain string
                    subdomains.add(data.lower())
            
            except json.JSONDecodeError:
                # Plain text output (one subdomain per line)
                subdomain = line.strip().lower()
                if subdomain and "." in subdomain:
                    subdomains.add(subdomain)
        
        return {
            "subdomains": sorted(list(subdomains)),
            "count": len(subdomains),
        }
