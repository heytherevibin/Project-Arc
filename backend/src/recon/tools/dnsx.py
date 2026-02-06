"""
dnsx Tool

DNS resolution and enumeration.
"""

import json
from typing import Any

from core.config import get_settings
from recon.tools.base import BaseTool, ToolResult


class DnsxTool(BaseTool):
    """
    dnsx DNS resolution tool.
    
    Resolves hostnames to IP addresses with support for
    multiple record types (A, AAAA, CNAME, MX, etc.).
    """
    
    name = "dnsx"
    description = "DNS resolution and enumeration"
    timeout_seconds = 300  # 5 minutes
    
    @property
    def mcp_url(self) -> str:
        return get_settings().MCP_DNSX_URL
    
    async def run(self, targets: list[str]) -> ToolResult:
        """
        Resolve DNS for a list of hostnames.
        
        Args:
            targets: List of hostnames to resolve
        
        Returns:
            ToolResult with resolution results
        """
        # Try MCP first
        try:
            return await self.call_mcp(
                tool_name="dnsx_resolve",
                arguments={
                    "hosts": targets,
                    "a": True,
                    "aaaa": True,
                    "cname": True,
                    "resp": True,
                },
            )
        except Exception:
            # Fall back to direct execution
            return await self._run_direct(targets)
    
    async def _run_direct(self, targets: list[str]) -> ToolResult:
        """Run dnsx directly as subprocess."""
        # Create input data (one host per line)
        input_data = "\n".join(targets)
        
        command = [
            "dnsx",
            "-silent",
            "-json",
            "-a",
            "-aaaa",
            "-cname",
            "-resp",
        ]
        
        return await self.execute_command(command, input_data=input_data)
    
    def parse_output(self, raw_output: str) -> dict[str, Any]:
        """
        Parse dnsx JSON output.
        
        Args:
            raw_output: JSON lines output from dnsx
        
        Returns:
            Dictionary with resolution results
        """
        resolved: dict[str, list[str]] = {}
        records: list[dict[str, Any]] = []
        
        for line in raw_output.strip().split("\n"):
            if not line:
                continue
            
            try:
                data = json.loads(line)
                
                host = data.get("host", "").lower()
                if not host:
                    continue
                
                # Extract A records (IPv4)
                a_records = data.get("a", [])
                if a_records:
                    if host not in resolved:
                        resolved[host] = []
                    resolved[host].extend(a_records)
                
                # Extract AAAA records (IPv6)
                aaaa_records = data.get("aaaa", [])
                if aaaa_records:
                    if host not in resolved:
                        resolved[host] = []
                    resolved[host].extend(aaaa_records)
                
                # Store full record for detailed info
                records.append({
                    "host": host,
                    "a": a_records,
                    "aaaa": aaaa_records,
                    "cname": data.get("cname", []),
                    "status_code": data.get("status_code"),
                })
            
            except json.JSONDecodeError:
                # Skip malformed lines
                continue
        
        # Deduplicate IPs
        for host in resolved:
            resolved[host] = list(set(resolved[host]))
        
        return {
            "resolved": resolved,
            "records": records,
            "resolved_count": len(resolved),
            "total_ips": sum(len(ips) for ips in resolved.values()),
        }
