"""
Naabu Tool

Fast port scanning.
"""

import json
from typing import Any

from core.config import get_settings
from recon.tools.base import BaseTool, ToolResult


class NaabuTool(BaseTool):
    """
    Naabu port scanner.
    
    Fast SYN/CONNECT port scanning with service detection support.
    """
    
    name = "naabu"
    description = "Fast port scanning"
    timeout_seconds = 900  # 15 minutes
    
    @property
    def mcp_url(self) -> str:
        return get_settings().MCP_NAABU_URL
    
    async def run(
        self,
        targets: list[str],
        ports: str = "top-1000",
        rate: int = 1000,
    ) -> ToolResult:
        """
        Run port scan against targets.
        
        Args:
            targets: List of IPs or hostnames to scan
            ports: Port specification (e.g., "80,443", "1-65535", "top-1000")
            rate: Packets per second rate limit
        
        Returns:
            ToolResult with discovered open ports
        """
        # Try MCP first
        try:
            return await self.call_mcp(
                tool_name="naabu_scan",
                arguments={
                    "hosts": targets,
                    "ports": ports,
                    "rate": rate,
                    "scan_all_ips": True,
                },
            )
        except Exception:
            # Fall back to direct execution
            return await self._run_direct(targets, ports, rate)
    
    async def _run_direct(
        self,
        targets: list[str],
        ports: str,
        rate: int,
    ) -> ToolResult:
        """Run Naabu directly as subprocess."""
        # Create input data (one host per line)
        input_data = "\n".join(targets)
        
        # Build port argument
        port_arg = []
        if ports == "top-1000":
            port_arg = ["-top-ports", "1000"]
        elif ports == "top-100":
            port_arg = ["-top-ports", "100"]
        elif "-" in ports or "," in ports:
            port_arg = ["-p", ports]
        else:
            port_arg = ["-p", ports]
        
        command = [
            "naabu",
            "-silent",
            "-json",
            "-rate", str(rate),
            *port_arg,
        ]
        
        return await self.execute_command(command, input_data=input_data)
    
    def parse_output(self, raw_output: str) -> dict[str, Any]:
        """
        Parse Naabu JSON output.
        
        Args:
            raw_output: JSON lines output from Naabu
        
        Returns:
            Dictionary with discovered ports per host
        """
        ports: dict[str, list[int]] = {}
        
        for line in raw_output.strip().split("\n"):
            if not line:
                continue
            
            try:
                data = json.loads(line)
                
                host = data.get("host") or data.get("ip", "")
                port = data.get("port")
                
                if host and port:
                    if host not in ports:
                        ports[host] = []
                    if port not in ports[host]:
                        ports[host].append(port)
            
            except json.JSONDecodeError:
                # Try parsing as "host:port" format
                if ":" in line:
                    parts = line.strip().split(":")
                    if len(parts) == 2:
                        try:
                            host = parts[0]
                            port = int(parts[1])
                            if host not in ports:
                                ports[host] = []
                            if port not in ports[host]:
                                ports[host].append(port)
                        except ValueError:
                            continue
        
        # Sort ports for each host
        for host in ports:
            ports[host].sort()
        
        return {
            "ports": ports,
            "hosts_with_open_ports": len(ports),
            "total_open_ports": sum(len(p) for p in ports.values()),
        }
