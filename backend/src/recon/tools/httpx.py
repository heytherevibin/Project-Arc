"""
Httpx Tool

HTTP probing and technology detection.
"""

import json
from typing import Any

from core.config import get_settings
from recon.tools.base import BaseTool, ToolResult


class HttpxTool(BaseTool):
    """
    Httpx HTTP prober.
    
    Probes URLs to identify live hosts, extract headers,
    titles, and detect technologies.
    """
    
    name = "httpx"
    description = "HTTP probing and technology detection"
    timeout_seconds = 600  # 10 minutes
    
    @property
    def mcp_url(self) -> str:
        return get_settings().MCP_HTTPX_URL
    
    async def run(
        self,
        targets: list[str],
        follow_redirects: bool = True,
        threads: int = 50,
    ) -> ToolResult:
        """
        Probe URLs for HTTP response information.
        
        Args:
            targets: List of URLs to probe
            follow_redirects: Whether to follow redirects
            threads: Number of concurrent threads
        
        Returns:
            ToolResult with probe results
        """
        # Try MCP first
        try:
            return await self.call_mcp(
                tool_name="httpx_probe",
                arguments={
                    "urls": targets,
                    "follow_redirects": follow_redirects,
                    "threads": threads,
                    "tech_detect": True,
                    "status_code": True,
                    "title": True,
                    "content_length": True,
                    "content_type": True,
                    "server": True,
                },
            )
        except Exception:
            # Fall back to direct execution
            return await self._run_direct(targets, follow_redirects, threads)
    
    async def _run_direct(
        self,
        targets: list[str],
        follow_redirects: bool,
        threads: int,
    ) -> ToolResult:
        """Run Httpx directly as subprocess."""
        # Create input data (one URL per line)
        input_data = "\n".join(targets)
        
        command = [
            "httpx",
            "-silent",
            "-json",
            "-threads", str(threads),
            "-status-code",
            "-title",
            "-content-length",
            "-content-type",
            "-server",
            "-tech-detect",
        ]
        
        if follow_redirects:
            command.append("-follow-redirects")
        
        return await self.execute_command(command, input_data=input_data)
    
    def parse_output(self, raw_output: str) -> dict[str, Any]:
        """
        Parse Httpx JSON output.
        
        Args:
            raw_output: JSON lines output from Httpx
        
        Returns:
            Dictionary with probe results
        """
        probed: list[dict[str, Any]] = []
        live_urls: list[str] = []
        technologies: dict[str, list[str]] = {}
        
        for line in raw_output.strip().split("\n"):
            if not line:
                continue
            
            try:
                data = json.loads(line)
                
                url = data.get("url", "")
                status_code = data.get("status_code", 0)
                
                # Extract relevant fields
                result = {
                    "url": url,
                    "status_code": status_code,
                    "title": data.get("title", ""),
                    "content_length": data.get("content_length", 0),
                    "content_type": data.get("content_type", ""),
                    "server": data.get("webserver", data.get("server", "")),
                    "host": data.get("host", ""),
                    "final_url": data.get("final_url", url),
                    "tls": data.get("tls", {}),
                }
                
                # Extract technologies
                tech = data.get("tech", [])
                if tech:
                    result["technologies"] = tech
                    if url not in technologies:
                        technologies[url] = []
                    technologies[url].extend(tech)
                
                probed.append(result)
                
                # Consider URL live if status code is 2xx or 3xx
                if 200 <= status_code < 400:
                    live_urls.append(url)
            
            except json.JSONDecodeError:
                continue
        
        return {
            "probed": probed,
            "live_urls": live_urls,
            "technologies": technologies,
            "probed_count": len(probed),
            "live_count": len(live_urls),
        }
