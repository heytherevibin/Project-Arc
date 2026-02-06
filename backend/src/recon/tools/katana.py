"""
Katana Tool

Web crawling and endpoint discovery.
"""

import json
from typing import Any
from urllib.parse import urlparse

from core.config import get_settings
from recon.tools.base import BaseTool, ToolResult


class KatanaTool(BaseTool):
    """
    Katana web crawler.
    
    Crawls websites to discover endpoints, parameters,
    JavaScript files, and forms.
    """
    
    name = "katana"
    description = "Web crawling and endpoint discovery"
    timeout_seconds = 900  # 15 minutes
    
    @property
    def mcp_url(self) -> str:
        return get_settings().MCP_KATANA_URL
    
    async def run(
        self,
        targets: list[str],
        depth: int = 3,
        js_crawl: bool = True,
        form_extraction: bool = True,
    ) -> ToolResult:
        """
        Crawl URLs to discover endpoints.
        
        Args:
            targets: List of URLs to crawl
            depth: Maximum crawl depth
            js_crawl: Whether to parse JavaScript for endpoints
            form_extraction: Whether to extract forms
        
        Returns:
            ToolResult with discovered endpoints
        """
        # Try MCP first
        try:
            return await self.call_mcp(
                tool_name="katana_crawl",
                arguments={
                    "urls": targets,
                    "depth": depth,
                    "js_crawl": js_crawl,
                    "form_extraction": form_extraction,
                    "automatic_form_fill": False,
                },
            )
        except Exception:
            # Fall back to direct execution
            return await self._run_direct(targets, depth, js_crawl)
    
    async def _run_direct(
        self,
        targets: list[str],
        depth: int,
        js_crawl: bool,
    ) -> ToolResult:
        """Run Katana directly as subprocess."""
        # Create input data (one URL per line)
        input_data = "\n".join(targets)
        
        command = [
            "katana",
            "-silent",
            "-json",
            "-depth", str(depth),
            "-field", "url,path,fqdn,file,dir,method,body",
        ]
        
        if js_crawl:
            command.extend(["-js-crawl"])
        
        return await self.execute_command(command, input_data=input_data)
    
    def parse_output(self, raw_output: str) -> dict[str, Any]:
        """
        Parse Katana JSON output.
        
        Args:
            raw_output: JSON lines output from Katana
        
        Returns:
            Dictionary with discovered endpoints
        """
        discovered_urls: set[str] = set()
        endpoints: list[dict[str, Any]] = []
        js_files: list[str] = []
        forms: list[dict[str, Any]] = []
        
        for line in raw_output.strip().split("\n"):
            if not line:
                continue
            
            try:
                data = json.loads(line)
                
                url = data.get("request", {}).get("url") or data.get("url", "")
                
                if not url:
                    continue
                
                discovered_urls.add(url)
                
                # Parse URL components
                parsed = urlparse(url)
                
                endpoint = {
                    "url": url,
                    "method": data.get("request", {}).get("method", "GET"),
                    "path": parsed.path or "/",
                    "query": parsed.query,
                    "source": data.get("source", "crawl"),
                }
                
                endpoints.append(endpoint)
                
                # Identify JavaScript files
                if url.endswith(".js") or ".js?" in url:
                    js_files.append(url)
                
                # Extract form data
                if data.get("request", {}).get("method") == "POST":
                    body = data.get("request", {}).get("body", "")
                    if body:
                        forms.append({
                            "url": url,
                            "method": "POST",
                            "parameters": self._parse_form_body(body),
                        })
            
            except json.JSONDecodeError:
                # Plain URL output
                url = line.strip()
                if url.startswith(("http://", "https://")):
                    discovered_urls.add(url)
        
        return {
            "discovered_urls": sorted(list(discovered_urls)),
            "endpoints": endpoints,
            "js_files": list(set(js_files)),
            "forms": forms,
            "total_urls": len(discovered_urls),
            "total_js_files": len(set(js_files)),
            "total_forms": len(forms),
        }
    
    def _parse_form_body(self, body: str) -> list[str]:
        """Parse form body to extract parameter names."""
        params = []
        
        # URL-encoded form
        if "=" in body:
            for pair in body.split("&"):
                if "=" in pair:
                    params.append(pair.split("=")[0])
        
        return params
