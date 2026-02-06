"""
Nuclei Tool

Vulnerability scanning with templates.
"""

import json
from typing import Any

from core.config import get_settings
from core.constants import Severity
from recon.tools.base import BaseTool, ToolResult


class NucleiTool(BaseTool):
    """
    Nuclei vulnerability scanner.
    
    Template-based vulnerability scanning with 9000+ community templates.
    """
    
    name = "nuclei"
    description = "Template-based vulnerability scanning"
    timeout_seconds = 1800  # 30 minutes
    
    @property
    def mcp_url(self) -> str:
        return get_settings().MCP_NUCLEI_URL
    
    async def run(
        self,
        targets: list[str],
        severity: list[str] | None = None,
        tags: list[str] | None = None,
        rate_limit: int = 150,
    ) -> ToolResult:
        """
        Run Nuclei vulnerability scan.
        
        Args:
            targets: List of URLs to scan
            severity: Filter by severity (critical, high, medium, low, info)
            tags: Filter by template tags
            rate_limit: Requests per second limit
        
        Returns:
            ToolResult with discovered vulnerabilities
        """
        # Default to critical and high severity if not specified
        if severity is None:
            severity = ["critical", "high", "medium"]
        
        # Try MCP first
        try:
            return await self.call_mcp(
                tool_name="nuclei_scan",
                arguments={
                    "urls": targets,
                    "severity": severity,
                    "tags": tags,
                    "rate_limit": rate_limit,
                    "automatic_scan": True,
                },
            )
        except Exception:
            # Fall back to direct execution
            return await self._run_direct(targets, severity, tags, rate_limit)
    
    async def _run_direct(
        self,
        targets: list[str],
        severity: list[str],
        tags: list[str] | None,
        rate_limit: int,
    ) -> ToolResult:
        """Run Nuclei directly as subprocess."""
        # Create input data (one URL per line)
        input_data = "\n".join(targets)
        
        command = [
            "nuclei",
            "-silent",
            "-json",
            "-rate-limit", str(rate_limit),
            "-severity", ",".join(severity),
            "-automatic-scan",
        ]
        
        if tags:
            command.extend(["-tags", ",".join(tags)])
        
        return await self.execute_command(command, input_data=input_data)
    
    def parse_output(self, raw_output: str) -> dict[str, Any]:
        """
        Parse Nuclei JSON output.
        
        Args:
            raw_output: JSON lines output from Nuclei
        
        Returns:
            Dictionary with discovered vulnerabilities
        """
        vulnerabilities: list[dict[str, Any]] = []
        severity_counts = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
        }
        
        for line in raw_output.strip().split("\n"):
            if not line:
                continue
            
            try:
                data = json.loads(line)
                
                template_id = data.get("template-id", data.get("templateID", "unknown"))
                info = data.get("info", {})
                
                # Extract severity
                raw_severity = info.get("severity", "unknown").lower()
                try:
                    severity = Severity(raw_severity)
                except ValueError:
                    severity = Severity.UNKNOWN
                
                vuln = {
                    "template_id": template_id,
                    "name": info.get("name", template_id),
                    "severity": severity.value,
                    "description": info.get("description", ""),
                    "matched_at": data.get("matched-at", data.get("host", "")),
                    "evidence": data.get("extracted-results", data.get("matcher-name", "")),
                    "curl_command": data.get("curl-command", ""),
                    "timestamp": data.get("timestamp", ""),
                    "tags": info.get("tags", []),
                    "reference": info.get("reference", []),
                    "cve_id": self._extract_cve(info),
                    "cwe_id": self._extract_cwe(info),
                    "cvss_score": info.get("classification", {}).get("cvss-score"),
                }
                
                vulnerabilities.append(vuln)
                
                # Update counts
                if severity.value in severity_counts:
                    severity_counts[severity.value] += 1
            
            except json.JSONDecodeError:
                continue
        
        # Sort by severity (critical first)
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        vulnerabilities.sort(
            key=lambda v: severity_order.get(v["severity"], 5)
        )
        
        return {
            "vulnerabilities": vulnerabilities,
            "total": len(vulnerabilities),
            "by_severity": severity_counts,
        }
    
    def _extract_cve(self, info: dict[str, Any]) -> str | None:
        """Extract CVE ID from template info."""
        classification = info.get("classification", {})
        
        # Check cve-id field
        cve = classification.get("cve-id", [])
        if cve:
            return cve[0] if isinstance(cve, list) else cve
        
        # Check tags for CVE references
        tags = info.get("tags", [])
        for tag in tags:
            if tag.upper().startswith("CVE-"):
                return tag.upper()
        
        return None
    
    def _extract_cwe(self, info: dict[str, Any]) -> str | None:
        """Extract CWE ID from template info."""
        classification = info.get("classification", {})
        
        cwe = classification.get("cwe-id", [])
        if cwe:
            return cwe[0] if isinstance(cwe, list) else cwe
        
        return None
