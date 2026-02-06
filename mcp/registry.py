"""
MCP Tool Registry

Central registry of all MCP servers with name, URL, port, health
status, and supported phases.  Provides discovery and phase-based
tool lookup.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from core.logging import get_logger

logger = get_logger(__name__)


@dataclass
class ToolRegistration:
    """A registered MCP tool server."""
    name: str
    url: str
    port: int
    phases: list[str] = field(default_factory=list)
    description: str = ""
    healthy: bool = False
    last_health_check: str = ""
    version: str = "1.0.0"


class ToolRegistry:
    """
    Central registry for MCP tool servers.

    Provides:
    - Registration and discovery
    - Phase-based tool lookup
    - Health status tracking
    """

    def __init__(self) -> None:
        self._tools: dict[str, ToolRegistration] = {}

    def register(
        self,
        name: str,
        url: str,
        port: int,
        phases: list[str] | None = None,
        description: str = "",
    ) -> None:
        """Register an MCP tool server."""
        self._tools[name] = ToolRegistration(
            name=name,
            url=url,
            port=port,
            phases=phases or [],
            description=description,
        )
        logger.debug("Tool registered", name=name, port=port)

    def unregister(self, name: str) -> None:
        """Remove a tool from the registry."""
        self._tools.pop(name, None)

    def discover(self) -> list[ToolRegistration]:
        """Return all registered tools."""
        return list(self._tools.values())

    def get_tool(self, name: str) -> ToolRegistration | None:
        """Get a specific tool by name."""
        return self._tools.get(name)

    def get_tools_for_phase(self, phase: str) -> list[ToolRegistration]:
        """Get all tools that support a given attack phase."""
        return [
            t for t in self._tools.values()
            if phase in t.phases
        ]

    def update_health(self, name: str, healthy: bool) -> None:
        """Update health status for a tool."""
        tool = self._tools.get(name)
        if tool:
            tool.healthy = healthy
            tool.last_health_check = datetime.now(timezone.utc).isoformat()

    async def health_check_all(
        self,
        http_client: Any | None = None,
        timeout: float = 5.0,
    ) -> dict[str, bool]:
        """
        Check health of all registered tools.
        Returns {tool_name: healthy_bool}.
        """
        results: dict[str, bool] = {}

        for name, tool in self._tools.items():
            healthy = False
            if http_client:
                try:
                    url = f"{tool.url}/health"
                    response = await http_client.get(url, timeout=timeout)
                    healthy = response.status_code == 200
                except Exception:
                    healthy = False

            self.update_health(name, healthy)
            results[name] = healthy

        healthy_count = sum(1 for v in results.values() if v)
        logger.info(
            "Health check complete",
            total=len(results),
            healthy=healthy_count,
            unhealthy=len(results) - healthy_count,
        )

        return results

    @property
    def healthy_tools(self) -> list[ToolRegistration]:
        return [t for t in self._tools.values() if t.healthy]

    @property
    def size(self) -> int:
        return len(self._tools)


def create_default_registry() -> ToolRegistry:
    """Create a registry with all default Arc MCP tools pre-registered."""
    registry = ToolRegistry()

    # Core Recon
    _reg = [
        ("naabu", 8000, ["recon"], "Port scanner"),
        ("httpx", 8001, ["recon"], "HTTP prober"),
        ("subfinder", 8002, ["recon"], "Subdomain discovery"),
        ("dnsx", 8003, ["recon"], "DNS resolver"),
        ("katana", 8004, ["recon"], "Web crawler"),
        ("nuclei", 8005, ["recon", "vuln_analysis"], "Vulnerability scanner"),
        ("gau", 8006, ["recon"], "URL aggregator"),
        ("knockpy", 8007, ["recon"], "Subdomain scanner"),
        ("kiterunner", 8008, ["recon"], "API endpoint discovery"),
        ("wappalyzer", 8009, ["recon"], "Technology fingerprinting"),
        ("whois", 8010, ["recon"], "WHOIS lookup"),
        ("shodan", 8011, ["recon"], "Shodan search"),
        ("github_recon", 8012, ["recon"], "GitHub OSINT"),
        # Vulnerability Scanning
        ("gvm", 8013, ["vuln_analysis"], "GVM/OpenVAS scanner"),
        ("nikto", 8014, ["vuln_analysis"], "Nikto web scanner"),
        # Exploitation
        ("metasploit", 8020, ["exploitation"], "Metasploit framework"),
        ("sqlmap", 8021, ["exploitation"], "SQL injection"),
        ("commix", 8022, ["exploitation"], "Command injection"),
        # C2
        ("sliver", 8030, ["post_exploitation", "lateral_movement"], "Sliver C2"),
        ("havoc", 8031, ["post_exploitation", "lateral_movement"], "Havoc C2"),
        # AD/Identity
        ("bloodhound", 8040, ["recon", "post_exploitation"], "BloodHound AD"),
        ("certipy", 8041, ["post_exploitation"], "ADCS enumeration"),
        ("impacket", 8042, ["exploitation", "post_exploitation", "lateral_movement"], "Impacket suite"),
        ("crackmapexec", 8043, ["post_exploitation", "lateral_movement"], "CrackMapExec"),
        # Utility
        ("curl", 8050, ["recon", "exploitation"], "HTTP client"),
        ("proxychains", 8051, ["recon", "exploitation"], "Proxychains routing"),
        ("tor", 8052, ["recon"], "Tor proxy"),
    ]

    base_url = "http://mcp-recon"
    for name, port, phases, desc in _reg:
        registry.register(name, f"{base_url}:{port}", port, phases, desc)

    return registry
