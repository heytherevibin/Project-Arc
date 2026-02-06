"""
OSINT Collector

Orchestrates passive reconnaissance tools (Shodan, Whois, GAU, GitHub)
in parallel, merging results into a unified data structure.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any

from core.logging import get_logger

logger = get_logger(__name__)


@dataclass
class OSINTResult:
    """Aggregated OSINT collection result."""
    domain: str
    subdomains: list[str] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)
    ips: list[str] = field(default_factory=list)
    technologies: list[dict[str, Any]] = field(default_factory=list)
    whois_info: dict[str, Any] = field(default_factory=dict)
    shodan_info: list[dict[str, Any]] = field(default_factory=list)
    github_leaks: list[dict[str, Any]] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


class OSINTCollector:
    """
    Orchestrates passive recon tools in parallel.

    Runs Shodan, Whois, GAU, GitHub recon concurrently and
    merges all results into a single OSINTResult.
    """

    def __init__(self, tool_executor: Any | None = None) -> None:
        """
        Parameters
        ----------
        tool_executor : optional MCPToolExecutor or similar callable
                        that can run tool_name + args and return results
        """
        self._executor = tool_executor

    async def collect(
        self,
        domain: str,
        tools: list[str] | None = None,
        timeout: float = 300.0,
    ) -> OSINTResult:
        """
        Run all passive tools in parallel and merge results.

        Parameters
        ----------
        domain  : target domain
        tools   : optional list of tool names to run (defaults to all)
        timeout : overall timeout in seconds
        """
        available = tools or ["subfinder", "whois", "gau", "shodan", "github_recon"]
        result = OSINTResult(domain=domain)

        tasks = []
        for tool in available:
            tasks.append(self._run_tool(tool, domain))

        completed = await asyncio.gather(*tasks, return_exceptions=True)

        for tool_name, outcome in zip(available, completed):
            if isinstance(outcome, Exception):
                result.errors.append(f"{tool_name}: {outcome}")
                logger.warning("OSINT tool failed", tool=tool_name, error=str(outcome))
                continue
            self._merge(result, tool_name, outcome)

        logger.info(
            "OSINT collection complete",
            domain=domain,
            subdomains=len(result.subdomains),
            urls=len(result.urls),
            errors=len(result.errors),
        )
        return result

    async def _run_tool(self, tool_name: str, domain: str) -> dict[str, Any]:
        """Execute a single tool via the executor."""
        if self._executor is None:
            return {}

        args: dict[str, Any] = {"domain": domain}

        if tool_name == "subfinder":
            args["silent"] = True
        elif tool_name == "gau":
            args["threads"] = 5
        elif tool_name == "shodan":
            args["query"] = domain
        elif tool_name == "github_recon":
            args["org"] = domain

        try:
            if hasattr(self._executor, "execute"):
                result = await self._executor.execute(tool_name, args)
                return result if isinstance(result, dict) else {"raw": result}
            return {}
        except Exception as exc:
            raise RuntimeError(f"{tool_name} execution failed: {exc}") from exc

    @staticmethod
    def _merge(result: OSINTResult, tool: str, data: dict[str, Any]) -> None:
        """Merge a single tool's output into the aggregated result."""
        if tool == "subfinder":
            subs = data.get("subdomains", data.get("hosts", []))
            result.subdomains.extend(s for s in subs if s not in result.subdomains)

        elif tool == "whois":
            result.whois_info = data

        elif tool == "gau":
            urls = data.get("urls", [])
            result.urls.extend(u for u in urls if u not in result.urls)

        elif tool == "shodan":
            hosts = data.get("matches", data.get("hosts", []))
            result.shodan_info.extend(hosts)
            for h in hosts:
                ip = h.get("ip_str") or h.get("ip", "")
                if ip and ip not in result.ips:
                    result.ips.append(ip)

        elif tool == "github_recon":
            leaks = data.get("results", data.get("leaks", []))
            result.github_leaks.extend(leaks)
