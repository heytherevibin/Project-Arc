"""
Reconnaissance Specialist Agent

Handles passive and active reconnaissance including subdomain discovery,
port scanning, HTTP probing, web crawling, and OSINT collection.
"""

from __future__ import annotations

from typing import Any

from agents.shared.base_agent import BaseAgent, Phase, ToolCall, ToolResponse
from core.logging import get_logger

logger = get_logger(__name__)


class ReconSpecialist(BaseAgent):
    """Specialist agent for reconnaissance operations."""

    agent_id = "recon"
    agent_name = "Reconnaissance Specialist"
    supported_phases = [Phase.RECON]
    available_tools = [
        "subfinder", "dnsx", "naabu", "httpx", "katana",
        "gau", "shodan", "wappalyzer", "whois", "knockpy",
        "kiterunner", "github_recon",
    ]

    async def plan(self, state: dict[str, Any]) -> list[ToolCall]:
        """Plan reconnaissance actions based on current state."""
        target = state.get("target", "")
        discovered_hosts = state.get("discovered_hosts", [])
        calls: list[ToolCall] = []

        if not target:
            return calls

        # Phase 1: Passive recon (low noise)
        if not discovered_hosts:
            calls.append(ToolCall(
                tool_name="subfinder",
                args={"target": target},
                risk_level="low",
            ))
            calls.append(ToolCall(
                tool_name="whois",
                args={"target": target},
                risk_level="low",
            ))
            calls.append(ToolCall(
                tool_name="shodan",
                args={"target": target},
                risk_level="low",
            ))

        # Phase 2: Active recon (after passive)
        else:
            calls.append(ToolCall(
                tool_name="dnsx",
                args={"targets": discovered_hosts[:50]},
                risk_level="low",
            ))
            calls.append(ToolCall(
                tool_name="naabu",
                args={"targets": discovered_hosts[:20]},
                risk_level="low",
            ))
            calls.append(ToolCall(
                tool_name="httpx",
                args={"targets": discovered_hosts[:50]},
                risk_level="low",
            ))

        return calls

    async def analyze(self, state: dict[str, Any], results: list[ToolResponse]) -> dict[str, Any]:
        """Analyze recon results and update state."""
        for result in results:
            if not result.success or not result.data:
                continue

            data = result.data if isinstance(result.data, dict) else {}

            # Extract subdomains
            subdomains = data.get("subdomains", [])
            if subdomains:
                existing = set(state.get("discovered_hosts", []))
                existing.update(subdomains)
                state["discovered_hosts"] = list(existing)

            # Extract IPs
            resolved = data.get("resolved", {})
            for sub, ips in resolved.items():
                existing = set(state.get("discovered_hosts", []))
                existing.update(ips)
                state["discovered_hosts"] = list(existing)

            # Extract live URLs
            live_urls = data.get("live_urls", [])
            if live_urls:
                existing = state.get("discovered_hosts", [])
                state["discovered_hosts"] = list(set(existing + live_urls))

        logger.info(
            "Recon analysis complete",
            hosts_discovered=len(state.get("discovered_hosts", [])),
        )
        return state
