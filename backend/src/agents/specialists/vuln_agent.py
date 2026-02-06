"""
Vulnerability Analysis Specialist Agent

Handles vulnerability scanning, CVE lookup, and risk assessment.
"""

from __future__ import annotations

from typing import Any

from agents.shared.base_agent import BaseAgent, Phase, ToolCall, ToolResponse
from core.logging import get_logger

logger = get_logger(__name__)


class VulnAnalysisSpecialist(BaseAgent):
    """Specialist agent for vulnerability analysis."""

    agent_id = "vuln_analysis"
    agent_name = "Vulnerability Analysis Specialist"
    supported_phases = [Phase.VULN_ANALYSIS]
    available_tools = ["nuclei", "nikto", "openvas"]

    async def plan(self, state: dict[str, Any]) -> list[ToolCall]:
        """Plan vulnerability scanning actions."""
        hosts = state.get("discovered_hosts", [])
        calls: list[ToolCall] = []

        if not hosts:
            return calls

        # Run Nuclei against discovered hosts
        calls.append(ToolCall(
            tool_name="nuclei",
            args={"targets": hosts[:100]},
            risk_level="medium",
        ))

        return calls

    async def analyze(self, state: dict[str, Any], results: list[ToolResponse]) -> dict[str, Any]:
        """Analyze vulnerability scan results."""
        for result in results:
            if not result.success or not result.data:
                continue

            data = result.data if isinstance(result.data, dict) else {}
            vulns = data.get("vulnerabilities", [])

            existing_vulns = state.get("discovered_vulns", [])
            existing_vulns.extend(vulns)
            state["discovered_vulns"] = existing_vulns

        logger.info(
            "Vuln analysis complete",
            vulns_found=len(state.get("discovered_vulns", [])),
        )
        return state
