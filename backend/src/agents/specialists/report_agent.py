"""
Reporting Specialist Agent

Generates penetration test reports with MITRE ATT&CK mapping,
risk scoring, and remediation recommendations.
"""

from __future__ import annotations

from typing import Any

from agents.shared.base_agent import BaseAgent, Phase, ToolCall, ToolResponse
from core.logging import get_logger

logger = get_logger(__name__)


class ReportSpecialist(BaseAgent):
    """Specialist agent for report generation."""

    agent_id = "report"
    agent_name = "Reporting Specialist"
    supported_phases = [Phase.REPORTING]
    available_tools = ["report_generator"]

    async def plan(self, state: dict[str, Any]) -> list[ToolCall]:
        """Plan report generation."""
        return [ToolCall(
            tool_name="report_generator",
            args={
                "mission_id": state.get("mission_id", ""),
                "project_id": state.get("project_id", ""),
                "target": state.get("target", ""),
                "vulns": state.get("discovered_vulns", []),
                "compromised_hosts": state.get("compromised_hosts", []),
                "credentials": state.get("harvested_creds", []),
                "phase_history": state.get("phase_history", []),
            },
            risk_level="low",
        )]

    async def analyze(self, state: dict[str, Any], results: list[ToolResponse]) -> dict[str, Any]:
        """Finalize reporting results."""
        for result in results:
            if result.success and result.data:
                state["report"] = result.data

        logger.info("Report generation complete", mission=state.get("mission_id"))
        return state
