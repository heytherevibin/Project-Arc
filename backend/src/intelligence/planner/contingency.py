"""
Contingency Planner

Generates backup plans when primary plan steps fail.  Uses TacticPlanner
phase tactics and FailureMemory to avoid known-bad approaches and
provide alternative tools/techniques.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from agents.shared.base_agent import Phase, ToolCall
from core.logging import get_logger

logger = get_logger(__name__)


@dataclass
class FallbackStep:
    """A single step in a fallback plan."""
    tool_name: str
    technique: str
    args: dict[str, Any]
    reason: str
    risk_level: str = "medium"
    requires_approval: bool = False


@dataclass
class ContingencyPlan:
    """A backup plan generated after a primary step fails."""
    original_tool: str
    original_technique: str
    failure_reason: str
    fallback_steps: list[FallbackStep]
    confidence: float  # 0-1


class ContingencyPlanner:
    """
    Generates alternative plans when the primary approach fails.

    Uses:
    - TacticPlanner phase tactics for alternatives within the same phase
    - FailureMemory to avoid previously failed approaches
    - Tool-technique affinity for intelligent substitution
    """

    # Tool substitution groups: tools in the same group are interchangeable
    TOOL_GROUPS: dict[str, list[str]] = {
        "subdomain_enum": ["subfinder", "knockpy"],
        "port_scan": ["naabu"],
        "vuln_scan": ["nuclei", "nikto", "gvm"],
        "web_exploit": ["sqlmap", "commix"],
        "exploit_framework": ["metasploit"],
        "credential_dump": ["impacket", "crackmapexec"],
        "c2": ["sliver", "havoc"],
        "ad_enum": ["bloodhound", "certipy"],
        "lateral_movement": ["impacket", "crackmapexec", "psexec", "wmi_exec"],
    }

    # Technique → fallback technique mapping
    TECHNIQUE_FALLBACKS: dict[str, list[str]] = {
        "sql_injection": ["command_injection", "ssrf", "file_upload"],
        "command_injection": ["sql_injection", "deserialization"],
        "metasploit_exploit": ["manual_exploit", "sql_injection"],
        "subdomain_enumeration": ["dns_bruteforce", "certificate_transparency"],
        "port_scanning": ["service_detection"],
        "kerberoasting": ["asreproasting", "password_spray"],
        "dcsync": ["credential_dump", "ntds_extraction"],
        "credential_dump": ["mimikatz", "lsass_dump"],
    }

    async def generate_fallback(
        self,
        failed_tool: str,
        failed_technique: str,
        failure_reason: str,
        phase: str,
        target: str,
        failure_memory: Any | None = None,
    ) -> ContingencyPlan:
        """
        Generate a contingency plan for a failed step.

        Parameters
        ----------
        failed_tool : the tool that failed
        failed_technique : the technique that failed
        failure_reason : why it failed
        phase : current attack phase
        target : target being attacked
        failure_memory : optional FailureMemory instance to check
        """
        alternatives = await self.get_alternative_tools(
            failed_tool, phase, target, failure_memory,
        )

        fallback_techniques = self.TECHNIQUE_FALLBACKS.get(failed_technique, [])

        fallback_steps: list[FallbackStep] = []

        # 1. Try alternative tools for the same technique
        for alt_tool in alternatives:
            fallback_steps.append(FallbackStep(
                tool_name=alt_tool,
                technique=failed_technique,
                args={"target": target},
                reason=f"Alternative tool for {failed_technique} (original: {failed_tool})",
                risk_level=self._tool_risk(alt_tool),
                requires_approval=self._needs_approval(alt_tool, phase),
            ))

        # 2. Try different techniques with compatible tools
        for alt_technique in fallback_techniques:
            tools = self._tools_for_technique(alt_technique)
            for tool in tools:
                if tool == failed_tool:
                    continue
                # Check failure memory
                if failure_memory:
                    should_avoid = await failure_memory.should_avoid(
                        alt_technique, target, tool,
                    )
                    if should_avoid:
                        continue

                fallback_steps.append(FallbackStep(
                    tool_name=tool,
                    technique=alt_technique,
                    args={"target": target},
                    reason=f"Alternative technique: {alt_technique} using {tool}",
                    risk_level=self._tool_risk(tool),
                    requires_approval=self._needs_approval(tool, phase),
                ))

        confidence = min(0.9, 0.3 + (0.1 * len(fallback_steps)))

        plan = ContingencyPlan(
            original_tool=failed_tool,
            original_technique=failed_technique,
            failure_reason=failure_reason,
            fallback_steps=fallback_steps[:5],  # top 5 alternatives
            confidence=confidence,
        )

        logger.info(
            "Contingency plan generated",
            original_tool=failed_tool,
            alternatives=len(plan.fallback_steps),
            confidence=confidence,
        )
        return plan

    async def get_alternative_tools(
        self,
        failed_tool: str,
        phase: str,
        target: str,
        failure_memory: Any | None = None,
    ) -> list[str]:
        """
        Get alternative tools for a failed tool within the same group.
        Filters out tools that have also failed against this target.
        """
        alternatives: list[str] = []
        for _group_name, group_tools in self.TOOL_GROUPS.items():
            if failed_tool in group_tools:
                for tool in group_tools:
                    if tool == failed_tool:
                        continue
                    if failure_memory:
                        should_avoid = await failure_memory.should_avoid(
                            tool, target,
                        )
                        if should_avoid:
                            continue
                    alternatives.append(tool)

        return alternatives

    async def replan_from_failure(
        self,
        state: dict[str, Any],
        failed_step: dict[str, Any],
        failure_memory: Any | None = None,
    ) -> list[ToolCall]:
        """
        Generate a new list of ToolCalls to replace a failed step,
        using the contingency planner.
        """
        plan = await self.generate_fallback(
            failed_tool=failed_step.get("tool", ""),
            failed_technique=failed_step.get("technique", ""),
            failure_reason=failed_step.get("error", "Unknown error"),
            phase=state.get("current_phase", Phase.RECON),
            target=state.get("target", ""),
            failure_memory=failure_memory,
        )

        tool_calls: list[ToolCall] = []
        for step in plan.fallback_steps:
            tool_calls.append(ToolCall(
                tool_name=step.tool_name,
                args=step.args,
                requires_approval=step.requires_approval,
                risk_level=step.risk_level,
            ))

        return tool_calls

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _tool_risk(tool: str) -> str:
        high_risk = {"metasploit", "sqlmap", "commix", "sliver", "havoc", "impacket"}
        medium_risk = {"crackmapexec", "certipy", "bloodhound", "nikto", "gvm"}
        if tool in high_risk:
            return "high"
        if tool in medium_risk:
            return "medium"
        return "low"

    @staticmethod
    def _needs_approval(tool: str, phase: str) -> bool:
        approval_phases = {Phase.EXPLOITATION, Phase.POST_EXPLOITATION, Phase.LATERAL_MOVEMENT}
        approval_tools = {"metasploit", "sqlmap", "commix", "sliver", "havoc", "impacket"}
        return phase in approval_phases or tool in approval_tools

    def _tools_for_technique(self, technique: str) -> list[str]:
        """Find tools that can execute a given technique."""
        technique_tool_map: dict[str, list[str]] = {
            "sql_injection": ["sqlmap"],
            "command_injection": ["commix"],
            "metasploit_exploit": ["metasploit"],
            "credential_dump": ["impacket", "crackmapexec"],
            "kerberoasting": ["impacket", "crackmapexec"],
            "asreproasting": ["impacket"],
            "password_spray": ["crackmapexec"],
            "dns_bruteforce": ["dnsx"],
            "certificate_transparency": ["subfinder"],
            "service_detection": ["httpx", "naabu"],
            "subdomain_enumeration": ["subfinder", "knockpy"],
            "ssrf": ["commix"],
            "deserialization": ["metasploit"],
            "file_upload": ["metasploit"],
            "manual_exploit": ["curl"],
            "mimikatz": ["impacket"],
            "lsass_dump": ["impacket"],
            "ntds_extraction": ["impacket"],
            "c2_implant": ["sliver", "havoc"],
        }
        return technique_tool_map.get(technique, [])
