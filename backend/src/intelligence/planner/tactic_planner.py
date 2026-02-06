"""
Tactic Planner

Phase-level planning that decides which specific techniques and
tools to use within a given attack phase.  Works with the procedural
memory to prioritize techniques with higher historical success rates.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from agents.shared.base_agent import Phase, ToolCall
from core.logging import get_logger

logger = get_logger(__name__)


@dataclass
class TacticRecommendation:
    """A recommended tactic with reasoning."""
    tool_name: str
    technique: str
    reason: str
    confidence: float        # 0.0–1.0
    risk_level: str
    requires_approval: bool
    success_rate: float      # Historical success rate


class TacticPlanner:
    """
    Recommends specific tools and techniques for the current phase
    based on the engagement state and technique success history.
    """

    # Phase → available techniques with metadata
    PHASE_TACTICS: dict[str, list[dict[str, Any]]] = {
        Phase.RECON: [
            {"tool": "subfinder", "technique": "subdomain_enumeration", "risk": "low", "approval": False},
            {"tool": "naabu", "technique": "port_scanning", "risk": "low", "approval": False},
            {"tool": "httpx", "technique": "http_probing", "risk": "low", "approval": False},
            {"tool": "katana", "technique": "web_crawling", "risk": "low", "approval": False},
            {"tool": "dnsx", "technique": "dns_resolution", "risk": "low", "approval": False},
            {"tool": "shodan", "technique": "passive_recon", "risk": "low", "approval": False},
            {"tool": "wappalyzer", "technique": "technology_fingerprint", "risk": "low", "approval": False},
            {"tool": "gau", "technique": "url_discovery", "risk": "low", "approval": False},
        ],
        Phase.VULN_ANALYSIS: [
            {"tool": "nuclei", "technique": "template_scanning", "risk": "medium", "approval": False},
        ],
        Phase.EXPLOITATION: [
            {"tool": "metasploit", "technique": "metasploit_exploit", "risk": "critical", "approval": True},
            {"tool": "sqlmap", "technique": "sql_injection", "risk": "high", "approval": True},
            {"tool": "commix", "technique": "command_injection", "risk": "high", "approval": True},
        ],
        Phase.POST_EXPLOITATION: [
            {"tool": "sliver", "technique": "c2_implant", "risk": "critical", "approval": True},
            {"tool": "impacket", "technique": "credential_dump", "risk": "critical", "approval": True},
            {"tool": "bloodhound", "technique": "ad_enumeration", "risk": "medium", "approval": True},
        ],
        Phase.LATERAL_MOVEMENT: [
            {"tool": "crackmapexec", "technique": "smb_lateral", "risk": "critical", "approval": True},
            {"tool": "impacket", "technique": "wmi_exec", "risk": "critical", "approval": True},
        ],
        Phase.PERSISTENCE: [
            {"tool": "sliver", "technique": "beacon_implant", "risk": "critical", "approval": True},
        ],
    }

    def recommend(
        self,
        phase: str,
        state: dict[str, Any],
        technique_history: list[dict[str, Any]] | None = None,
        max_risk: str = "critical",
    ) -> list[TacticRecommendation]:
        """
        Recommend tactics for the current phase and state.

        Args:
            phase: Current attack phase
            state: Current mission state
            technique_history: Past technique success/failure records
            max_risk: Maximum acceptable risk level
        """
        risk_order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
        max_risk_val = risk_order.get(max_risk, 3)

        available = self.PHASE_TACTICS.get(phase, [])
        history_map: dict[str, float] = {}
        if technique_history:
            for t in technique_history:
                history_map[t.get("technique", "")] = t.get("success_rate", 0.5)

        recommendations: list[TacticRecommendation] = []
        for tactic in available:
            risk = tactic["risk"]
            if risk_order.get(risk, 0) > max_risk_val:
                continue

            technique = tactic["technique"]
            success_rate = history_map.get(technique, 0.5)
            confidence = self._calculate_confidence(tactic, state, success_rate)
            reason = self._explain_recommendation(tactic, state, success_rate)

            recommendations.append(TacticRecommendation(
                tool_name=tactic["tool"],
                technique=technique,
                reason=reason,
                confidence=confidence,
                risk_level=risk,
                requires_approval=tactic["approval"],
                success_rate=success_rate,
            ))

        # Sort by confidence (higher = better)
        recommendations.sort(key=lambda r: r.confidence, reverse=True)
        return recommendations

    def to_tool_calls(
        self,
        recommendations: list[TacticRecommendation],
        target: str,
        limit: int = 5,
    ) -> list[ToolCall]:
        """Convert recommendations to executable ToolCalls."""
        calls: list[ToolCall] = []
        for rec in recommendations[:limit]:
            calls.append(ToolCall(
                tool_name=rec.tool_name,
                args={"target": target},
                requires_approval=rec.requires_approval,
                risk_level=rec.risk_level,
            ))
        return calls

    @staticmethod
    def _calculate_confidence(
        tactic: dict[str, Any],
        state: dict[str, Any],
        success_rate: float,
    ) -> float:
        """Calculate confidence score for a recommendation."""
        base = 0.5

        # Boost from historical success rate
        base += (success_rate - 0.5) * 0.3

        # Boost low-risk tactics
        risk_boost = {"low": 0.1, "medium": 0.05, "high": 0.0, "critical": -0.05}
        base += risk_boost.get(tactic.get("risk", "low"), 0.0)

        # Boost if we have data to work with
        if state.get("discovered_hosts") and tactic.get("tool") in ("httpx", "naabu", "nuclei"):
            base += 0.1

        return min(max(base, 0.0), 1.0)

    @staticmethod
    def _explain_recommendation(
        tactic: dict[str, Any],
        state: dict[str, Any],
        success_rate: float,
    ) -> str:
        """Generate a human-readable explanation for a recommendation."""
        parts = [f"Use {tactic['tool']} for {tactic['technique']}"]
        if success_rate > 0.7:
            parts.append(f"(high historical success rate: {success_rate:.0%})")
        elif success_rate < 0.3:
            parts.append(f"(low historical success rate: {success_rate:.0%}, consider alternatives)")
        return ". ".join(parts)
