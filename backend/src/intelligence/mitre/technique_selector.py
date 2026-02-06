"""
MITRE ATT&CK Technique Selector

Recommends ATT&CK techniques based on current phase, target environment,
available tools, and historical success rates from procedural memory.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from core.logging import get_logger
from intelligence.mitre.attack_mapper import MITREAttackMapper, Technique

logger = get_logger(__name__)


@dataclass
class TechniqueRecommendation:
    """A ranked technique recommendation."""
    technique: Technique
    score: float          # 0-1 composite score
    reason: str
    tool: str
    success_rate: float   # historical success rate
    risk_level: str
    requires_approval: bool


class TechniqueSelector:
    """
    Recommends ATT&CK techniques for the current attack context.

    Ranking factors:
    - Phase alignment (is the technique relevant to current phase?)
    - Tool availability (do we have a tool for it?)
    - Historical success rate (from procedural memory)
    - Risk level (prefer lower risk when alternatives exist)
    """

    # Phase → relevant ATT&CK tactics
    PHASE_TACTICS: dict[str, list[str]] = {
        "recon": ["Reconnaissance", "Resource Development"],
        "vuln_analysis": ["Reconnaissance", "Discovery"],
        "exploitation": ["Initial Access", "Execution"],
        "post_exploitation": ["Credential Access", "Privilege Escalation", "Persistence"],
        "lateral_movement": ["Lateral Movement", "Discovery"],
        "persistence": ["Persistence", "Defense Evasion"],
        "exfiltration": ["Exfiltration", "Collection"],
        "reporting": [],
    }

    # Risk weights by risk level
    RISK_WEIGHTS: dict[str, float] = {
        "low": 1.0,
        "medium": 0.8,
        "high": 0.6,
        "critical": 0.4,
    }

    def __init__(self, attack_mapper: MITREAttackMapper | None = None) -> None:
        self._mapper = attack_mapper or MITREAttackMapper.__new__(MITREAttackMapper)
        self._tool_map = getattr(self._mapper, "TOOL_TECHNIQUE_MAP", MITREAttackMapper.TOOL_TECHNIQUE_MAP)

    async def recommend(
        self,
        phase: str,
        available_tools: list[str],
        target_info: dict[str, Any] | None = None,
        success_history: dict[str, float] | None = None,
        limit: int = 10,
    ) -> list[TechniqueRecommendation]:
        """
        Recommend ATT&CK techniques ranked by composite score.

        Parameters
        ----------
        phase           : current attack phase
        available_tools : tools the agent has access to
        target_info     : optional target environment details
        success_history : technique_id → historical success rate
        limit           : max recommendations to return
        """
        success_rates = success_history or {}
        relevant_tactics = set(self.PHASE_TACTICS.get(phase, []))
        recommendations: list[TechniqueRecommendation] = []

        for tool in available_tools:
            techniques = self._tool_map.get(tool, [])
            for tech in techniques:
                # Phase alignment score
                tactic_score = 1.0 if tech.tactic in relevant_tactics else 0.3

                # Success rate
                hist_rate = success_rates.get(tech.technique_id, 0.5)

                # Risk factor
                risk = self._infer_risk(tool, phase)
                risk_weight = self.RISK_WEIGHTS.get(risk, 0.5)

                # Target compatibility bonus
                target_bonus = self._target_bonus(tech, target_info or {})

                # Composite score
                score = (
                    0.35 * tactic_score
                    + 0.30 * hist_rate
                    + 0.20 * risk_weight
                    + 0.15 * target_bonus
                )

                recommendations.append(TechniqueRecommendation(
                    technique=tech,
                    score=score,
                    reason=self._build_reason(tech, tactic_score, hist_rate, risk),
                    tool=tool,
                    success_rate=hist_rate,
                    risk_level=risk,
                    requires_approval=self._needs_approval(tool, phase),
                ))

        # Sort by score descending
        recommendations.sort(key=lambda r: r.score, reverse=True)

        logger.info(
            "Techniques recommended",
            phase=phase,
            total=len(recommendations),
            returned=min(limit, len(recommendations)),
        )

        return recommendations[:limit]

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _infer_risk(tool: str, phase: str) -> str:
        high_risk_tools = {"metasploit", "sqlmap", "commix", "sliver", "havoc", "impacket"}
        medium_risk_tools = {"crackmapexec", "certipy", "bloodhound", "nikto"}
        if tool in high_risk_tools:
            return "critical" if phase in ("exploitation", "post_exploitation") else "high"
        if tool in medium_risk_tools:
            return "medium"
        return "low"

    @staticmethod
    def _needs_approval(tool: str, phase: str) -> bool:
        approval_tools = {"metasploit", "sqlmap", "commix", "sliver", "havoc", "impacket"}
        approval_phases = {"exploitation", "post_exploitation", "lateral_movement"}
        return tool in approval_tools or phase in approval_phases

    @staticmethod
    def _target_bonus(tech: Technique, target_info: dict[str, Any]) -> float:
        """Bonus score if the technique matches the target environment."""
        os_type = target_info.get("os", "").lower()
        is_ad = target_info.get("active_directory", False)

        # AD-specific techniques get a bonus in AD environments
        ad_techniques = {"T1087.002", "T1069.002", "T1558.003", "T1558.004"}
        if is_ad and tech.technique_id in ad_techniques:
            return 1.0

        # Windows-specific techniques
        windows_techniques = {"T1003", "T1053", "T1059.001"}
        if "windows" in os_type and tech.technique_id in windows_techniques:
            return 0.8

        return 0.5

    @staticmethod
    def _build_reason(
        tech: Technique,
        tactic_score: float,
        success_rate: float,
        risk: str,
    ) -> str:
        parts: list[str] = []
        if tactic_score >= 0.8:
            parts.append(f"aligned with {tech.tactic}")
        if success_rate >= 0.7:
            parts.append(f"high historical success ({success_rate:.0%})")
        elif success_rate <= 0.3:
            parts.append(f"low historical success ({success_rate:.0%})")
        parts.append(f"risk: {risk}")
        return "; ".join(parts) if parts else "general recommendation"
