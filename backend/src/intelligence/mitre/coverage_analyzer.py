"""
MITRE ATT&CK Coverage Analyzer

Calculates ATT&CK matrix coverage for an engagement: which tactics
and techniques have been exercised, gaps, and recommendations.
Generates heatmap data for frontend display.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

from core.logging import get_logger
from intelligence.mitre.attack_mapper import Technique

logger = get_logger(__name__)


# Complete ATT&CK Enterprise tactic list (14 tactics)
ALL_TACTICS: list[str] = [
    "Reconnaissance",
    "Resource Development",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
]


@dataclass
class TacticCoverage:
    """Coverage stats for a single tactic."""
    tactic: str
    techniques_used: list[Technique]
    coverage_count: int = 0
    status: str = "not_covered"  # not_covered | partial | covered


@dataclass
class CoverageResult:
    """Complete ATT&CK coverage analysis."""
    tactic_coverage: list[TacticCoverage]
    total_techniques_used: int
    total_tactics_covered: int
    total_tactics: int
    coverage_percentage: float  # 0-100
    gaps: list[str]             # tactics with no coverage
    recommendations: list[str]
    heatmap_data: list[dict[str, Any]]  # [{tactic, count, status, color}]


class CoverageAnalyzer:
    """
    Analyzes ATT&CK matrix coverage for a penetration test engagement.

    Tracks which techniques/tactics were exercised and identifies
    gaps that should be addressed for comprehensive coverage.
    """

    # Minimum techniques per tactic to count as "covered"
    MIN_TECHNIQUES_COVERED = 1
    # Minimum techniques per tactic to count as "partial"
    MIN_TECHNIQUES_PARTIAL = 0

    def __init__(self) -> None:
        self._used_techniques: list[Technique] = []

    def record_technique(self, technique: Technique) -> None:
        """Record a technique that was used during the engagement."""
        self._used_techniques.append(technique)

    def record_techniques(self, techniques: list[Technique]) -> None:
        """Record multiple techniques."""
        self._used_techniques.extend(techniques)

    def analyze(
        self,
        used_techniques: list[Technique] | None = None,
    ) -> CoverageResult:
        """
        Analyze ATT&CK coverage.

        Parameters
        ----------
        used_techniques : optional list of techniques (overrides
                          internally recorded techniques)
        """
        techniques = used_techniques or self._used_techniques

        # Group techniques by tactic
        tactic_map: dict[str, list[Technique]] = defaultdict(list)
        for tech in techniques:
            tactic_map[tech.tactic].append(tech)

        # Build coverage per tactic
        tactic_coverage: list[TacticCoverage] = []
        gaps: list[str] = []

        for tactic in ALL_TACTICS:
            used = tactic_map.get(tactic, [])
            count = len(used)

            if count >= self.MIN_TECHNIQUES_COVERED:
                status = "covered"
            elif count > self.MIN_TECHNIQUES_PARTIAL:
                status = "partial"
            else:
                status = "not_covered"
                gaps.append(tactic)

            tactic_coverage.append(TacticCoverage(
                tactic=tactic,
                techniques_used=used,
                coverage_count=count,
                status=status,
            ))

        total_techniques = len(set(t.technique_id for t in techniques))
        total_covered = sum(1 for tc in tactic_coverage if tc.status == "covered")
        coverage_pct = (total_covered / len(ALL_TACTICS)) * 100 if ALL_TACTICS else 0

        # Generate recommendations
        recommendations = self._generate_recommendations(gaps, tactic_map)

        # Heatmap data for frontend
        heatmap = self._build_heatmap(tactic_coverage)

        result = CoverageResult(
            tactic_coverage=tactic_coverage,
            total_techniques_used=total_techniques,
            total_tactics_covered=total_covered,
            total_tactics=len(ALL_TACTICS),
            coverage_percentage=round(coverage_pct, 1),
            gaps=gaps,
            recommendations=recommendations,
            heatmap_data=heatmap,
        )

        logger.info(
            "ATT&CK coverage analyzed",
            techniques=total_techniques,
            tactics_covered=total_covered,
            coverage=f"{coverage_pct:.1f}%",
            gaps=len(gaps),
        )

        return result

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _generate_recommendations(
        gaps: list[str],
        tactic_map: dict[str, list[Technique]],
    ) -> list[str]:
        """Generate recommendations to improve coverage."""
        recs: list[str] = []

        # Recommend covering gap tactics
        tactic_tool_hints: dict[str, str] = {
            "Initial Access": "Use phishing or exploitation techniques (metasploit, sqlmap)",
            "Execution": "Use script execution or exploitation payloads",
            "Persistence": "Establish persistence (scheduled tasks, registry, services)",
            "Privilege Escalation": "Try local exploits, token manipulation, UAC bypass",
            "Defense Evasion": "Test AV evasion, obfuscation, process injection",
            "Credential Access": "Dump credentials (mimikatz, hashdump, kerberoast)",
            "Lateral Movement": "Pivot using harvested credentials (impacket, psexec)",
            "Collection": "Collect sensitive data from compromised hosts",
            "Command and Control": "Establish C2 channels (sliver, havoc)",
            "Exfiltration": "Test data exfiltration paths",
            "Impact": "Test destructive capabilities (only with explicit auth)",
        }

        for gap in gaps:
            hint = tactic_tool_hints.get(gap, f"Add techniques for {gap}")
            recs.append(f"[{gap}] {hint}")

        # Suggest depth in partially covered tactics
        for tactic, techs in tactic_map.items():
            if 0 < len(techs) < 3:
                recs.append(
                    f"[{tactic}] Only {len(techs)} technique(s) tested — "
                    f"consider additional techniques for depth"
                )

        return recs

    @staticmethod
    def _build_heatmap(coverage: list[TacticCoverage]) -> list[dict[str, Any]]:
        """Build heatmap data for frontend visualization."""
        color_map = {
            "covered": "#52c41a",     # green
            "partial": "#faad14",     # yellow
            "not_covered": "#ff4d4f", # red
        }

        return [
            {
                "tactic": tc.tactic,
                "count": tc.coverage_count,
                "status": tc.status,
                "color": color_map.get(tc.status, "#d9d9d9"),
                "techniques": [t.technique_id for t in tc.techniques_used],
            }
            for tc in coverage
        ]
