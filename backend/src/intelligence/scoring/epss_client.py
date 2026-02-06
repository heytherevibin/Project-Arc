"""
EPSS Client

Integrates with FIRST's Exploit Prediction Scoring System for ML-based
vulnerability prioritization. Predicts probability of exploitation
in the next 30 days.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import aiohttp

from core.logging import get_logger

logger = get_logger(__name__)


@dataclass
class EPSSScore:
    """EPSS score for a single CVE."""
    cve: str
    epss: float        # Probability 0-1
    percentile: float  # Relative ranking 0-1
    date: str


@dataclass
class PrioritizedVuln:
    """A vulnerability with composite priority scoring."""
    vulnerability: dict[str, Any]
    epss_score: EPSSScore | None
    priority_score: float
    recommended_action: str


class EPSSScorer:
    """
    ML-based vulnerability prioritization using EPSS.

    Combines EPSS probability, CVSS severity, and contextual factors
    into a composite priority score.
    """

    EPSS_API = "https://api.first.org/data/v1/epss"

    async def fetch_scores(self, cves: list[str]) -> dict[str, EPSSScore]:
        """Fetch EPSS scores from the FIRST API."""
        if not cves:
            return {}

        scores: dict[str, EPSSScore] = {}

        try:
            # API supports up to 100 CVEs per request
            for i in range(0, len(cves), 100):
                batch = cves[i:i + 100]
                async with aiohttp.ClientSession() as session:
                    async with session.get(
                        self.EPSS_API,
                        params={"cve": ",".join(batch)},
                        timeout=aiohttp.ClientTimeout(total=30),
                    ) as response:
                        if response.status != 200:
                            logger.warning("EPSS API error", status=response.status)
                            continue
                        data = await response.json()

                for item in data.get("data", []):
                    scores[item["cve"]] = EPSSScore(
                        cve=item["cve"],
                        epss=float(item.get("epss", 0)),
                        percentile=float(item.get("percentile", 0)),
                        date=item.get("date", ""),
                    )

        except Exception as e:
            logger.warning("Failed to fetch EPSS scores", error=str(e))

        logger.info("Fetched EPSS scores", count=len(scores), requested=len(cves))
        return scores

    def prioritize(
        self,
        vulnerabilities: list[dict[str, Any]],
        epss_scores: dict[str, EPSSScore],
    ) -> list[PrioritizedVuln]:
        """
        Composite scoring combining EPSS, CVSS, and context.

        Formula:
            priority = (EPSS * 0.4) + (CVSS_normalized * 0.3) + (context * 0.3)
        """
        prioritized: list[PrioritizedVuln] = []

        for vuln in vulnerabilities:
            cve_id = vuln.get("cve_id", "")
            epss = epss_scores.get(cve_id)

            # EPSS component (40% weight)
            epss_component = (epss.epss if epss else 0.1) * 0.4

            # CVSS component (30% weight)
            cvss = vuln.get("cvss_score", vuln.get("cvss", 5.0))
            if isinstance(cvss, str):
                try:
                    cvss = float(cvss)
                except ValueError:
                    cvss = 5.0
            cvss_normalized = (cvss / 10.0) * 0.3

            # Context component (30% weight)
            context_score = self._calculate_context_score(vuln) * 0.3

            priority_score = epss_component + cvss_normalized + context_score

            prioritized.append(PrioritizedVuln(
                vulnerability=vuln,
                epss_score=epss,
                priority_score=round(priority_score, 4),
                recommended_action=self._recommend_action(priority_score, epss),
            ))

        return sorted(prioritized, key=lambda x: x.priority_score, reverse=True)

    @staticmethod
    def _calculate_context_score(vuln: dict[str, Any]) -> float:
        """Context-aware scoring based on asset criticality and exposure."""
        score = 0.5  # Base

        # Internet-facing
        if vuln.get("is_internet_facing") or vuln.get("external"):
            score += 0.2

        # Critical asset
        if vuln.get("criticality") == "high" or vuln.get("asset_criticality") == "high":
            score += 0.2

        # Known public exploit
        if vuln.get("has_public_exploit") or vuln.get("exploit_available"):
            score += 0.1

        return min(score, 1.0)

    @staticmethod
    def _recommend_action(priority: float, epss: EPSSScore | None) -> str:
        """Recommend action based on priority score."""
        if priority >= 0.8:
            return "EXPLOIT_IMMEDIATELY"
        if priority >= 0.6:
            return "EXPLOIT_HIGH_PRIORITY"
        if priority >= 0.4:
            return "INVESTIGATE"
        if priority >= 0.2:
            return "MONITOR"
        return "LOW_PRIORITY"
