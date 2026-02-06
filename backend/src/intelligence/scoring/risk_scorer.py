"""
Composite Risk Scorer

Calculates multi-dimensional risk scores for assets, vulnerabilities,
and overall engagement using weighted factor analysis.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from core.logging import get_logger

logger = get_logger(__name__)


class RiskLevel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class RiskFactor:
    """Individual risk factor contributing to overall score."""
    name: str
    weight: float  # 0.0 – 1.0
    raw_value: float  # 0.0 – 1.0 (normalised)
    description: str = ""

    @property
    def weighted_value(self) -> float:
        return self.weight * self.raw_value


@dataclass
class RiskAssessment:
    """Full risk assessment output for an asset or engagement."""
    entity_id: str
    entity_type: str  # "asset" | "engagement" | "vulnerability"
    factors: list[RiskFactor] = field(default_factory=list)
    composite_score: float = 0.0  # 0 – 100
    risk_level: RiskLevel = RiskLevel.INFO
    summary: str = ""


class RiskScorer:
    """
    Multi-factor risk scoring engine.

    Combines:
    - Vulnerability severity / density
    - EPSS exploitation probability
    - Attack surface exposure
    - Asset criticality / business impact
    - Network reachability
    """

    # --- Factor weight presets ---------------------------------------------------
    ENGAGEMENT_WEIGHTS: dict[str, float] = {
        "vuln_severity": 0.30,
        "epss_exposure": 0.20,
        "attack_surface": 0.15,
        "asset_criticality": 0.15,
        "network_exposure": 0.10,
        "credential_exposure": 0.10,
    }

    ASSET_WEIGHTS: dict[str, float] = {
        "vuln_density": 0.25,
        "epss_max": 0.20,
        "internet_facing": 0.15,
        "privilege_level": 0.15,
        "data_sensitivity": 0.15,
        "patch_age": 0.10,
    }

    # -------------------------------------------------------------------------
    def score_engagement(
        self,
        vulns: list[dict[str, Any]],
        epss_scores: dict[str, float],
        attack_surface: dict[str, int],
        asset_criticality: float = 0.5,
        credential_count: int = 0,
    ) -> RiskAssessment:
        """Score overall engagement risk."""
        factors: list[RiskFactor] = []
        weights = self.ENGAGEMENT_WEIGHTS

        # 1. Vulnerability severity aggregate
        vuln_raw = self._vuln_severity_score(vulns)
        factors.append(RiskFactor("vuln_severity", weights["vuln_severity"], vuln_raw,
                                  "Weighted vulnerability severity distribution"))

        # 2. EPSS exploitation probability
        epss_raw = self._epss_aggregate(epss_scores)
        factors.append(RiskFactor("epss_exposure", weights["epss_exposure"], epss_raw,
                                  "Maximum EPSS exploitation probability"))

        # 3. Attack surface breadth
        surface_raw = self._attack_surface_score(attack_surface)
        factors.append(RiskFactor("attack_surface", weights["attack_surface"], surface_raw,
                                  "Number and diversity of exposed assets"))

        # 4. Asset criticality (user-provided)
        factors.append(RiskFactor("asset_criticality", weights["asset_criticality"],
                                  min(max(asset_criticality, 0.0), 1.0),
                                  "Business criticality of target assets"))

        # 5. Network exposure (heuristic from surface)
        net_raw = min(1.0, attack_surface.get("Port", 0) / 200.0)
        factors.append(RiskFactor("network_exposure", weights["network_exposure"], net_raw,
                                  "Open port / service exposure"))

        # 6. Credential exposure
        cred_raw = min(1.0, credential_count / 20.0)
        factors.append(RiskFactor("credential_exposure", weights["credential_exposure"], cred_raw,
                                  "Number of harvested credentials"))

        composite = sum(f.weighted_value for f in factors) * 100.0
        composite = round(min(100.0, max(0.0, composite)), 2)

        assessment = RiskAssessment(
            entity_id="engagement",
            entity_type="engagement",
            factors=factors,
            composite_score=composite,
            risk_level=self._level(composite),
            summary=self._engagement_summary(composite, vulns),
        )
        logger.info("Engagement risk scored", score=composite, level=assessment.risk_level.value)
        return assessment

    def score_asset(
        self,
        asset: dict[str, Any],
        vulns: list[dict[str, Any]],
        epss_scores: dict[str, float],
    ) -> RiskAssessment:
        """Score a single asset's risk."""
        factors: list[RiskFactor] = []
        weights = self.ASSET_WEIGHTS

        vuln_count = len(vulns)
        vuln_density = min(1.0, vuln_count / 20.0)
        factors.append(RiskFactor("vuln_density", weights["vuln_density"], vuln_density))

        max_epss = max(epss_scores.values(), default=0.0)
        factors.append(RiskFactor("epss_max", weights["epss_max"], min(1.0, max_epss)))

        internet = 1.0 if asset.get("is_internet_facing") or asset.get("external") else 0.3
        factors.append(RiskFactor("internet_facing", weights["internet_facing"], internet))

        priv = {"system": 1.0, "admin": 0.8, "user": 0.4, "none": 0.1}
        priv_level = priv.get(asset.get("privilege_level", "none"), 0.3)
        factors.append(RiskFactor("privilege_level", weights["privilege_level"], priv_level))

        sensitivity_map = {"high": 1.0, "medium": 0.6, "low": 0.3}
        data_raw = sensitivity_map.get(asset.get("data_sensitivity", "low"), 0.3)
        factors.append(RiskFactor("data_sensitivity", weights["data_sensitivity"], data_raw))

        patch_days = asset.get("days_since_last_patch", 90)
        patch_raw = min(1.0, patch_days / 365.0)
        factors.append(RiskFactor("patch_age", weights["patch_age"], patch_raw))

        composite = sum(f.weighted_value for f in factors) * 100.0
        composite = round(min(100.0, max(0.0, composite)), 2)

        return RiskAssessment(
            entity_id=asset.get("id", "unknown"),
            entity_type="asset",
            factors=factors,
            composite_score=composite,
            risk_level=self._level(composite),
            summary=f"Asset risk: {composite:.1f}/100",
        )

    # ------------ helpers ---------------------------------------------------
    @staticmethod
    def _vuln_severity_score(vulns: list[dict[str, Any]]) -> float:
        if not vulns:
            return 0.0
        weights = {"critical": 1.0, "high": 0.7, "medium": 0.4, "low": 0.1}
        total = sum(weights.get(v.get("severity", "info"), 0) for v in vulns)
        return min(1.0, total / max(len(vulns), 1))

    @staticmethod
    def _epss_aggregate(epss_scores: dict[str, float]) -> float:
        if not epss_scores:
            return 0.0
        return min(1.0, max(epss_scores.values()))

    @staticmethod
    def _attack_surface_score(surface: dict[str, int]) -> float:
        total_assets = sum(surface.values())
        if total_assets == 0:
            return 0.0
        return min(1.0, total_assets / 500.0)

    @staticmethod
    def _level(score: float) -> RiskLevel:
        if score >= 80:
            return RiskLevel.CRITICAL
        if score >= 60:
            return RiskLevel.HIGH
        if score >= 35:
            return RiskLevel.MEDIUM
        if score >= 15:
            return RiskLevel.LOW
        return RiskLevel.INFO

    @staticmethod
    def _engagement_summary(score: float, vulns: list[dict[str, Any]]) -> str:
        crit = sum(1 for v in vulns if v.get("severity") == "critical")
        high = sum(1 for v in vulns if v.get("severity") == "high")
        return (
            f"Overall engagement risk score: {score:.1f}/100. "
            f"{len(vulns)} total findings ({crit} critical, {high} high)."
        )
