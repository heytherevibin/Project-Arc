"""
Impact Calculator

Estimates the business and technical impact of successful exploitation
based on the CIA triad, affected asset criticality, data sensitivity,
and blast radius within the attack graph.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from core.logging import get_logger

logger = get_logger(__name__)


class ImpactLevel(str, Enum):
    CATASTROPHIC = "catastrophic"
    SEVERE = "severe"
    SIGNIFICANT = "significant"
    MODERATE = "moderate"
    MINIMAL = "minimal"


@dataclass
class CIAImpact:
    """CIA triad impact breakdown."""
    confidentiality: float = 0.0   # 0.0 – 1.0
    integrity: float = 0.0
    availability: float = 0.0

    @property
    def aggregate(self) -> float:
        """ISS-style aggregate: 1 - (1-C)*(1-I)*(1-A)."""
        return round(1.0 - (1.0 - self.confidentiality) * (1.0 - self.integrity) * (1.0 - self.availability), 4)


@dataclass
class ImpactAssessment:
    """Full impact assessment for a vulnerability or exploit chain."""
    entity_id: str
    entity_type: str                  # "vulnerability" | "exploit_chain" | "asset"
    cia: CIAImpact = field(default_factory=CIAImpact)
    business_impact_score: float = 0.0   # 0 – 100
    technical_impact_score: float = 0.0  # 0 – 100
    composite_score: float = 0.0         # 0 – 100
    impact_level: ImpactLevel = ImpactLevel.MINIMAL
    blast_radius: int = 0                # Number of assets affected
    data_at_risk: list[str] = field(default_factory=list)
    summary: str = ""


class ImpactCalculator:
    """
    Computes business and technical impact scores.

    Considers:
    - CIA triad impact (from CVSS or manual assessment)
    - Asset criticality tier
    - Data sensitivity classification
    - Blast radius (downstream reachable nodes in attack graph)
    - Regulatory / compliance implications
    """

    # Asset tier multipliers
    CRITICALITY_TIERS: dict[str, float] = {
        "tier1": 1.0,   # Mission-critical (DC, CA, financial)
        "tier2": 0.75,  # Important (mail, file, VPN)
        "tier3": 0.5,   # Standard (workstations, printers)
        "tier4": 0.25,  # Low-value (lab, dev, test)
    }

    # Data classification multipliers
    DATA_SENSITIVITY: dict[str, float] = {
        "restricted": 1.0,     # PII, PHI, PCI, secrets
        "confidential": 0.8,
        "internal": 0.5,
        "public": 0.15,
    }

    # Regulatory frameworks triggered by data types
    REGULATORY_MAP: dict[str, list[str]] = {
        "pii": ["GDPR", "CCPA", "PIPEDA"],
        "phi": ["HIPAA", "HITECH"],
        "pci": ["PCI-DSS"],
        "financial": ["SOX", "GLBA"],
        "classified": ["NIST 800-171", "CMMC"],
    }

    def calculate(
        self,
        vuln: dict[str, Any],
        asset: dict[str, Any] | None = None,
        blast_radius: int = 1,
    ) -> ImpactAssessment:
        """
        Calculate impact for a single vulnerability in context of its asset.

        Args:
            vuln: Vulnerability record with severity / CVSS / CIA data.
            asset: Optional asset metadata (criticality, data classification).
            blast_radius: Number of downstream reachable assets.
        """
        asset = asset or {}
        entity_id = vuln.get("id") or vuln.get("vulnerability_id") or vuln.get("cve_id", "unknown")

        # --- CIA impact -------------------------------------------------------
        cia = self._extract_cia(vuln)

        # --- Technical impact (based on CIA + exploit scope) ------------------
        technical = cia.aggregate * 100.0

        # --- Business impact --------------------------------------------------
        tier = asset.get("criticality_tier", "tier3")
        tier_mult = self.CRITICALITY_TIERS.get(tier, 0.5)

        data_class = asset.get("data_classification", "internal")
        data_mult = self.DATA_SENSITIVITY.get(data_class, 0.5)

        # Blast radius amplifier (logarithmic, caps at ~2×)
        import math
        radius_mult = 1.0 + min(1.0, math.log2(max(blast_radius, 1)) / 8.0)

        business = technical * tier_mult * data_mult * radius_mult
        business = min(100.0, business)

        # --- Composite -------------------------------------------------------
        composite = round(0.4 * technical + 0.6 * business, 2)
        level = self._level(composite)

        # --- Data at risk -----------------------------------------------------
        data_at_risk = self._identify_data_at_risk(asset)

        summary = (
            f"Impact: {composite:.1f}/100 ({level.value}). "
            f"CIA: C={cia.confidentiality:.1f} I={cia.integrity:.1f} A={cia.availability:.1f}. "
            f"Blast radius: {blast_radius} asset(s)."
        )

        assessment = ImpactAssessment(
            entity_id=entity_id,
            entity_type="vulnerability",
            cia=cia,
            business_impact_score=round(business, 2),
            technical_impact_score=round(technical, 2),
            composite_score=composite,
            impact_level=level,
            blast_radius=blast_radius,
            data_at_risk=data_at_risk,
            summary=summary,
        )
        logger.debug("Impact calculated", entity=entity_id, score=composite, level=level.value)
        return assessment

    def calculate_chain(
        self,
        vulns: list[dict[str, Any]],
        assets: list[dict[str, Any]],
        total_blast: int = 0,
    ) -> ImpactAssessment:
        """
        Calculate aggregate impact for an exploit chain spanning multiple
        vulnerabilities and assets.
        """
        if not vulns:
            return ImpactAssessment(entity_id="chain", entity_type="exploit_chain")

        # Aggregate CIA: take maximum of each dimension across the chain
        c = max((self._extract_cia(v).confidentiality for v in vulns), default=0.0)
        i = max((self._extract_cia(v).integrity for v in vulns), default=0.0)
        a = max((self._extract_cia(v).availability for v in vulns), default=0.0)
        cia = CIAImpact(confidentiality=c, integrity=i, availability=a)

        # Business = highest tier among assets
        tier_vals = [self.CRITICALITY_TIERS.get(
            a.get("criticality_tier", "tier3"), 0.5) for a in assets] or [0.5]
        best_tier = max(tier_vals)

        data_vals = [self.DATA_SENSITIVITY.get(
            a.get("data_classification", "internal"), 0.5) for a in assets] or [0.5]
        best_data = max(data_vals)

        import math
        radius_mult = 1.0 + min(1.0, math.log2(max(total_blast, 1)) / 8.0)

        technical = cia.aggregate * 100.0
        business = min(100.0, technical * best_tier * best_data * radius_mult)
        composite = round(0.4 * technical + 0.6 * business, 2)

        all_data: list[str] = []
        for a in assets:
            all_data.extend(self._identify_data_at_risk(a))

        return ImpactAssessment(
            entity_id="chain",
            entity_type="exploit_chain",
            cia=cia,
            business_impact_score=round(business, 2),
            technical_impact_score=round(technical, 2),
            composite_score=composite,
            impact_level=self._level(composite),
            blast_radius=total_blast or len(assets),
            data_at_risk=list(set(all_data)),
            summary=f"Chain impact: {composite:.1f}/100 across {len(vulns)} vulns, {len(assets)} assets",
        )

    # ---------- helpers -------------------------------------------------------
    @staticmethod
    def _extract_cia(vuln: dict[str, Any]) -> CIAImpact:
        """Extract CIA values from vulnerability data, falling back to severity."""
        c = vuln.get("impact_confidentiality") or vuln.get("cia_c")
        i = vuln.get("impact_integrity") or vuln.get("cia_i")
        a = vuln.get("impact_availability") or vuln.get("cia_a")

        impact_map = {"high": 0.9, "medium": 0.5, "low": 0.2, "none": 0.0}

        def _resolve(val: Any) -> float:
            if isinstance(val, (int, float)):
                return min(1.0, max(0.0, float(val)))
            if isinstance(val, str):
                return impact_map.get(val.lower(), 0.5)
            return 0.5

        if c is not None or i is not None or a is not None:
            return CIAImpact(
                confidentiality=_resolve(c),
                integrity=_resolve(i),
                availability=_resolve(a),
            )

        # Fallback: derive from CVSS or severity
        cvss = vuln.get("cvss_score", vuln.get("cvss", 5.0))
        if isinstance(cvss, str):
            try:
                cvss = float(cvss)
            except ValueError:
                cvss = 5.0
        normalised = min(1.0, cvss / 10.0)
        return CIAImpact(
            confidentiality=normalised,
            integrity=normalised * 0.8,
            availability=normalised * 0.6,
        )

    @staticmethod
    def _level(score: float) -> ImpactLevel:
        if score >= 85:
            return ImpactLevel.CATASTROPHIC
        if score >= 65:
            return ImpactLevel.SEVERE
        if score >= 40:
            return ImpactLevel.SIGNIFICANT
        if score >= 20:
            return ImpactLevel.MODERATE
        return ImpactLevel.MINIMAL

    def _identify_data_at_risk(self, asset: dict[str, Any]) -> list[str]:
        """Identify data types and regulatory frameworks at risk."""
        data_types = asset.get("data_types", [])
        if isinstance(data_types, str):
            data_types = [d.strip() for d in data_types.split(",")]

        at_risk: list[str] = list(data_types)
        for dt in data_types:
            dt_lower = dt.lower()
            for key, frameworks in self.REGULATORY_MAP.items():
                if key in dt_lower:
                    at_risk.extend(frameworks)
        return list(set(at_risk))
