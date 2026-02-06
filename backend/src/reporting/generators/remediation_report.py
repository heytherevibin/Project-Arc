"""
Remediation Report Generator

Generates prioritised remediation plans with effort estimates,
dependency ordering, and verification steps.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from core.logging import get_logger
from graph.client import Neo4jClient
from intelligence.scoring.epss_client import EPSSScorer

logger = get_logger(__name__)


@dataclass
class RemediationItem:
    """Single remediation action."""
    id: str
    priority: str          # P1 / P2 / P3 / P4
    title: str
    severity: str
    affected_assets: list[str] = field(default_factory=list)
    cve_id: str | None = None
    epss_probability: float | None = None
    description: str = ""
    remediation_steps: list[str] = field(default_factory=list)
    verification_steps: list[str] = field(default_factory=list)
    estimated_effort: str = ""    # "low" | "medium" | "high"
    dependencies: list[str] = field(default_factory=list)
    owner: str = ""
    sla_days: int = 0


@dataclass
class RemediationReport:
    """Complete remediation plan."""
    title: str
    project_id: str
    generated_at: str
    items: list[RemediationItem] = field(default_factory=list)
    summary: dict[str, Any] = field(default_factory=dict)
    quick_wins: list[str] = field(default_factory=list)


class RemediationReportGenerator:
    """
    Generates actionable remediation reports with:
    - Prioritised remediation items
    - Effort and SLA estimates
    - Dependency ordering
    - Verification / validation steps
    - Quick-win identification
    """

    SEVERITY_SLA: dict[str, int] = {
        "critical": 1,     # 1 day
        "high": 7,         # 7 days
        "medium": 30,      # 30 days
        "low": 90,         # 90 days
    }

    EFFORT_MAP: dict[str, str] = {
        "patch": "low",
        "config": "low",
        "upgrade": "medium",
        "redesign": "high",
        "replace": "high",
    }

    # Common remediation patterns
    REMEDIATION_PATTERNS: dict[str, dict[str, Any]] = {
        "sql-injection": {
            "steps": [
                "Use parameterised queries / prepared statements",
                "Implement input validation and sanitisation",
                "Apply WAF rules for SQL injection patterns",
                "Enforce least-privilege database accounts",
            ],
            "verification": [
                "Re-test with SQLMap to confirm remediation",
                "Run SAST scan on modified code",
            ],
            "effort": "medium",
        },
        "xss": {
            "steps": [
                "Encode output contextually (HTML, JS, URL, CSS)",
                "Implement Content-Security-Policy headers",
                "Use framework auto-escaping features",
                "Validate and sanitise user input",
            ],
            "verification": [
                "Re-test with XSS payloads",
                "Verify CSP headers are enforced",
            ],
            "effort": "medium",
        },
        "outdated-software": {
            "steps": [
                "Update to the latest stable version",
                "Review vendor changelog for security fixes",
                "Test updated software in staging environment",
                "Deploy to production with rollback plan",
            ],
            "verification": [
                "Verify version with banner scan",
                "Re-run vulnerability scan against updated service",
            ],
            "effort": "low",
        },
        "weak-credential": {
            "steps": [
                "Enforce strong password policy (min 14 chars, complexity)",
                "Implement multi-factor authentication",
                "Rotate all compromised credentials immediately",
                "Deploy credential monitoring / breach detection",
            ],
            "verification": [
                "Re-test authentication with original weak credentials",
                "Verify MFA is enforced for all accounts",
            ],
            "effort": "low",
        },
        "default": {
            "steps": [
                "Review vendor advisory and apply recommended fix",
                "Implement compensating controls if patching is delayed",
                "Document exception if risk is accepted",
            ],
            "verification": [
                "Re-scan affected asset to confirm remediation",
            ],
            "effort": "medium",
        },
    }

    def __init__(self, neo4j_client: Neo4jClient) -> None:
        self._client = neo4j_client
        self._epss = EPSSScorer()

    async def generate(
        self,
        project_id: str,
    ) -> RemediationReport:
        """Generate the full remediation report."""
        logger.info("Generating remediation report", project_id=project_id)

        vulns = await self._get_vulnerabilities(project_id)

        # EPSS enrichment
        cve_ids = [v.get("cve_id") for v in vulns if v.get("cve_id")]
        epss_map = await self._epss.fetch_scores(cve_ids) if cve_ids else {}

        items = self._build_items(vulns, epss_map)
        items.sort(key=lambda i: self._priority_order(i.priority))

        quick_wins = self._identify_quick_wins(items)

        summary = {
            "total_items": len(items),
            "p1": sum(1 for i in items if i.priority == "P1"),
            "p2": sum(1 for i in items if i.priority == "P2"),
            "p3": sum(1 for i in items if i.priority == "P3"),
            "p4": sum(1 for i in items if i.priority == "P4"),
            "quick_wins": len(quick_wins),
            "high_effort": sum(1 for i in items if i.estimated_effort == "high"),
        }

        report = RemediationReport(
            title=f"Remediation Plan — Project {project_id}",
            project_id=project_id,
            generated_at=datetime.now(timezone.utc).isoformat(),
            items=items,
            summary=summary,
            quick_wins=quick_wins,
        )

        logger.info("Remediation report generated", items=len(items), quick_wins=len(quick_wins))
        return report

    # ---- data fetch ----------------------------------------------------------
    async def _get_vulnerabilities(self, project_id: str) -> list[dict[str, Any]]:
        result = await self._client.execute_read(
            """
            MATCH (v:Vulnerability {project_id: $pid})
            OPTIONAL MATCH (v)-[:ASSOCIATED_CVE]->(c:CVE)
            OPTIONAL MATCH (v)-[:FOUND_AT|AFFECTS]->(a)
            RETURN v.vulnerability_id AS id, v.name AS name,
                   v.severity AS severity, v.template_id AS template_id,
                   v.description AS description, v.matched_at AS matched_at,
                   c.cve_id AS cve_id, c.cvss_score AS cvss_score,
                   collect(DISTINCT coalesce(a.name, a.address, a.url)) AS affected
            ORDER BY CASE v.severity
                WHEN 'critical' THEN 0 WHEN 'high' THEN 1
                WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4
            END
            """,
            {"pid": project_id},
        )
        return [dict(r) for r in result]

    # ---- builders ------------------------------------------------------------
    def _build_items(
        self,
        vulns: list[dict[str, Any]],
        epss_map: dict[str, Any],
    ) -> list[RemediationItem]:
        items: list[RemediationItem] = []
        seen_templates: set[str] = set()

        for v in vulns:
            template = v.get("template_id", v.get("id", ""))
            if template in seen_templates:
                continue
            seen_templates.add(template)

            severity = v.get("severity", "info")
            priority_map = {"critical": "P1", "high": "P2", "medium": "P3", "low": "P4"}
            priority = priority_map.get(severity, "P4")

            cve = v.get("cve_id")
            epss = epss_map.get(cve)
            epss_prob = epss.epss if epss else None

            # Match remediation pattern
            pattern = self._match_pattern(v)

            affected = [str(a) for a in v.get("affected", []) if a]
            if not affected and v.get("matched_at"):
                affected = [v["matched_at"]]

            items.append(RemediationItem(
                id=v.get("id", template),
                priority=priority,
                title=v.get("name", template),
                severity=severity,
                affected_assets=affected,
                cve_id=cve,
                epss_probability=epss_prob,
                description=v.get("description", ""),
                remediation_steps=pattern["steps"],
                verification_steps=pattern["verification"],
                estimated_effort=pattern["effort"],
                sla_days=self.SEVERITY_SLA.get(severity, 90),
            ))

        return items

    def _match_pattern(self, vuln: dict[str, Any]) -> dict[str, Any]:
        """Match vulnerability to a known remediation pattern."""
        name = (vuln.get("name", "") + " " + vuln.get("template_id", "")).lower()

        if "sql" in name and "inject" in name:
            return self.REMEDIATION_PATTERNS["sql-injection"]
        if "xss" in name or "cross-site" in name:
            return self.REMEDIATION_PATTERNS["xss"]
        if "outdated" in name or "version" in name or "upgrade" in name:
            return self.REMEDIATION_PATTERNS["outdated-software"]
        if "credential" in name or "password" in name or "default" in name:
            return self.REMEDIATION_PATTERNS["weak-credential"]
        return self.REMEDIATION_PATTERNS["default"]

    @staticmethod
    def _identify_quick_wins(items: list[RemediationItem]) -> list[str]:
        """Identify quick-win items: high severity + low effort."""
        wins: list[str] = []
        for item in items:
            if item.priority in ("P1", "P2") and item.estimated_effort == "low":
                wins.append(f"[{item.priority}] {item.title} — {item.estimated_effort} effort")
        return wins

    @staticmethod
    def _priority_order(priority: str) -> int:
        return {"P1": 0, "P2": 1, "P3": 2, "P4": 3}.get(priority, 4)
