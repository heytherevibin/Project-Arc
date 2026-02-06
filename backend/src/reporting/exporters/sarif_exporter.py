"""
SARIF Exporter

Exports vulnerability findings in SARIF (Static Analysis Results
Interchange Format) for CI/CD pipeline integration.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from core.logging import get_logger
from graph.client import Neo4jClient

logger = get_logger(__name__)


class SARIFExporter:
    """
    Exports Arc findings in SARIF v2.1.0 format.

    SARIF is the industry standard for security tool output,
    supported by GitHub Advanced Security, Azure DevOps, etc.
    """

    SARIF_VERSION = "2.1.0"
    SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json"

    SEVERITY_MAP = {
        "critical": "error",
        "high": "error",
        "medium": "warning",
        "low": "note",
        "info": "none",
    }

    def __init__(self, neo4j_client: Neo4jClient) -> None:
        self._client = neo4j_client

    async def export(self, project_id: str) -> dict[str, Any]:
        """Export all findings for a project as SARIF."""
        vulns = await self._fetch_vulnerabilities(project_id)

        rules = []
        results = []
        rule_ids_seen: set[str] = set()

        for vuln in vulns:
            template_id = vuln.get("template_id", "unknown")
            rule_id = template_id.replace("/", "-").replace(":", "-")

            # Create rule (dedup by template)
            if rule_id not in rule_ids_seen:
                rule_ids_seen.add(rule_id)
                rules.append({
                    "id": rule_id,
                    "name": vuln.get("name", "Unknown"),
                    "shortDescription": {
                        "text": vuln.get("name", "Unknown Vulnerability"),
                    },
                    "fullDescription": {
                        "text": vuln.get("description", "") or vuln.get("name", ""),
                    },
                    "defaultConfiguration": {
                        "level": self.SEVERITY_MAP.get(
                            vuln.get("severity", "medium"), "warning"
                        ),
                    },
                    "properties": {
                        "severity": vuln.get("severity", "unknown"),
                        "tags": ["security", "vulnerability"],
                    },
                })

            # Create result
            results.append({
                "ruleId": rule_id,
                "level": self.SEVERITY_MAP.get(vuln.get("severity", "medium"), "warning"),
                "message": {
                    "text": f"{vuln.get('name', 'Vulnerability')} found at {vuln.get('matched_at', 'unknown')}",
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": vuln.get("matched_at", ""),
                            },
                        },
                    }
                ] if vuln.get("matched_at") else [],
                "properties": {
                    "vulnerability_id": vuln.get("vulnerability_id", ""),
                    "severity": vuln.get("severity", "unknown"),
                    "evidence": vuln.get("evidence", ""),
                },
            })

        sarif = {
            "version": self.SARIF_VERSION,
            "$schema": self.SARIF_SCHEMA,
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "Arc",
                            "version": "0.1.0",
                            "informationUri": "https://github.com/arc-framework/arc",
                            "rules": rules,
                        },
                    },
                    "results": results,
                    "invocations": [
                        {
                            "executionSuccessful": True,
                            "endTimeUtc": datetime.now(timezone.utc).isoformat(),
                        },
                    ],
                },
            ],
        }

        logger.info(
            "SARIF export complete",
            rules=len(rules),
            results=len(results),
            project_id=project_id,
        )

        return sarif

    async def export_json(self, project_id: str) -> str:
        """Export as JSON string."""
        sarif = await self.export(project_id)
        return json.dumps(sarif, indent=2)

    async def _fetch_vulnerabilities(self, project_id: str) -> list[dict[str, Any]]:
        """Fetch all vulnerabilities for a project."""
        result = await self._client.execute_read(
            """
            MATCH (v:Vulnerability {project_id: $pid})
            RETURN v.vulnerability_id AS vulnerability_id,
                   v.template_id AS template_id,
                   v.name AS name,
                   v.severity AS severity,
                   v.matched_at AS matched_at,
                   v.description AS description,
                   v.evidence AS evidence,
                   v.cve_id AS cve_id
            ORDER BY CASE v.severity
                WHEN 'critical' THEN 0
                WHEN 'high' THEN 1
                WHEN 'medium' THEN 2
                ELSE 3
            END
            """,
            {"pid": project_id},
        )
        return [dict(r) for r in result]
