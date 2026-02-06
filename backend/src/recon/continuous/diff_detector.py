"""
Diff Detector

Compares current scan results with previous baselines stored in Neo4j.
Identifies new hosts, removed hosts, new ports, and new vulnerabilities.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from core.logging import get_logger
from graph.client import Neo4jClient

logger = get_logger(__name__)


@dataclass
class DiffResult:
    """Result of a diff comparison."""
    scan_time: str
    new_hosts: list[str] = field(default_factory=list)
    removed_hosts: list[str] = field(default_factory=list)
    new_ports: list[dict[str, Any]] = field(default_factory=list)
    closed_ports: list[dict[str, Any]] = field(default_factory=list)
    new_vulns: list[dict[str, Any]] = field(default_factory=list)
    resolved_vulns: list[dict[str, Any]] = field(default_factory=list)
    new_services: list[dict[str, Any]] = field(default_factory=list)
    total_changes: int = 0


class DiffDetector:
    """
    Detects changes between current scan results and the
    baseline stored in Neo4j.
    """

    def __init__(self, client: Neo4jClient) -> None:
        self._client = client

    async def detect_changes(
        self,
        project_id: str,
        current_scan: dict[str, Any],
    ) -> DiffResult:
        """
        Compare current scan results against the Neo4j baseline.

        Parameters
        ----------
        project_id   : project to compare against
        current_scan : current scan result dict with tools output
        """
        now = datetime.now(timezone.utc).isoformat()
        result = DiffResult(scan_time=now)

        # Get baseline from Neo4j
        baseline_hosts = await self._get_baseline_hosts(project_id)
        baseline_ports = await self._get_baseline_ports(project_id)
        baseline_vulns = await self._get_baseline_vulns(project_id)

        # Extract current data from scan results
        current_hosts = self._extract_hosts(current_scan)
        current_ports = self._extract_ports(current_scan)
        current_vulns = self._extract_vulns(current_scan)

        # Compute diffs
        result.new_hosts = [h for h in current_hosts if h not in baseline_hosts]
        result.removed_hosts = [h for h in baseline_hosts if h not in current_hosts]
        result.new_ports = [p for p in current_ports if p not in baseline_ports]
        result.closed_ports = [p for p in baseline_ports if p not in current_ports]
        result.new_vulns = [v for v in current_vulns if v not in baseline_vulns]

        result.total_changes = (
            len(result.new_hosts)
            + len(result.removed_hosts)
            + len(result.new_ports)
            + len(result.closed_ports)
            + len(result.new_vulns)
        )

        logger.info(
            "Diff detection complete",
            project=project_id,
            new_hosts=len(result.new_hosts),
            removed_hosts=len(result.removed_hosts),
            new_ports=len(result.new_ports),
            new_vulns=len(result.new_vulns),
            total_changes=result.total_changes,
        )

        return result

    # ------------------------------------------------------------------
    # Baseline retrieval
    # ------------------------------------------------------------------

    async def _get_baseline_hosts(self, project_id: str) -> set[str]:
        query = """
        MATCH (h:Host {project_id: $project_id})
        RETURN collect(DISTINCT coalesce(h.hostname, h.ip)) AS hosts
        """
        records = await self._client.execute_read(query, {"project_id": project_id})
        if records:
            return set(records[0].get("hosts", []))
        return set()

    async def _get_baseline_ports(self, project_id: str) -> list[dict[str, Any]]:
        query = """
        MATCH (h:Host {project_id: $project_id})-[:HAS_PORT]->(p:Port)
        RETURN h.hostname AS host, p.number AS port, p.protocol AS protocol
        """
        records = await self._client.execute_read(query, {"project_id": project_id})
        return [dict(r) for r in records]

    async def _get_baseline_vulns(self, project_id: str) -> list[dict[str, Any]]:
        query = """
        MATCH (v:Vulnerability {project_id: $project_id})
        RETURN v.vuln_id AS vuln_id, v.name AS name, v.severity AS severity
        """
        records = await self._client.execute_read(query, {"project_id": project_id})
        return [dict(r) for r in records]

    # ------------------------------------------------------------------
    # Extraction from scan data
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_hosts(scan: dict[str, Any]) -> set[str]:
        hosts: set[str] = set()
        for _tool, data in scan.get("tools", {}).items():
            if isinstance(data, dict):
                for h in data.get("hosts", []):
                    hosts.add(h)
                for h in data.get("subdomains", []):
                    hosts.add(h)
                for h in data.get("ips", []):
                    hosts.add(h)
        return hosts

    @staticmethod
    def _extract_ports(scan: dict[str, Any]) -> list[dict[str, Any]]:
        ports: list[dict[str, Any]] = []
        for _tool, data in scan.get("tools", {}).items():
            if isinstance(data, dict):
                for p in data.get("ports", []):
                    if isinstance(p, dict):
                        ports.append(p)
        return ports

    @staticmethod
    def _extract_vulns(scan: dict[str, Any]) -> list[dict[str, Any]]:
        vulns: list[dict[str, Any]] = []
        for _tool, data in scan.get("tools", {}).items():
            if isinstance(data, dict):
                for v in data.get("vulnerabilities", []):
                    if isinstance(v, dict):
                        vulns.append({
                            "vuln_id": v.get("template_id", ""),
                            "name": v.get("name", ""),
                            "severity": v.get("severity", ""),
                        })
        return vulns
