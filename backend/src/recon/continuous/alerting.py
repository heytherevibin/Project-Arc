"""
Alert Manager

Evaluates change significance and sends alerts via WebSocket broadcast
when significant changes are detected (new critical vulns, new hosts, etc.).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Awaitable

from core.logging import get_logger

logger = get_logger(__name__)


@dataclass
class Alert:
    """A monitoring alert."""
    alert_id: str
    severity: str       # "critical" | "high" | "medium" | "low" | "info"
    category: str       # "new_host" | "new_vuln" | "new_port" | "host_down"
    title: str
    description: str
    project_id: str
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    data: dict[str, Any] = field(default_factory=dict)


class AlertManager:
    """
    Evaluates changes from the DiffDetector and produces alerts.

    Sends alerts via a configurable broadcast function (typically
    a WebSocket broadcast to connected frontend clients).
    """

    def __init__(
        self,
        broadcast_fn: Callable[[dict[str, Any]], Awaitable[None]] | None = None,
    ) -> None:
        """
        Parameters
        ----------
        broadcast_fn : async function that sends a dict to all connected
                       WebSocket clients (injected from the API layer)
        """
        self._broadcast = broadcast_fn
        self._alert_history: list[Alert] = []

    async def evaluate_changes(
        self,
        changes: dict[str, Any],
        project_id: str,
    ) -> list[Alert]:
        """
        Evaluate a DiffResult-like dict and generate alerts
        for significant changes.
        """
        alerts: list[Alert] = []
        now = datetime.now(timezone.utc).isoformat()

        # New hosts
        for host in changes.get("new_hosts", []):
            alerts.append(Alert(
                alert_id=f"alert-newhost-{host}-{len(self._alert_history)}",
                severity="medium",
                category="new_host",
                title=f"New host discovered: {host}",
                description=f"A previously unknown host ({host}) appeared in the latest scan.",
                project_id=project_id,
                timestamp=now,
                data={"host": host},
            ))

        # New vulnerabilities
        for vuln in changes.get("new_vulns", []):
            sev = vuln.get("severity", "info")
            alert_sev = "critical" if sev == "critical" else ("high" if sev == "high" else "medium")
            alerts.append(Alert(
                alert_id=f"alert-newvuln-{vuln.get('vuln_id', '')}-{len(self._alert_history)}",
                severity=alert_sev,
                category="new_vuln",
                title=f"New {sev} vulnerability: {vuln.get('name', 'unknown')}",
                description=f"Vulnerability {vuln.get('vuln_id', '')} ({sev}) found in latest scan.",
                project_id=project_id,
                timestamp=now,
                data=vuln,
            ))

        # New ports
        for port_info in changes.get("new_ports", []):
            alerts.append(Alert(
                alert_id=f"alert-newport-{port_info.get('host','')}-{port_info.get('port','')}-{len(self._alert_history)}",
                severity="low",
                category="new_port",
                title=f"New port open: {port_info.get('host', '')}:{port_info.get('port', '')}",
                description=f"Port {port_info.get('port', '')} is now open on {port_info.get('host', '')}.",
                project_id=project_id,
                timestamp=now,
                data=port_info,
            ))

        # Removed hosts
        for host in changes.get("removed_hosts", []):
            alerts.append(Alert(
                alert_id=f"alert-hostdown-{host}-{len(self._alert_history)}",
                severity="info",
                category="host_down",
                title=f"Host no longer reachable: {host}",
                description=f"Host {host} was not found in the latest scan.",
                project_id=project_id,
                timestamp=now,
                data={"host": host},
            ))

        # Store and broadcast
        self._alert_history.extend(alerts)
        await self._broadcast_alerts(alerts)

        logger.info(
            "Alerts generated",
            project=project_id,
            count=len(alerts),
            critical=sum(1 for a in alerts if a.severity == "critical"),
        )

        return alerts

    async def send_alert(self, alert: Alert) -> None:
        """Send a single alert via broadcast."""
        self._alert_history.append(alert)
        await self._broadcast_alerts([alert])

    def get_recent_alerts(
        self,
        project_id: str | None = None,
        limit: int = 50,
    ) -> list[Alert]:
        """Get recent alerts, optionally filtered by project."""
        alerts = self._alert_history
        if project_id:
            alerts = [a for a in alerts if a.project_id == project_id]
        return alerts[-limit:]

    async def _broadcast_alerts(self, alerts: list[Alert]) -> None:
        """Broadcast alerts to connected clients."""
        if not self._broadcast or not alerts:
            return

        for alert in alerts:
            try:
                await self._broadcast({
                    "type": "monitoring_alert",
                    "data": {
                        "alert_id": alert.alert_id,
                        "severity": alert.severity,
                        "category": alert.category,
                        "title": alert.title,
                        "description": alert.description,
                        "project_id": alert.project_id,
                        "timestamp": alert.timestamp,
                        "data": alert.data,
                    },
                })
            except Exception as exc:
                logger.warning("Alert broadcast failed", error=str(exc))
