"""
Continuous Monitor

Orchestrates scheduled re-scans and change detection.
Integrates with the DiffDetector and AlertManager to provide
real-time attack surface monitoring.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from core.logging import get_logger

logger = get_logger(__name__)


@dataclass
class MonitoringConfig:
    """Configuration for continuous monitoring."""
    project_id: str
    target: str
    interval_minutes: int = 60
    tools: list[str] = field(default_factory=lambda: ["subfinder", "naabu", "httpx", "nuclei"])
    alert_on_new_hosts: bool = True
    alert_on_new_vulns: bool = True
    alert_on_new_ports: bool = True
    max_iterations: int = 0  # 0 = unlimited


class ContinuousMonitor:
    """
    Orchestrates scheduled re-scans for attack surface monitoring.

    Runs periodic scans, compares against baseline via DiffDetector,
    and triggers alerts via AlertManager when changes are found.
    """

    def __init__(
        self,
        tool_executor: Any | None = None,
        diff_detector: Any | None = None,
        alert_manager: Any | None = None,
    ) -> None:
        self._executor = tool_executor
        self._diff = diff_detector
        self._alerter = alert_manager
        self._running: dict[str, bool] = {}
        self._tasks: dict[str, asyncio.Task[None]] = {}

    async def start_monitoring(self, config: MonitoringConfig) -> str:
        """
        Start continuous monitoring for a project.
        Returns a monitoring session ID.
        """
        session_id = f"monitor-{config.project_id}-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"
        self._running[session_id] = True

        task = asyncio.create_task(
            self._monitor_loop(session_id, config),
            name=f"monitor-{config.project_id}",
        )
        self._tasks[session_id] = task

        logger.info(
            "Monitoring started",
            session_id=session_id,
            project=config.project_id,
            interval=config.interval_minutes,
        )
        return session_id

    async def stop_monitoring(self, session_id: str) -> None:
        """Stop a running monitoring session."""
        self._running[session_id] = False
        task = self._tasks.pop(session_id, None)
        if task and not task.done():
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
        logger.info("Monitoring stopped", session_id=session_id)

    async def check_for_changes(
        self,
        config: MonitoringConfig,
    ) -> dict[str, Any]:
        """Run a single scan cycle and check for changes."""
        scan_result = await self._run_scan(config)

        changes: dict[str, Any] = {"scan_time": datetime.now(timezone.utc).isoformat()}

        if self._diff:
            changes = await self._diff.detect_changes(
                config.project_id, scan_result,
            )

        if self._alerter and self._has_significant_changes(changes, config):
            await self._alerter.evaluate_changes(changes, config.project_id)

        return changes

    def is_running(self, session_id: str) -> bool:
        return self._running.get(session_id, False)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    async def _monitor_loop(
        self,
        session_id: str,
        config: MonitoringConfig,
    ) -> None:
        """Main monitoring loop."""
        iterations = 0

        while self._running.get(session_id, False):
            try:
                await self.check_for_changes(config)
                iterations += 1

                if config.max_iterations and iterations >= config.max_iterations:
                    logger.info("Max iterations reached", session_id=session_id)
                    break

                await asyncio.sleep(config.interval_minutes * 60)

            except asyncio.CancelledError:
                break
            except Exception as exc:
                logger.error("Monitor loop error", error=str(exc))
                await asyncio.sleep(60)  # brief pause before retry

        self._running[session_id] = False

    async def _run_scan(self, config: MonitoringConfig) -> dict[str, Any]:
        """Run the configured scan tools and return combined results."""
        if not self._executor:
            return {}

        results: dict[str, Any] = {"target": config.target, "tools": {}}

        for tool in config.tools:
            try:
                args: dict[str, Any] = {"domain": config.target}
                if tool == "naabu":
                    args = {"host": config.target, "top_ports": "1000"}
                elif tool == "nuclei":
                    args = {"targets": [config.target], "severity": "critical,high,medium"}

                result = await self._executor.execute(tool, args)
                results["tools"][tool] = result
            except Exception as exc:
                results["tools"][tool] = {"error": str(exc)}

        return results

    @staticmethod
    def _has_significant_changes(
        changes: dict[str, Any],
        config: MonitoringConfig,
    ) -> bool:
        """Check if changes are significant enough to alert."""
        if config.alert_on_new_hosts and changes.get("new_hosts"):
            return True
        if config.alert_on_new_vulns and changes.get("new_vulns"):
            return True
        if config.alert_on_new_ports and changes.get("new_ports"):
            return True
        return False
