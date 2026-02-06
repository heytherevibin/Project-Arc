"""
MCP Health Checker

Background async task that periodically pings all MCP server /health
endpoints and reports status.  Can broadcast status changes via WebSocket.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Any, Callable, Awaitable

from core.logging import get_logger

logger = get_logger(__name__)


class HealthChecker:
    """
    Background health checker for MCP tool servers.

    Periodically pings /health endpoints and tracks status.
    Broadcasts status changes to connected WebSocket clients.
    """

    def __init__(
        self,
        registry: Any,
        http_client: Any | None = None,
        interval_seconds: float = 30.0,
        broadcast_fn: Callable[[dict[str, Any]], Awaitable[None]] | None = None,
    ) -> None:
        """
        Parameters
        ----------
        registry         : ToolRegistry instance
        http_client      : httpx.AsyncClient or similar
        interval_seconds : how often to check health
        broadcast_fn     : optional async function to push status to clients
        """
        self._registry = registry
        self._http = http_client
        self._interval = interval_seconds
        self._broadcast = broadcast_fn
        self._running = False
        self._task: asyncio.Task[None] | None = None
        self._status: dict[str, bool] = {}

    async def start(self) -> None:
        """Start the background health check loop."""
        if self._running:
            return

        self._running = True
        self._task = asyncio.create_task(
            self._check_loop(),
            name="mcp-health-checker",
        )
        logger.info("Health checker started", interval=self._interval)

    async def stop(self) -> None:
        """Stop the background health check loop."""
        self._running = False
        if self._task and not self._task.done():
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        logger.info("Health checker stopped")

    def get_status(self) -> dict[str, Any]:
        """Get current health status of all tools."""
        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tools": self._status,
            "total": len(self._status),
            "healthy": sum(1 for v in self._status.values() if v),
            "unhealthy": sum(1 for v in self._status.values() if not v),
        }

    @property
    def is_running(self) -> bool:
        return self._running

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    async def _check_loop(self) -> None:
        """Main health check loop."""
        while self._running:
            try:
                await self._run_checks()
                await asyncio.sleep(self._interval)
            except asyncio.CancelledError:
                break
            except Exception as exc:
                logger.error("Health check loop error", error=str(exc))
                await asyncio.sleep(self._interval)

    async def _run_checks(self) -> None:
        """Check health of all registered tools."""
        if not self._registry:
            return

        old_status = dict(self._status)

        if self._http:
            new_status = await self._registry.health_check_all(
                http_client=self._http,
                timeout=5.0,
            )
        else:
            new_status = {t.name: False for t in self._registry.discover()}

        self._status = new_status

        # Detect changes and broadcast
        changes: dict[str, dict[str, bool]] = {}
        for name, healthy in new_status.items():
            if old_status.get(name) != healthy:
                changes[name] = {"was": old_status.get(name, False), "now": healthy}

        if changes and self._broadcast:
            try:
                await self._broadcast({
                    "type": "mcp_health_update",
                    "data": {
                        "status": new_status,
                        "changes": changes,
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    },
                })
            except Exception as exc:
                logger.warning("Health status broadcast failed", error=str(exc))

        if changes:
            logger.info("MCP health changes detected", changes=changes)
