"""
Decoy Traffic Generator

Generates benign HTTP traffic to mask scan patterns and reduce
the signal-to-noise ratio for IDS/IPS systems.
"""

from __future__ import annotations

import asyncio
import random
from typing import Any

from core.logging import get_logger

logger = get_logger(__name__)

# Common benign user-agent strings
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
]

# Common benign paths that look like normal browsing
BENIGN_PATHS = [
    "/", "/index.html", "/about", "/contact", "/favicon.ico",
    "/robots.txt", "/sitemap.xml", "/css/style.css", "/js/main.js",
    "/images/logo.png", "/api/health", "/status", "/feed",
]


class DecoyTrafficGenerator:
    """
    Generates benign-looking HTTP traffic in the background
    to reduce the detectability of active scanning operations.

    Uses asyncio tasks for non-blocking background operation.
    """

    def __init__(
        self,
        http_client: Any | None = None,
        requests_per_minute: float = 30.0,
    ) -> None:
        """
        Parameters
        ----------
        http_client        : optional httpx.AsyncClient
        requests_per_minute: rate of decoy requests
        """
        self._http = http_client
        self._rate = requests_per_minute
        self._running = False
        self._task: asyncio.Task[None] | None = None
        self._targets: list[str] = []
        self._requests_sent = 0

    async def start_decoy(
        self,
        targets: list[str],
        duration_minutes: float | None = None,
    ) -> None:
        """
        Start generating decoy traffic against the given targets.

        Parameters
        ----------
        targets          : list of base URLs to send decoy requests to
        duration_minutes : optional max duration (None = until stopped)
        """
        if self._running:
            logger.warning("Decoy traffic already running")
            return

        self._targets = targets
        self._running = True
        self._requests_sent = 0

        self._task = asyncio.create_task(
            self._traffic_loop(duration_minutes),
            name="decoy-traffic",
        )

        logger.info(
            "Decoy traffic started",
            targets=len(targets),
            rate=self._rate,
        )

    async def stop_decoy(self) -> dict[str, Any]:
        """Stop generating decoy traffic. Returns stats."""
        self._running = False
        if self._task and not self._task.done():
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass

        stats = {
            "requests_sent": self._requests_sent,
            "targets": len(self._targets),
        }

        logger.info("Decoy traffic stopped", **stats)
        return stats

    @property
    def is_running(self) -> bool:
        return self._running

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    async def _traffic_loop(self, duration_minutes: float | None) -> None:
        """Main decoy traffic loop."""
        interval = 60.0 / self._rate if self._rate > 0 else 2.0
        elapsed = 0.0

        while self._running:
            try:
                if duration_minutes and elapsed >= duration_minutes * 60:
                    break

                await self._send_decoy_request()
                self._requests_sent += 1

                # Add jitter to make traffic look more natural
                jitter = random.uniform(0.5, 1.5) * interval
                await asyncio.sleep(jitter)
                elapsed += jitter

            except asyncio.CancelledError:
                break
            except Exception as exc:
                logger.debug("Decoy request failed", error=str(exc))
                await asyncio.sleep(interval)
                elapsed += interval

        self._running = False

    async def _send_decoy_request(self) -> None:
        """Send a single benign-looking HTTP request."""
        if not self._http or not self._targets:
            return

        target = random.choice(self._targets)
        path = random.choice(BENIGN_PATHS)
        url = f"{target.rstrip('/')}{path}"
        ua = random.choice(USER_AGENTS)

        headers = {
            "User-Agent": ua,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Connection": "keep-alive",
        }

        try:
            await self._http.get(url, headers=headers, timeout=10, follow_redirects=True)
        except Exception:
            pass  # Decoy failures are expected and non-critical
