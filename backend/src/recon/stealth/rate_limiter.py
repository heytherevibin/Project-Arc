"""
Scan Rate Limiter

Token-bucket rate limiting for scan tools to avoid detection
and IDS/IPS alerts.  Configurable per-tool limits.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from typing import Any

from core.logging import get_logger

logger = get_logger(__name__)


@dataclass
class RateLimitConfig:
    """Rate limit configuration for a tool."""
    tool_name: str
    tokens_per_second: float  # refill rate
    max_tokens: int           # bucket capacity
    burst_allowed: bool = False


class ScanRateLimiter:
    """
    Token-bucket rate limiter for scan tools.

    Each tool has its own bucket with configurable fill rate
    and maximum capacity.  ``acquire()`` blocks until a token
    is available.
    """

    # Default limits per tool (requests per second)
    DEFAULT_LIMITS: dict[str, float] = {
        "subfinder": 10.0,
        "naabu": 5.0,
        "httpx": 20.0,
        "nuclei": 3.0,
        "katana": 5.0,
        "nikto": 2.0,
        "gvm": 1.0,
        "sqlmap": 1.0,
        "commix": 1.0,
    }

    def __init__(self, custom_limits: dict[str, float] | None = None) -> None:
        self._limits = {**self.DEFAULT_LIMITS, **(custom_limits or {})}
        self._buckets: dict[str, _TokenBucket] = {}
        self._lock = asyncio.Lock()

    async def acquire(self, tool_name: str) -> None:
        """
        Acquire a rate-limit token for a tool.
        Blocks until a token is available.
        """
        bucket = self._get_bucket(tool_name)
        await bucket.acquire()

    def release(self, tool_name: str) -> None:
        """Explicitly release a token (optional — tokens auto-refill)."""
        # Token buckets auto-refill; this is a no-op but provided for API symmetry
        pass

    def set_limit(self, tool_name: str, tokens_per_second: float) -> None:
        """Set or update the rate limit for a tool."""
        self._limits[tool_name] = tokens_per_second
        # Reset bucket if it exists
        if tool_name in self._buckets:
            self._buckets[tool_name] = _TokenBucket(
                rate=tokens_per_second,
                capacity=max(1, int(tokens_per_second * 2)),
            )

    def get_limit(self, tool_name: str) -> float:
        """Get current rate limit for a tool."""
        return self._limits.get(tool_name, 10.0)

    def _get_bucket(self, tool_name: str) -> _TokenBucket:
        if tool_name not in self._buckets:
            rate = self._limits.get(tool_name, 10.0)
            self._buckets[tool_name] = _TokenBucket(
                rate=rate,
                capacity=max(1, int(rate * 2)),
            )
        return self._buckets[tool_name]


class _TokenBucket:
    """Simple async token bucket implementation."""

    def __init__(self, rate: float, capacity: int) -> None:
        self._rate = rate          # tokens per second
        self._capacity = capacity
        self._tokens = float(capacity)
        self._last_refill = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        """Wait until a token is available, then consume it."""
        while True:
            async with self._lock:
                self._refill()
                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    return

            # Wait proportional to refill rate
            wait = 1.0 / self._rate if self._rate > 0 else 1.0
            await asyncio.sleep(wait)

    def _refill(self) -> None:
        now = time.monotonic()
        elapsed = now - self._last_refill
        self._tokens = min(
            float(self._capacity),
            self._tokens + elapsed * self._rate,
        )
        self._last_refill = now
