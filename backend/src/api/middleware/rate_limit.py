"""
Rate Limiting Middleware

Per-IP rate limiting for API endpoints.
Uses in-memory sliding window; for multi-worker production use Redis.
"""

import time
from collections import defaultdict
from typing import Callable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

from core.config import get_settings
from core.logging import get_logger


logger = get_logger(__name__)

# In-memory store: client_key -> list of request timestamps (sliding window)
# For multi-worker/production, replace with Redis-backed store
_request_timestamps: dict[str, list[float]] = defaultdict(list)


def _get_client_key(request: Request) -> str:
    """Get client identifier (IP or X-Forwarded-For when behind proxy)."""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    if request.client:
        return request.client.host
    return "unknown"


def _clean_old_timestamps(timestamps: list[float], window_seconds: int) -> list[float]:
    """Remove timestamps outside the current window."""
    cutoff = time.monotonic() - window_seconds
    return [t for t in timestamps if t > cutoff]


class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    Per-IP rate limiting using sliding window.
    
    Exempts health/live/ready and docs from limiting.
    """

    def __init__(self, app, requests_per_window: int | None = None, window_seconds: int | None = None):
        super().__init__(app)
        settings = get_settings()
        self.requests_per_window = requests_per_window or settings.RATE_LIMIT_REQUESTS
        self.window_seconds = window_seconds or settings.RATE_LIMIT_WINDOW_SECONDS

    async def dispatch(self, request: Request, call_next: Callable):
        path = request.scope.get("path", "")
        if path in ("/health", "/health/mcp", "/live", "/ready", "/docs", "/redoc", "/openapi.json"):
            return await call_next(request)
        if path.startswith("/api/v1/health") or path.startswith("/api/v1/live") or path.startswith("/api/v1/ready"):
            return await call_next(request)
        if path.startswith("/docs") or path.startswith("/redoc"):
            return await call_next(request)
        # WebSocket upgrade must not be rate-limited or connection fails before establishment
        if path == "/ws" or path.startswith("/ws?"):
            return await call_next(request)

        client_key = _get_client_key(request)
        now = time.monotonic()

        timestamps = _request_timestamps[client_key]
        timestamps = _clean_old_timestamps(timestamps, self.window_seconds)

        if len(timestamps) >= self.requests_per_window:
            logger.warning(
                "Rate limit exceeded",
                client=client_key,
                path=path,
                count=len(timestamps),
            )
            return JSONResponse(
                status_code=429,
                content={
                    "detail": "Rate limit exceeded. Try again later.",
                    "code": "RATE_LIMIT_EXCEEDED",
                },
            )

        timestamps.append(now)
        _request_timestamps[client_key] = timestamps

        response = await call_next(request)

        if response.status_code < 400:
            remaining = max(0, self.requests_per_window - len(timestamps))
            response.headers["X-RateLimit-Limit"] = str(self.requests_per_window)
            response.headers["X-RateLimit-Remaining"] = str(remaining)

        return response
