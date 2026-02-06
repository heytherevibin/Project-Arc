"""
Request Logging Middleware

Logs all incoming requests and outgoing responses.
"""

import time

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response

from core.logging import get_logger


logger = get_logger(__name__)


class LoggingMiddleware(BaseHTTPMiddleware):
    """
    Middleware that logs request and response information.
    
    Logs:
    - Request method and path
    - Response status code
    - Request duration
    - Client IP (if available)
    """
    
    async def dispatch(
        self,
        request: Request,
        call_next: RequestResponseEndpoint,
    ) -> Response:
        # Skip health check endpoint to reduce noise
        if request.url.path == "/health":
            return await call_next(request)
        
        # Record start time
        start_time = time.perf_counter()
        
        # Get client IP
        client_ip = self._get_client_ip(request)
        
        # Log request
        logger.info(
            "Request started",
            method=request.method,
            path=request.url.path,
            query=str(request.query_params) if request.query_params else None,
            client_ip=client_ip,
        )
        
        # Process request
        response = await call_next(request)
        
        # Calculate duration
        duration_ms = (time.perf_counter() - start_time) * 1000
        
        # Log response
        log_method = logger.info if response.status_code < 400 else logger.warning
        log_method(
            "Request completed",
            method=request.method,
            path=request.url.path,
            status_code=response.status_code,
            duration_ms=round(duration_ms, 2),
            client_ip=client_ip,
        )
        
        return response
    
    def _get_client_ip(self, request: Request) -> str | None:
        """Extract client IP from request headers."""
        # Check for forwarded headers (behind proxy)
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            # Take the first IP in the chain
            return forwarded_for.split(",")[0].strip()
        
        # Check for real IP header
        real_ip = request.headers.get("X-Real-IP")
        if real_ip:
            return real_ip
        
        # Fall back to client host
        if request.client:
            return request.client.host
        
        return None
