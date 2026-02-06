"""
Correlation ID Middleware

Adds correlation IDs to requests for distributed tracing.
"""

from uuid import uuid4

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response

from core.logging import set_correlation_id


CORRELATION_ID_HEADER = "X-Correlation-ID"


class CorrelationIdMiddleware(BaseHTTPMiddleware):
    """
    Middleware that ensures every request has a correlation ID.
    
    If the request includes an X-Correlation-ID header, it is used.
    Otherwise, a new UUID is generated.
    
    The correlation ID is:
    1. Set in the logging context for all log messages
    2. Added to the response headers for client tracking
    """
    
    async def dispatch(
        self,
        request: Request,
        call_next: RequestResponseEndpoint,
    ) -> Response:
        # Get or generate correlation ID
        correlation_id = request.headers.get(CORRELATION_ID_HEADER)
        if not correlation_id:
            correlation_id = str(uuid4())
        
        # Set in logging context
        set_correlation_id(correlation_id)
        
        # Store in request state for access in routes
        request.state.correlation_id = correlation_id
        
        # Process request
        response = await call_next(request)
        
        # Add to response headers
        response.headers[CORRELATION_ID_HEADER] = correlation_id
        
        return response
