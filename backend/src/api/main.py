"""
Arc API - Main Application

FastAPI application entry point with middleware, lifecycle management,
and route registration.
"""

import re
from contextlib import asynccontextmanager
from typing import AsyncIterator

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import ORJSONResponse

from api.middleware.correlation import CorrelationIdMiddleware
from api.middleware.logging import LoggingMiddleware
from api.middleware.rate_limit import RateLimitMiddleware
from api.graphql.schema import graphql_router
from api.routes import agents, auth, findings, graph, health, missions, monitoring, projects, recon_tools, reports, scans, settings, targets, vulnerabilities, websocket
from core.config import get_settings
from core.exceptions import ArcException
from core.logging import get_logger, setup_logging
from graph.client import close_neo4j, init_neo4j, get_neo4j_client
from graph.schema_init import init_schema


logger = get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """
    Application lifespan manager.
    
    Handles startup and shutdown events for database connections
    and other resources.
    """
    settings = get_settings()
    
    # Startup
    logger.info(
        "Starting Arc API",
        version=settings.APP_VERSION,
        environment=settings.APP_ENV,
    )
    
    # Initialize logging
    setup_logging()
    
    # Connect to Neo4j
    try:
        await init_neo4j()
        logger.info("Neo4j connection established")
        
        # Initialize schema
        client = get_neo4j_client()
        await init_schema(client)
        logger.info("Neo4j schema initialized")
        
    except Exception as e:
        logger.error("Failed to initialize Neo4j", error=str(e))
        # Allow startup to continue - health check will report unhealthy

    # Start monitoring scheduler (re-scan jobs)
    try:
        from api.routes.monitoring import monitoring_tick
        from core.monitoring import start_scheduler
        start_scheduler(monitoring_tick)
    except Exception as e:
        logger.warning("Monitoring scheduler not started", error=str(e))

    # Warn if all MCP URLs are the same (common cause of 404 for all tools)
    mcp_urls = [
        (getattr(settings, attr, "") or "").strip().rstrip("/")
        for _, attr in [
            ("naabu", "MCP_NAABU_URL"),
            ("httpx", "MCP_HTTPX_URL"),
            ("subfinder", "MCP_SUBFINDER_URL"),
            ("dnsx", "MCP_DNSX_URL"),
            ("katana", "MCP_KATANA_URL"),
            ("nuclei", "MCP_NUCLEI_URL"),
        ]
    ]
    if mcp_urls and all(u and u == mcp_urls[0] for u in mcp_urls):
        logger.warning(
            "All MCP_*_URL point to the same URL (%s). Each tool needs its own port. "
            "Use Naabu=8000, Httpx=8001, Subfinder=8002, dnsx=8003, Katana=8004, Nuclei=8005.",
            mcp_urls[0],
        )

    yield
    
    # Shutdown
    logger.info("Shutting down Arc API")
    try:
        from core.monitoring import stop_scheduler
        stop_scheduler()
    except Exception:
        pass
    await close_neo4j()


def create_application() -> FastAPI:
    """
    Create and configure the FastAPI application.
    
    Returns:
        Configured FastAPI application instance
    """
    settings = get_settings()
    
    app = FastAPI(
        title=settings.APP_NAME,
        description="Enterprise Autonomous AI Red Team Framework",
        version=settings.APP_VERSION,
        docs_url="/docs" if settings.is_development else None,
        redoc_url="/redoc" if settings.is_development else None,
        openapi_url="/openapi.json" if settings.is_development else None,
        default_response_class=ORJSONResponse,
        lifespan=lifespan,
    )
    
    # CORS from env only (CORS_ORIGINS, CORS_ORIGIN_REGEX); no hardcoded fallback
    cors_origins = (
        settings.CORS_ORIGINS
        if isinstance(settings.CORS_ORIGINS, list) and settings.CORS_ORIGINS
        else []
    )
    cors_kw: dict = {
        "allow_origins": cors_origins,
        "allow_credentials": True,
        "allow_methods": ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
        "allow_headers": ["*"],
        "expose_headers": ["X-Correlation-ID"],
    }
    if settings.CORS_ORIGIN_REGEX:
        cors_kw["allow_origin_regex"] = settings.CORS_ORIGIN_REGEX
    app.add_middleware(CORSMiddleware, **cors_kw)
    
    # Rate limiting (per-IP)
    app.add_middleware(RateLimitMiddleware)
    
    # Add custom middleware
    app.add_middleware(LoggingMiddleware)
    app.add_middleware(CorrelationIdMiddleware)
    
    # Register exception handlers
    register_exception_handlers(app)
    
    # Register routes
    register_routes(app, settings.API_PREFIX)
    
    return app


def _cors_headers_from_request(request: Request) -> dict[str, str]:
    """Add CORS headers for error responses using allowed origins from env."""
    origin = request.headers.get("origin")
    if not origin:
        return {}
    settings = get_settings()
    origins = (
        settings.CORS_ORIGINS
        if isinstance(settings.CORS_ORIGINS, list) and settings.CORS_ORIGINS
        else []
    )
    if origin in origins:
        return {
            "Access-Control-Allow-Origin": origin,
            "Access-Control-Allow-Credentials": "true",
        }
    if settings.CORS_ORIGIN_REGEX and re.match(settings.CORS_ORIGIN_REGEX, origin):
        return {
            "Access-Control-Allow-Origin": origin,
            "Access-Control-Allow-Credentials": "true",
        }
    return {}


def register_exception_handlers(app: FastAPI) -> None:
    """Register global exception handlers (with CORS on error responses)."""

    def _response(status_code: int, content: dict, request: Request) -> ORJSONResponse:
        r = ORJSONResponse(status_code=status_code, content=content)
        for k, v in _cors_headers_from_request(request).items():
            r.headers[k] = v
        return r

    @app.exception_handler(ArcException)
    async def arc_exception_handler(
        request: Request,
        exc: ArcException,
    ) -> ORJSONResponse:
        """Handle Arc-specific exceptions."""
        logger.warning(
            "Arc exception",
            code=exc.code,
            message=exc.message,
            path=request.url.path,
        )
        return _response(exc.status_code, exc.to_dict(), request)

    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(
        request: Request,
        exc: RequestValidationError,
    ) -> ORJSONResponse:
        """Handle Pydantic validation errors."""
        logger.warning(
            "Validation error",
            errors=exc.errors(),
            path=request.url.path,
        )
        return _response(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            {
                "error": {
                    "code": "VALIDATION_ERROR",
                    "message": "Request validation failed",
                    "details": {"errors": exc.errors()},
                }
            },
            request,
        )

    @app.exception_handler(Exception)
    async def unhandled_exception_handler(
        request: Request,
        exc: Exception,
    ) -> ORJSONResponse:
        """Handle unexpected exceptions."""
        logger.exception(
            "Unhandled exception",
            path=request.url.path,
            exception_type=type(exc).__name__,
        )
        return _response(
            status.HTTP_500_INTERNAL_SERVER_ERROR,
            {
                "error": {
                    "code": "INTERNAL_ERROR",
                    "message": "An unexpected error occurred",
                    "details": {},
                }
            },
            request,
        )


def register_routes(app: FastAPI, prefix: str) -> None:
    """Register API routes."""
    
    # Health check: at root (e.g. /health, /health/mcp) and under API prefix (e.g. /api/v1/health/mcp)
    app.include_router(health.router, tags=["Health"])
    app.include_router(health.router, prefix=prefix, tags=["Health"])
    
    # Authentication (no prefix for /api/v1/auth)
    app.include_router(
        auth.router,
        prefix=f"{prefix}/auth",
        tags=["Authentication"],
    )
    
    # API routes
    app.include_router(
        projects.router,
        prefix=f"{prefix}/projects",
        tags=["Projects"],
    )
    app.include_router(
        targets.router,
        prefix=f"{prefix}/targets",
        tags=["Targets"],
    )
    app.include_router(
        scans.router,
        prefix=f"{prefix}/scans",
        tags=["Scans"],
    )
    app.include_router(
        vulnerabilities.router,
        prefix=f"{prefix}/vulnerabilities",
        tags=["Vulnerabilities"],
    )
    app.include_router(
        findings.router,
        prefix=f"{prefix}/findings",
        tags=["Findings"],
    )
    app.include_router(
        reports.router,
        prefix=f"{prefix}/reports",
        tags=["Reports"],
    )
    app.include_router(
        graph.router,
        prefix=f"{prefix}/graph",
        tags=["Graph"],
    )
    app.include_router(
        recon_tools.router,
        prefix=f"{prefix}/tools",
        tags=["Recon Tools (Extended)"],
    )
    app.include_router(
        monitoring.router,
        prefix=f"{prefix}/monitoring",
        tags=["Monitoring"],
    )
    app.include_router(
        settings.router,
        prefix=f"{prefix}/settings",
        tags=["Settings"],
    )
    app.include_router(
        missions.router,
        prefix=f"{prefix}/missions",
        tags=["Missions"],
    )
    app.include_router(
        agents.router,
        prefix=f"{prefix}/agents",
        tags=["Agents"],
    )
    
    # GraphQL
    app.include_router(
        graphql_router,
        prefix=f"{prefix}",
        tags=["GraphQL"],
    )
    
    # WebSocket (no prefix)
    app.include_router(websocket.router, tags=["WebSocket"])


# Create application instance
app = create_application()
