"""
Arc Logging Configuration

Structured logging with ELK Stack integration.
Provides JSON-formatted logs for production and human-readable logs for development.
"""

import logging
import sys
from contextvars import ContextVar
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

import structlog
from structlog.types import Processor

from core.config import get_settings


# Context variables for request-scoped data
correlation_id_var: ContextVar[str] = ContextVar("correlation_id", default="")
user_id_var: ContextVar[str] = ContextVar("user_id", default="")
project_id_var: ContextVar[str] = ContextVar("project_id", default="")


def get_correlation_id() -> str:
    """Get the current correlation ID or generate a new one."""
    cid = correlation_id_var.get()
    if not cid:
        cid = str(uuid4())
        correlation_id_var.set(cid)
    return cid


def set_correlation_id(correlation_id: str) -> None:
    """Set the correlation ID for the current context."""
    correlation_id_var.set(correlation_id)


def set_user_context(user_id: str, project_id: str | None = None) -> None:
    """Set user context for logging."""
    user_id_var.set(user_id)
    if project_id:
        project_id_var.set(project_id)


def add_correlation_id(
    logger: logging.Logger,
    method_name: str,
    event_dict: dict[str, Any],
) -> dict[str, Any]:
    """Add correlation ID to log events."""
    event_dict["correlation_id"] = get_correlation_id()
    return event_dict


def add_user_context(
    logger: logging.Logger,
    method_name: str,
    event_dict: dict[str, Any],
) -> dict[str, Any]:
    """Add user context to log events."""
    user_id = user_id_var.get()
    if user_id:
        event_dict["user_id"] = user_id
    
    project_id = project_id_var.get()
    if project_id:
        event_dict["project_id"] = project_id
    
    return event_dict


def add_app_context(
    logger: logging.Logger,
    method_name: str,
    event_dict: dict[str, Any],
) -> dict[str, Any]:
    """Add application context to log events."""
    settings = get_settings()
    event_dict["app_name"] = settings.APP_NAME
    event_dict["app_version"] = settings.APP_VERSION
    event_dict["environment"] = settings.APP_ENV
    return event_dict


def add_timestamp(
    logger: logging.Logger,
    method_name: str,
    event_dict: dict[str, Any],
) -> dict[str, Any]:
    """Add ISO 8601 timestamp to log events."""
    event_dict["@timestamp"] = datetime.now(timezone.utc).isoformat()
    return event_dict


def rename_event_key(
    logger: logging.Logger,
    method_name: str,
    event_dict: dict[str, Any],
) -> dict[str, Any]:
    """Rename 'event' to 'message' for ELK compatibility."""
    if "event" in event_dict:
        event_dict["message"] = event_dict.pop("event")
    return event_dict


def setup_logging() -> None:
    """
    Configure structured logging for the application.
    
    Sets up structlog with appropriate processors for the environment:
    - Development: Console-friendly colored output
    - Production: JSON output for ELK Stack
    """
    settings = get_settings()
    
    # Common processors for all environments
    shared_processors: list[Processor] = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_log_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.PositionalArgumentsFormatter(),
        add_timestamp,
        add_correlation_id,
        add_user_context,
        add_app_context,
        structlog.processors.StackInfoRenderer(),
        structlog.processors.UnicodeDecoder(),
    ]
    
    if settings.LOG_FORMAT == "json" or settings.is_production:
        # Production: JSON output for ELK
        processors: list[Processor] = [
            *shared_processors,
            rename_event_key,
            structlog.processors.format_exc_info,
            structlog.processors.JSONRenderer(),
        ]
        
        # Configure standard library logging for JSON
        logging.basicConfig(
            format="%(message)s",
            stream=sys.stdout,
            level=getattr(logging, settings.LOG_LEVEL),
        )
    else:
        # Development: Console-friendly output
        processors = [
            *shared_processors,
            structlog.dev.ConsoleRenderer(
                colors=True,
                exception_formatter=structlog.dev.plain_traceback,
            ),
        ]
        
        logging.basicConfig(
            format="%(message)s",
            stream=sys.stdout,
            level=getattr(logging, settings.LOG_LEVEL),
        )
    
    # Configure structlog
    structlog.configure(
        processors=processors,
        wrapper_class=structlog.stdlib.BoundLogger,
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )
    
    # Reduce noise from third-party libraries
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    logging.getLogger("neo4j").setLevel(logging.WARNING)


def get_logger(name: str | None = None) -> structlog.stdlib.BoundLogger:
    """
    Get a configured logger instance.
    
    Args:
        name: Logger name (usually __name__ of the calling module)
    
    Returns:
        Configured structlog logger
    
    Example:
        logger = get_logger(__name__)
        logger.info("Processing request", request_id="abc123")
    """
    return structlog.get_logger(name)


class LogContext:
    """
    Context manager for adding temporary context to logs.
    
    Example:
        with LogContext(scan_id="scan-123", target="example.com"):
            logger.info("Starting scan")  # Includes scan_id and target
    """
    
    def __init__(self, **kwargs: Any) -> None:
        self.context = kwargs
        self._token: Any = None
    
    def __enter__(self) -> "LogContext":
        self._token = structlog.contextvars.bind_contextvars(**self.context)
        return self
    
    def __exit__(self, *args: Any) -> None:
        if self._token:
            structlog.contextvars.unbind_contextvars(*self.context.keys())


def log_exception(
    logger: structlog.stdlib.BoundLogger,
    exception: Exception,
    message: str = "Exception occurred",
    **extra: Any,
) -> None:
    """
    Log an exception with structured context.
    
    Args:
        logger: The logger instance
        exception: The exception to log
        message: Log message
        **extra: Additional context to include
    """
    logger.exception(
        message,
        exception_type=type(exception).__name__,
        exception_message=str(exception),
        **extra,
    )


def log_tool_execution(
    logger: structlog.stdlib.BoundLogger,
    tool_name: str,
    target: str,
    success: bool,
    duration_ms: float,
    **extra: Any,
) -> None:
    """
    Log a tool execution with standardized format.
    
    Args:
        logger: The logger instance
        tool_name: Name of the tool executed
        target: Target of the tool execution
        success: Whether execution succeeded
        duration_ms: Execution duration in milliseconds
        **extra: Additional context to include
    """
    log_method = logger.info if success else logger.warning
    log_method(
        "Tool execution completed",
        tool_name=tool_name,
        target=target,
        success=success,
        duration_ms=round(duration_ms, 2),
        **extra,
    )


def log_scan_event(
    logger: structlog.stdlib.BoundLogger,
    scan_id: str,
    event_type: str,
    phase: str | None = None,
    progress: float | None = None,
    **extra: Any,
) -> None:
    """
    Log a scan event with standardized format.
    
    Args:
        logger: The logger instance
        scan_id: Unique scan identifier
        event_type: Type of scan event
        phase: Current scan phase
        progress: Scan progress (0-100)
        **extra: Additional context to include
    """
    logger.info(
        "Scan event",
        scan_id=scan_id,
        event_type=event_type,
        phase=phase,
        progress=progress,
        **extra,
    )


def log_security_event(
    logger: structlog.stdlib.BoundLogger,
    event_type: str,
    severity: str,
    source_ip: str | None = None,
    user_agent: str | None = None,
    **extra: Any,
) -> None:
    """
    Log a security-relevant event.
    
    Args:
        logger: The logger instance
        event_type: Type of security event
        severity: Event severity
        source_ip: Source IP address
        user_agent: User agent string
        **extra: Additional context to include
    """
    logger.warning(
        "Security event",
        security_event_type=event_type,
        security_severity=severity,
        source_ip=source_ip,
        user_agent=user_agent,
        **extra,
    )
