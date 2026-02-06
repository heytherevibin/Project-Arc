"""
Arc Exception Definitions

Hierarchical exception classes for consistent error handling across the framework.
All exceptions inherit from ArcException to enable unified exception handling.
"""

from typing import Any


class ArcException(Exception):
    """
    Base exception for all Arc-related errors.
    
    Provides structured error information for logging and API responses.
    
    Attributes:
        message: Human-readable error message
        code: Machine-readable error code
        details: Additional error context
        status_code: HTTP status code for API responses
    """
    
    def __init__(
        self,
        message: str,
        code: str = "ARC_ERROR",
        details: dict[str, Any] | None = None,
        status_code: int = 500,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.code = code
        self.details = details or {}
        self.status_code = status_code
    
    def to_dict(self) -> dict[str, Any]:
        """Convert exception to dictionary for API responses."""
        return {
            "error": {
                "code": self.code,
                "message": self.message,
                "details": self.details,
            }
        }
    
    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(code={self.code!r}, message={self.message!r})"


# =============================================================================
# Configuration Errors
# =============================================================================

class ConfigurationError(ArcException):
    """Raised when configuration is invalid or missing."""
    
    def __init__(
        self,
        message: str,
        config_key: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        details = details or {}
        if config_key:
            details["config_key"] = config_key
        super().__init__(
            message=message,
            code="CONFIGURATION_ERROR",
            details=details,
            status_code=500,
        )


# =============================================================================
# Database Errors
# =============================================================================

class DatabaseError(ArcException):
    """Base class for database-related errors."""
    
    def __init__(
        self,
        message: str,
        code: str = "DATABASE_ERROR",
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(
            message=message,
            code=code,
            details=details,
            status_code=503,
        )


class Neo4jConnectionError(DatabaseError):
    """Raised when Neo4j connection fails."""
    
    def __init__(self, message: str, details: dict[str, Any] | None = None) -> None:
        super().__init__(
            message=message,
            code="NEO4J_CONNECTION_ERROR",
            details=details,
        )


class Neo4jQueryError(DatabaseError):
    """Raised when a Neo4j query fails."""
    
    def __init__(
        self,
        message: str,
        query: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        details = details or {}
        if query:
            details["query"] = query[:500]  # Truncate long queries
        super().__init__(
            message=message,
            code="NEO4J_QUERY_ERROR",
            details=details,
        )


class RedisConnectionError(DatabaseError):
    """Raised when Redis connection fails."""
    
    def __init__(self, message: str, details: dict[str, Any] | None = None) -> None:
        super().__init__(
            message=message,
            code="REDIS_CONNECTION_ERROR",
            details=details,
        )


# =============================================================================
# Authentication & Authorization Errors
# =============================================================================

class AuthenticationError(ArcException):
    """Raised when authentication fails."""
    
    def __init__(
        self,
        message: str = "Authentication failed",
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(
            message=message,
            code="AUTHENTICATION_ERROR",
            details=details,
            status_code=401,
        )


class InvalidCredentialsError(AuthenticationError):
    """Raised when credentials are invalid."""
    
    def __init__(self, details: dict[str, Any] | None = None) -> None:
        super().__init__(
            message="Invalid credentials provided",
            details=details,
        )


class TokenExpiredError(AuthenticationError):
    """Raised when authentication token has expired."""
    
    def __init__(self, details: dict[str, Any] | None = None) -> None:
        super().__init__(
            message="Authentication token has expired",
            details=details,
        )


class InvalidTokenError(AuthenticationError):
    """Raised when authentication token is invalid."""
    
    def __init__(self, details: dict[str, Any] | None = None) -> None:
        super().__init__(
            message="Invalid authentication token",
            details=details,
        )


class AuthorizationError(ArcException):
    """Raised when user lacks permission for an action."""
    
    def __init__(
        self,
        message: str = "Permission denied",
        resource: str | None = None,
        action: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        details = details or {}
        if resource:
            details["resource"] = resource
        if action:
            details["action"] = action
        super().__init__(
            message=message,
            code="AUTHORIZATION_ERROR",
            details=details,
            status_code=403,
        )


# =============================================================================
# Validation Errors
# =============================================================================

class ValidationError(ArcException):
    """Raised when input validation fails."""
    
    def __init__(
        self,
        message: str,
        field: str | None = None,
        value: Any = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        details = details or {}
        if field:
            details["field"] = field
        if value is not None:
            # Avoid logging sensitive values
            details["value_type"] = type(value).__name__
        super().__init__(
            message=message,
            code="VALIDATION_ERROR",
            details=details,
            status_code=400,
        )


class InvalidTargetError(ValidationError):
    """Raised when a scan target is invalid."""
    
    def __init__(
        self,
        target: str,
        reason: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        details = details or {}
        details["target"] = target
        if reason:
            details["reason"] = reason
        super().__init__(
            message=f"Invalid target: {target}",
            details=details,
        )


# =============================================================================
# Tool & Scanning Errors
# =============================================================================

class ToolExecutionError(ArcException):
    """Raised when a security tool execution fails."""
    
    def __init__(
        self,
        message: str,
        tool_name: str,
        exit_code: int | None = None,
        stderr: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        details = details or {}
        details["tool_name"] = tool_name
        if exit_code is not None:
            details["exit_code"] = exit_code
        if stderr:
            details["stderr"] = stderr[:1000]  # Truncate long stderr
        super().__init__(
            message=message,
            code="TOOL_EXECUTION_ERROR",
            details=details,
            status_code=500,
        )


class ToolNotFoundError(ToolExecutionError):
    """Raised when a security tool is not available."""
    
    def __init__(self, tool_name: str, details: dict[str, Any] | None = None) -> None:
        super().__init__(
            message=f"Tool not found: {tool_name}",
            tool_name=tool_name,
            details=details,
        )


class ToolTimeoutError(ToolExecutionError):
    """Raised when a tool execution times out."""
    
    def __init__(
        self,
        tool_name: str,
        timeout_seconds: int,
        details: dict[str, Any] | None = None,
    ) -> None:
        details = details or {}
        details["timeout_seconds"] = timeout_seconds
        super().__init__(
            message=f"Tool {tool_name} timed out after {timeout_seconds}s",
            tool_name=tool_name,
            details=details,
        )


class ScanError(ArcException):
    """Base class for scan-related errors."""
    
    def __init__(
        self,
        message: str,
        scan_id: str | None = None,
        code: str = "SCAN_ERROR",
        details: dict[str, Any] | None = None,
    ) -> None:
        details = details or {}
        if scan_id:
            details["scan_id"] = scan_id
        super().__init__(
            message=message,
            code=code,
            details=details,
            status_code=500,
        )


class ScanNotFoundError(ScanError):
    """Raised when a scan is not found."""
    
    def __init__(self, scan_id: str, details: dict[str, Any] | None = None) -> None:
        super().__init__(
            message=f"Scan not found: {scan_id}",
            scan_id=scan_id,
            code="SCAN_NOT_FOUND",
            details=details,
        )
        self.status_code = 404


class ScanAlreadyRunningError(ScanError):
    """Raised when trying to start a scan that's already running."""
    
    def __init__(self, scan_id: str, details: dict[str, Any] | None = None) -> None:
        super().__init__(
            message=f"Scan is already running: {scan_id}",
            scan_id=scan_id,
            code="SCAN_ALREADY_RUNNING",
            details=details,
        )
        self.status_code = 409


# =============================================================================
# MCP Server Errors
# =============================================================================

class MCPError(ArcException):
    """Base class for MCP-related errors."""
    
    def __init__(
        self,
        message: str,
        server_name: str | None = None,
        code: str = "MCP_ERROR",
        details: dict[str, Any] | None = None,
    ) -> None:
        details = details or {}
        if server_name:
            details["server_name"] = server_name
        super().__init__(
            message=message,
            code=code,
            details=details,
            status_code=503,
        )


class MCPConnectionError(MCPError):
    """Raised when connection to MCP server fails."""
    
    def __init__(
        self,
        server_name: str,
        url: str,
        details: dict[str, Any] | None = None,
    ) -> None:
        details = details or {}
        details["url"] = url
        super().__init__(
            message=f"Failed to connect to MCP server: {server_name}",
            server_name=server_name,
            code="MCP_CONNECTION_ERROR",
            details=details,
        )


class MCPToolError(MCPError):
    """Raised when an MCP tool call fails."""
    
    def __init__(
        self,
        tool_name: str,
        server_name: str,
        error_message: str,
        details: dict[str, Any] | None = None,
    ) -> None:
        details = details or {}
        details["tool_name"] = tool_name
        details["error_message"] = error_message
        super().__init__(
            message=f"MCP tool '{tool_name}' failed: {error_message}",
            server_name=server_name,
            code="MCP_TOOL_ERROR",
            details=details,
        )


# =============================================================================
# Resource Errors
# =============================================================================

class ResourceNotFoundError(ArcException):
    """Raised when a requested resource is not found."""
    
    def __init__(
        self,
        resource_type: str,
        resource_id: str,
        details: dict[str, Any] | None = None,
    ) -> None:
        details = details or {}
        details["resource_type"] = resource_type
        details["resource_id"] = resource_id
        super().__init__(
            message=f"{resource_type} not found: {resource_id}",
            code="RESOURCE_NOT_FOUND",
            details=details,
            status_code=404,
        )


class ResourceConflictError(ArcException):
    """Raised when a resource conflict occurs."""
    
    def __init__(
        self,
        message: str,
        resource_type: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        details = details or {}
        if resource_type:
            details["resource_type"] = resource_type
        super().__init__(
            message=message,
            code="RESOURCE_CONFLICT",
            details=details,
            status_code=409,
        )


# =============================================================================
# Rate Limiting Errors
# =============================================================================

class RateLimitExceededError(ArcException):
    """Raised when rate limit is exceeded."""
    
    def __init__(
        self,
        retry_after_seconds: int,
        details: dict[str, Any] | None = None,
    ) -> None:
        details = details or {}
        details["retry_after_seconds"] = retry_after_seconds
        super().__init__(
            message="Rate limit exceeded",
            code="RATE_LIMIT_EXCEEDED",
            details=details,
            status_code=429,
        )
