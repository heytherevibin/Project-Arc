"""
Arc Core Module

Provides foundational components for the Arc framework including:
- Configuration management
- Logging infrastructure
- Exception definitions
- Common constants
"""

from core.config import Settings, get_settings
from core.exceptions import (
    ArcException,
    ConfigurationError,
    DatabaseError,
    AuthenticationError,
    AuthorizationError,
    ValidationError,
    ToolExecutionError,
    ScanError,
)
from core.constants import (
    ScanStatus,
    ScanType,
    Severity,
    Phase,
)

__all__ = [
    # Configuration
    "Settings",
    "get_settings",
    # Exceptions
    "ArcException",
    "ConfigurationError",
    "DatabaseError",
    "AuthenticationError",
    "AuthorizationError",
    "ValidationError",
    "ToolExecutionError",
    "ScanError",
    # Constants
    "ScanStatus",
    "ScanType",
    "Severity",
    "Phase",
]
