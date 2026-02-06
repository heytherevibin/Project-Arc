"""Shared types for recon orchestrators."""

from dataclasses import dataclass, field
from typing import Any


@dataclass
class PhaseResult:
    """Result from an orchestrator run; pipeline uses data for storage and findings_delta for count."""

    success: bool
    data: dict[str, Any] = field(default_factory=dict)
    error: str | None = None
    findings_delta: int = 0
