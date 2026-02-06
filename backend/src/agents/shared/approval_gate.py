"""
Approval Gate

Human-in-the-loop approval checkpoints for dangerous operations.
When an agent wants to perform a high-risk action (exploitation,
lateral movement, persistence), it must request approval first.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from core.logging import get_logger

logger = get_logger(__name__)


class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ApprovalStatus(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    EXPIRED = "expired"


@dataclass
class ApprovalRequest:
    """A request for human approval of a dangerous action."""
    request_id: str
    agent_id: str
    action: str
    description: str
    risk_level: RiskLevel
    target: str
    tool_name: str
    tool_args: dict[str, Any]
    status: ApprovalStatus = ApprovalStatus.PENDING
    mitre_technique: str | None = None
    blast_radius: str | None = None
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    resolved_at: str | None = None
    resolved_by: str | None = None
    notes: str | None = None


class ApprovalGate:
    """
    Manages approval requests for dangerous operations.

    Agents check with the gate before performing high-risk actions.
    The gate holds the request until a human operator approves or denies it.
    """

    # Actions that always require approval
    ALWAYS_REQUIRE = {
        "exploit", "metasploit_exploit", "sqlmap_inject",
        "lateral_move", "psexec", "wmi_exec",
        "deploy_implant", "sliver_implant",
        "dump_credentials", "mimikatz",
        "establish_persistence",
        "exfiltrate_data",
    }

    # Risk level auto-classification
    RISK_MAP: dict[str, RiskLevel] = {
        "naabu_scan": RiskLevel.LOW,
        "subfinder": RiskLevel.LOW,
        "httpx_probe": RiskLevel.LOW,
        "nuclei_scan": RiskLevel.MEDIUM,
        "metasploit_exploit": RiskLevel.CRITICAL,
        "sqlmap_inject": RiskLevel.HIGH,
        "bloodhound_collect": RiskLevel.MEDIUM,
        "kerberoast": RiskLevel.HIGH,
        "dcsync": RiskLevel.CRITICAL,
        "sliver_implant": RiskLevel.CRITICAL,
        "lateral_move": RiskLevel.CRITICAL,
        "credential_dump": RiskLevel.CRITICAL,
    }

    def __init__(self) -> None:
        self._pending: dict[str, ApprovalRequest] = {}
        self._history: list[ApprovalRequest] = []

    def requires_approval(self, action: str, risk_level: str | None = None) -> bool:
        """Check if an action requires human approval."""
        if action in self.ALWAYS_REQUIRE:
            return True
        if risk_level and RiskLevel(risk_level) in (RiskLevel.HIGH, RiskLevel.CRITICAL):
            return True
        return False

    def request_approval(
        self,
        agent_id: str,
        action: str,
        description: str,
        target: str,
        tool_name: str,
        tool_args: dict[str, Any],
        mitre_technique: str | None = None,
        blast_radius: str | None = None,
    ) -> ApprovalRequest:
        """Create an approval request."""
        risk = self.RISK_MAP.get(action, RiskLevel.MEDIUM)

        request = ApprovalRequest(
            request_id=f"appr-{uuid.uuid4().hex[:12]}",
            agent_id=agent_id,
            action=action,
            description=description,
            risk_level=risk,
            target=target,
            tool_name=tool_name,
            tool_args=tool_args,
            mitre_technique=mitre_technique,
            blast_radius=blast_radius,
        )

        self._pending[request.request_id] = request
        logger.info(
            "Approval requested",
            request_id=request.request_id,
            agent=agent_id,
            action=action,
            risk=risk.value,
        )

        return request

    def approve(self, request_id: str, approved_by: str, notes: str | None = None) -> bool:
        """Approve a pending request."""
        req = self._pending.pop(request_id, None)
        if not req:
            return False

        req.status = ApprovalStatus.APPROVED
        req.resolved_at = datetime.now(timezone.utc).isoformat()
        req.resolved_by = approved_by
        req.notes = notes
        self._history.append(req)

        logger.info("Approval granted", request_id=request_id, by=approved_by)
        return True

    def deny(self, request_id: str, denied_by: str, notes: str | None = None) -> bool:
        """Deny a pending request."""
        req = self._pending.pop(request_id, None)
        if not req:
            return False

        req.status = ApprovalStatus.DENIED
        req.resolved_at = datetime.now(timezone.utc).isoformat()
        req.resolved_by = denied_by
        req.notes = notes
        self._history.append(req)

        logger.info("Approval denied", request_id=request_id, by=denied_by)
        return True

    def get_pending(self) -> list[ApprovalRequest]:
        """Get all pending approval requests."""
        return list(self._pending.values())

    def get_history(self, limit: int = 50) -> list[ApprovalRequest]:
        """Get approval history."""
        return self._history[-limit:]

    def is_approved(self, request_id: str) -> bool:
        """Check if a request has been approved."""
        # Check history
        for req in self._history:
            if req.request_id == request_id:
                return req.status == ApprovalStatus.APPROVED
        return False
