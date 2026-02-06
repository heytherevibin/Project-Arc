"""
Exfiltration Specialist Agent

Identifies and extracts high-value data from compromised hosts.
Handles sensitive file discovery, database dumping, and secure
data transfer.  All actions require human approval.
"""

from __future__ import annotations

from typing import Any

from agents.shared.base_agent import BaseAgent, Phase, ToolCall, ToolResponse
from core.logging import get_logger

logger = get_logger(__name__)


class ExfilSpecialist(BaseAgent):
    """Specialist agent for data exfiltration operations."""

    agent_id = "exfiltration"
    agent_name = "Exfiltration Specialist"
    supported_phases = [Phase.EXFILTRATION]
    available_tools = [
        "file_discovery", "database_dump",
        "exfiltrate_data", "archive_create",
        "data_staging",
    ]

    # File patterns considered high-value for pentest reporting
    HIGH_VALUE_PATTERNS = [
        "*.kdbx", "*.key", "*.pem", "*.pfx",         # Keys & certs
        "web.config", "appsettings.json", ".env",     # Config with secrets
        "shadow", "passwd", "SAM", "SYSTEM",          # OS credentials
        "*.sql", "*.bak", "*.mdf",                     # Database files
    ]

    async def plan(self, state: dict[str, Any]) -> list[ToolCall]:
        """
        Plan data discovery and exfiltration on compromised hosts.

        Prioritizes hosts with admin sessions for deeper access.
        """
        sessions = state.get("active_sessions", [])
        calls: list[ToolCall] = []

        if not sessions:
            return calls

        # Prioritize admin sessions
        admin_sessions = [s for s in sessions if s.get("is_admin")]
        target_sessions = admin_sessions[:3] or sessions[:3]

        for session in target_sessions:
            session_id = session.get("session_id", "")
            host = session.get("host", "")

            # Discover sensitive files
            calls.append(ToolCall(
                tool_name="file_discovery",
                args={
                    "session_id": session_id,
                    "host": host,
                    "patterns": self.HIGH_VALUE_PATTERNS,
                    "max_depth": 5,
                },
                requires_approval=True,
                risk_level="high",
            ))

            # Check for accessible databases
            calls.append(ToolCall(
                tool_name="database_dump",
                args={
                    "session_id": session_id,
                    "host": host,
                    "enumerate_only": True,  # Just discover, don't dump yet
                },
                requires_approval=True,
                risk_level="high",
            ))

        return calls

    async def analyze(self, state: dict[str, Any], results: list[ToolResponse]) -> dict[str, Any]:
        """Analyze data discovery results and record findings."""
        sensitive_files: list[dict[str, Any]] = []
        databases: list[dict[str, Any]] = []

        for result in results:
            if not result.success or not result.data:
                continue

            data = result.data if isinstance(result.data, dict) else {}

            # Track discovered sensitive files
            files = data.get("files", [])
            if files:
                sensitive_files.extend(files)

            # Track discovered databases
            dbs = data.get("databases", [])
            if dbs:
                databases.extend(dbs)

        # Store findings in agent messages for reporting
        if sensitive_files or databases:
            agent_messages = state.get("agent_messages", [])
            agent_messages.append({
                "from": self.agent_id,
                "to": "report",
                "content": "Data discovery complete",
                "data": {
                    "sensitive_files_count": len(sensitive_files),
                    "databases_count": len(databases),
                    "sensitive_files": sensitive_files[:20],  # Top 20
                    "databases": databases[:10],
                },
            })
            state["agent_messages"] = agent_messages

        logger.info(
            "Exfiltration analysis complete",
            sensitive_files=len(sensitive_files),
            databases=len(databases),
        )
        return state
