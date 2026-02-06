"""
Persistence Specialist Agent

Establishes persistence mechanisms on compromised hosts to maintain
long-term access.  Uses Sliver C2 implants, scheduled tasks, registry
modifications, and service installations.  All actions require approval.
"""

from __future__ import annotations

from typing import Any

from agents.shared.base_agent import BaseAgent, Phase, ToolCall, ToolResponse
from core.logging import get_logger

logger = get_logger(__name__)


class PersistenceSpecialist(BaseAgent):
    """Specialist agent for establishing persistence."""

    agent_id = "persistence"
    agent_name = "Persistence Specialist"
    supported_phases = [Phase.PERSISTENCE]
    available_tools = [
        "sliver", "sliver_implant",
        "establish_persistence", "scheduled_task",
        "registry_persistence", "service_install",
    ]

    async def plan(self, state: dict[str, Any]) -> list[ToolCall]:
        """
        Plan persistence mechanisms on compromised hosts.

        Chooses appropriate techniques based on the host OS and
        available session privileges.
        """
        sessions = state.get("active_sessions", [])
        calls: list[ToolCall] = []

        if not sessions:
            return calls

        for session in sessions[:5]:
            session_id = session.get("session_id", "")
            host = session.get("host", "")
            os_type = session.get("os", "").lower()
            is_admin = session.get("is_admin", False)

            # Deploy C2 implant for long-term access
            calls.append(ToolCall(
                tool_name="sliver_implant",
                args={
                    "session_id": session_id,
                    "host": host,
                    "implant_type": "beacon",
                    "callback_interval": 300,  # 5 minute beacon
                },
                requires_approval=True,
                risk_level="critical",
            ))

            if is_admin:
                if "windows" in os_type:
                    # Windows: scheduled task + registry run key
                    calls.append(ToolCall(
                        tool_name="scheduled_task",
                        args={
                            "session_id": session_id,
                            "host": host,
                            "task_name": "SystemHealthCheck",
                            "trigger": "on_login",
                        },
                        requires_approval=True,
                        risk_level="critical",
                    ))
                else:
                    # Linux: cron job or systemd service
                    calls.append(ToolCall(
                        tool_name="establish_persistence",
                        args={
                            "session_id": session_id,
                            "host": host,
                            "method": "cron",
                        },
                        requires_approval=True,
                        risk_level="critical",
                    ))

        return calls

    async def analyze(self, state: dict[str, Any], results: list[ToolResponse]) -> dict[str, Any]:
        """Analyze persistence establishment results."""
        implants_deployed = 0

        for result in results:
            if not result.success or not result.data:
                continue

            data = result.data if isinstance(result.data, dict) else {}

            # Track deployed implants
            implant = data.get("implant")
            if implant:
                implants_deployed += 1
                # Update session with implant info
                sessions = state.get("active_sessions", [])
                for session in sessions:
                    host = implant.get("host", "")
                    if session.get("host") == host:
                        session["implant_id"] = implant.get("implant_id")
                        session["persistence"] = True
                        break

            # Track persistence method
            method = data.get("persistence_method")
            if method:
                agent_messages = state.get("agent_messages", [])
                agent_messages.append({
                    "from": self.agent_id,
                    "to": "supervisor",
                    "content": f"Persistence established on {data.get('host', '?')} via {method}",
                })
                state["agent_messages"] = agent_messages

        logger.info(
            "Persistence analysis complete",
            implants_deployed=implants_deployed,
        )
        return state
