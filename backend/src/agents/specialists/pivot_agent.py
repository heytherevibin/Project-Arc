"""
Pivot (Lateral Movement) Specialist Agent

Handles lateral movement across the network using harvested credentials,
pass-the-hash, WMI execution, and SMB relay techniques.  All actions
require human approval.
"""

from __future__ import annotations

from typing import Any

from agents.shared.base_agent import BaseAgent, Phase, ToolCall, ToolResponse
from core.logging import get_logger

logger = get_logger(__name__)


class PivotSpecialist(BaseAgent):
    """Specialist agent for lateral movement operations."""

    agent_id = "pivot"
    agent_name = "Lateral Movement Specialist"
    supported_phases = [Phase.LATERAL_MOVEMENT]
    available_tools = [
        "impacket", "crackmapexec", "sliver",
        "psexec", "wmi_exec", "ssh_pivot",
    ]

    async def plan(self, state: dict[str, Any]) -> list[ToolCall]:
        """
        Plan lateral movement actions using harvested credentials
        and known hosts.
        """
        creds = state.get("harvested_creds", [])
        compromised = set(state.get("compromised_hosts", []))
        discovered = state.get("discovered_hosts", [])
        calls: list[ToolCall] = []

        if not creds:
            return calls

        # Identify uncompromised hosts reachable from the network
        targets = [h for h in discovered if h not in compromised][:10]

        if not targets:
            return calls

        # Use the best credential for each movement
        best_cred = self._best_credential(creds)

        for target_host in targets[:5]:
            # Try CrackMapExec for SMB-based lateral movement
            calls.append(ToolCall(
                tool_name="crackmapexec",
                args={
                    "target": target_host,
                    "username": best_cred.get("username", ""),
                    "credential": best_cred.get("hash") or best_cred.get("password", ""),
                    "method": "smb",
                },
                requires_approval=True,
                risk_level="critical",
            ))

        # If we have domain admin creds, attempt WMI exec on high-value targets
        if best_cred.get("is_admin") or best_cred.get("type") == "domain_admin":
            for target_host in targets[:3]:
                calls.append(ToolCall(
                    tool_name="wmi_exec",
                    args={
                        "target": target_host,
                        "username": best_cred.get("username", ""),
                        "credential": best_cred.get("hash") or best_cred.get("password", ""),
                    },
                    requires_approval=True,
                    risk_level="critical",
                ))

        return calls

    async def analyze(self, state: dict[str, Any], results: list[ToolResponse]) -> dict[str, Any]:
        """Analyze lateral movement results."""
        for result in results:
            if not result.success or not result.data:
                continue

            data = result.data if isinstance(result.data, dict) else {}

            # Track new sessions
            session = data.get("session")
            if session:
                sessions = state.get("active_sessions", [])
                sessions.append(session)
                state["active_sessions"] = sessions

                host = data.get("host") or session.get("host")
                if host:
                    compromised = state.get("compromised_hosts", [])
                    if host not in compromised:
                        compromised.append(host)
                    state["compromised_hosts"] = compromised

            # Track any new credentials discovered during pivot
            new_creds = data.get("credentials", [])
            if new_creds:
                existing = state.get("harvested_creds", [])
                existing.extend(new_creds)
                state["harvested_creds"] = existing

        logger.info(
            "Pivot analysis complete",
            compromised=len(state.get("compromised_hosts", [])),
            sessions=len(state.get("active_sessions", [])),
        )
        return state

    @staticmethod
    def _best_credential(creds: list[dict[str, Any]]) -> dict[str, Any]:
        """Pick the most privileged credential for lateral movement."""
        # Prefer domain admin > local admin > regular user
        priority = {"domain_admin": 0, "admin": 1, "local_admin": 1, "user": 2}
        sorted_creds = sorted(
            creds,
            key=lambda c: priority.get(c.get("type", "user"), 3),
        )
        return sorted_creds[0] if sorted_creds else {}
