"""
Supervisor Agent

Top-level orchestrator that routes tasks to specialist agents based on
mission phase, maintains the goal hierarchy, and coordinates the overall
penetration test campaign.

Uses LangGraph StateGraph for workflow orchestration with checkpointing.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Annotated, Any, AsyncIterator, TypedDict

from core.config import get_settings
from core.logging import get_logger
from agents.shared.approval_gate import ApprovalGate
from agents.shared.base_agent import AgentMessage, Phase
from memory.cognitive import CognitiveMemory
from memory.working.context_manager import Goal, WorkingMemory

logger = get_logger(__name__)


# ---------------------------------------------------------------------------
# Agent State (shared across the graph)
# ---------------------------------------------------------------------------

def _merge_messages(left: list, right: list) -> list:
    """Merge message lists (LangGraph reducer)."""
    return left + right


class AgentState(TypedDict, total=False):
    """Shared state for the multi-agent graph."""
    # Core messaging
    messages: Annotated[list[dict[str, Any]], _merge_messages]

    # Mission tracking
    mission_id: str
    project_id: str
    current_phase: str
    phase_history: list[dict[str, Any]]

    # Hierarchical goals
    strategic_goals: list[dict[str, Any]]
    tactical_goals: list[dict[str, Any]]
    operational_goals: list[dict[str, Any]]

    # Shared intelligence
    target: str
    discovered_hosts: list[str]
    discovered_vulns: list[dict[str, Any]]
    active_sessions: list[dict[str, Any]]
    compromised_hosts: list[str]
    harvested_creds: list[dict[str, Any]]

    # Coordination
    pending_approvals: list[dict[str, Any]]
    agent_messages: list[dict[str, Any]]

    # Next agent to route to
    next_agent: str


# ---------------------------------------------------------------------------
# Supervisor Agent
# ---------------------------------------------------------------------------

class SupervisorAgent:
    """
    Top-level orchestrator using a state graph pattern.

    Routes tasks to specialist agents based on the current mission phase:
    - recon          → ReconAgent
    - vuln_analysis  → VulnAnalysisAgent
    - exploitation   → ExploitAgent (requires approval)
    - post_exploit   → PostExploitAgent (requires approval)
    - lateral        → LateralMovementAgent (requires approval)
    - reporting      → ReportAgent
    """

    PHASE_ORDER = [
        Phase.RECON,
        Phase.VULN_ANALYSIS,
        Phase.EXPLOITATION,
        Phase.POST_EXPLOITATION,
        Phase.LATERAL_MOVEMENT,
        Phase.REPORTING,
    ]

    PHASE_AGENT_MAP = {
        Phase.RECON: "recon",
        Phase.VULN_ANALYSIS: "vuln_analysis",
        Phase.EXPLOITATION: "exploit",
        Phase.POST_EXPLOITATION: "post_exploit",
        Phase.LATERAL_MOVEMENT: "lateral",
        Phase.REPORTING: "report",
    }

    # Phases that require human approval before entering
    APPROVAL_PHASES = {Phase.EXPLOITATION, Phase.POST_EXPLOITATION, Phase.LATERAL_MOVEMENT}

    def __init__(
        self,
        memory: CognitiveMemory,
        approval_gate: ApprovalGate | None = None,
    ) -> None:
        self.memory = memory
        self.working = WorkingMemory()
        self.approval_gate = approval_gate or ApprovalGate()
        self._settings = get_settings()

    def create_initial_state(
        self,
        mission_id: str,
        project_id: str,
        target: str,
        objective: str,
    ) -> AgentState:
        """Create initial state for a new mission."""
        return AgentState(
            messages=[{"role": "user", "content": objective}],
            mission_id=mission_id,
            project_id=project_id,
            current_phase=Phase.RECON,
            phase_history=[],
            strategic_goals=[{
                "goal_id": f"goal-{uuid.uuid4().hex[:8]}",
                "description": objective,
                "level": "strategic",
                "status": "active",
            }],
            tactical_goals=[],
            operational_goals=[],
            target=target,
            discovered_hosts=[],
            discovered_vulns=[],
            active_sessions=[],
            compromised_hosts=[],
            harvested_creds=[],
            pending_approvals=[],
            agent_messages=[],
            next_agent="recon",
        )

    async def route(self, state: AgentState) -> AgentState:
        """
        Supervisor routing node: decide which specialist to invoke next.

        This is the "think" step of the supervisor.
        """
        current_phase = state.get("current_phase", Phase.RECON)
        target = state.get("target", "")

        logger.info(
            "Supervisor routing",
            mission=state.get("mission_id"),
            phase=current_phase,
            target=target,
        )

        # Check if current phase is complete and should advance
        next_phase = self._should_advance_phase(state)

        if next_phase and next_phase != current_phase:
            # Phase transition
            if next_phase in self.APPROVAL_PHASES:
                # Require human approval before entering dangerous phases
                state["pending_approvals"].append({
                    "type": "phase_transition",
                    "from_phase": current_phase,
                    "to_phase": next_phase,
                    "description": f"Advance to {next_phase} phase",
                    "status": "pending",
                })
                logger.info(
                    "Approval required for phase transition",
                    from_phase=current_phase,
                    to_phase=next_phase,
                )
                # Stay in current phase until approved
                state["next_agent"] = self.PHASE_AGENT_MAP.get(current_phase, "recon")
            else:
                state["current_phase"] = next_phase
                state["phase_history"].append({
                    "from": current_phase,
                    "to": next_phase,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                })
                state["next_agent"] = self.PHASE_AGENT_MAP.get(next_phase, "recon")
                logger.info("Phase transition", from_phase=current_phase, to_phase=next_phase)
        else:
            # Stay in current phase
            state["next_agent"] = self.PHASE_AGENT_MAP.get(current_phase, "recon")

        return state

    def _should_advance_phase(self, state: AgentState) -> str | None:
        """Determine if the mission should advance to the next phase."""
        current = state.get("current_phase", Phase.RECON)
        current_idx = self.PHASE_ORDER.index(current) if current in self.PHASE_ORDER else 0

        # Simple heuristics for phase advancement
        if current == Phase.RECON:
            # Advance to vuln_analysis when we have hosts
            hosts = state.get("discovered_hosts", [])
            if len(hosts) > 0:
                return Phase.VULN_ANALYSIS

        elif current == Phase.VULN_ANALYSIS:
            # Advance to exploitation when we have vulnerabilities
            vulns = state.get("discovered_vulns", [])
            if len(vulns) > 0:
                return Phase.EXPLOITATION

        elif current == Phase.EXPLOITATION:
            # Advance to post-exploitation when we have sessions
            sessions = state.get("active_sessions", [])
            if len(sessions) > 0:
                return Phase.POST_EXPLOITATION

        elif current == Phase.POST_EXPLOITATION:
            # Advance to lateral movement when we have credentials
            creds = state.get("harvested_creds", [])
            if len(creds) > 0:
                return Phase.LATERAL_MOVEMENT

        elif current == Phase.LATERAL_MOVEMENT:
            # Advance to reporting when we've compromised enough
            return Phase.REPORTING

        return None

    async def approve_phase_transition(
        self,
        state: AgentState,
        approved_by: str,
    ) -> AgentState:
        """Approve a pending phase transition."""
        pending = state.get("pending_approvals", [])
        for approval in pending:
            if approval.get("status") == "pending" and approval.get("type") == "phase_transition":
                approval["status"] = "approved"
                approval["approved_by"] = approved_by
                approval["approved_at"] = datetime.now(timezone.utc).isoformat()

                new_phase = approval["to_phase"]
                state["current_phase"] = new_phase
                state["phase_history"].append({
                    "from": approval["from_phase"],
                    "to": new_phase,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "approved_by": approved_by,
                })
                state["next_agent"] = self.PHASE_AGENT_MAP.get(new_phase, "recon")

                logger.info(
                    "Phase transition approved",
                    to_phase=new_phase,
                    by=approved_by,
                )
                break

        return state
