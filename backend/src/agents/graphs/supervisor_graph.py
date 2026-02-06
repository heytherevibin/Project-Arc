"""
Supervisor graph logic for the LangGraph workflow.

Encapsulates supervisor routing, phase advancement heuristics, and
conditional edge routing. Used by workflow.py to build the StateGraph.
"""

from __future__ import annotations

from datetime import datetime, timezone

from langgraph.graph import END

from agents.shared.base_agent import Phase
from agents.supervisor.supervisor_agent import AgentState
from core.logging import get_logger


logger = get_logger(__name__)


# ---------------------------------------------------------------------------
# Node keys (exported for workflow graph construction)
# ---------------------------------------------------------------------------
SUPERVISOR = "supervisor"
RECON = "recon"
VULN_ANALYSIS = "vuln_analysis"
EXPLOIT = "exploit"
POST_EXPLOIT = "post_exploit"
LATERAL = "lateral"
REPORT = "report"
APPROVAL_WAIT = "approval_wait"

MAX_ITERATIONS = 50

PHASE_ORDER = [
    Phase.RECON,
    Phase.VULN_ANALYSIS,
    Phase.EXPLOITATION,
    Phase.POST_EXPLOITATION,
    Phase.LATERAL_MOVEMENT,
    Phase.REPORTING,
]

_PHASE_AGENT = {
    Phase.RECON: RECON,
    Phase.VULN_ANALYSIS: VULN_ANALYSIS,
    Phase.EXPLOITATION: EXPLOIT,
    Phase.POST_EXPLOITATION: POST_EXPLOIT,
    Phase.LATERAL_MOVEMENT: LATERAL,
    Phase.REPORTING: REPORT,
}


def _phase_to_agent(phase: str) -> str:
    """Map phase to specialist node key."""
    return _PHASE_AGENT.get(phase, RECON)


def _should_advance(state: AgentState) -> str | None:
    """Determine if the mission should advance to the next phase."""
    current = state.get("current_phase", Phase.RECON)

    if current == Phase.RECON:
        if len(state.get("discovered_hosts", [])) > 0:
            return Phase.VULN_ANALYSIS
    elif current == Phase.VULN_ANALYSIS:
        if len(state.get("discovered_vulns", [])) > 0:
            return Phase.EXPLOITATION
    elif current == Phase.EXPLOITATION:
        if len(state.get("active_sessions", [])) > 0:
            return Phase.POST_EXPLOITATION
    elif current == Phase.POST_EXPLOITATION:
        if len(state.get("harvested_creds", [])) > 0:
            return Phase.LATERAL_MOVEMENT
    elif current == Phase.LATERAL_MOVEMENT:
        return Phase.REPORTING

    return None


async def supervisor_node(state: AgentState) -> AgentState:
    """Supervisor routing: decides the next specialist from current state."""
    current_phase = state.get("current_phase", Phase.RECON)
    iteration = state.get("_iteration", 0)
    state["_iteration"] = iteration + 1

    if iteration >= MAX_ITERATIONS:
        logger.warning("Max iterations reached, forcing report phase")
        state["current_phase"] = Phase.REPORTING
        state["next_agent"] = REPORT
        return state

    pending = [
        a for a in state.get("pending_approvals", [])
        if a.get("status") == "pending"
    ]
    if pending:
        state["next_agent"] = APPROVAL_WAIT
        return state

    next_phase = _should_advance(state)
    approval_phases = {Phase.EXPLOITATION, Phase.POST_EXPLOITATION, Phase.LATERAL_MOVEMENT}

    if next_phase and next_phase != current_phase:
        if next_phase in approval_phases:
            state["pending_approvals"] = state.get("pending_approvals", []) + [{
                "type": "phase_transition",
                "from_phase": current_phase,
                "to_phase": next_phase,
                "description": f"Advance to {next_phase} phase",
                "status": "pending",
            }]
            state["next_agent"] = APPROVAL_WAIT
        else:
            state["current_phase"] = next_phase
            state["phase_history"] = state.get("phase_history", []) + [{
                "from": current_phase,
                "to": next_phase,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }]
            state["next_agent"] = _phase_to_agent(next_phase)
    else:
        state["next_agent"] = _phase_to_agent(current_phase)

    return state


def route_after_supervisor(state: AgentState) -> str:
    """Conditional edge: route from supervisor to the chosen specialist or END."""
    next_agent = state.get("next_agent", RECON)
    if next_agent == "__end__":
        return END
    return next_agent


def route_after_approval(state: AgentState) -> str:
    """After approval wait, go back to supervisor for re-routing."""
    return SUPERVISOR


def route_after_specialist(state: AgentState) -> str:
    """After any specialist, go back to supervisor or END."""
    next_agent = state.get("next_agent", "")
    if next_agent == "__end__":
        return END
    return SUPERVISOR
