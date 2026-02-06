"""
Supervisor State

Canonical definition of the shared AgentState TypedDict used across
the entire LangGraph workflow.  Extracted from supervisor_agent.py
so that every module can import state types without circular deps.
"""

from __future__ import annotations

from typing import Annotated, Any, TypedDict


# ---------------------------------------------------------------------------
# Reducer helpers
# ---------------------------------------------------------------------------

def _merge_lists(left: list, right: list) -> list:
    """Append-merge reducer for LangGraph annotated fields."""
    return left + right


# ---------------------------------------------------------------------------
# Agent State
# ---------------------------------------------------------------------------

class AgentState(TypedDict, total=False):
    """Shared state for the multi-agent pentest graph."""

    # Core messaging
    messages: Annotated[list[dict[str, Any]], _merge_lists]

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

    # Next agent to route to (set by supervisor / routing logic)
    next_agent: str

    # --- Extended state fields (Phase A additions) -------------------------

    # Performance tracking
    phase_durations: dict[str, float]       # phase -> cumulative seconds
    tool_execution_log: list[dict[str, Any]]  # [{tool, success, duration_ms, ts}]
    approval_history: list[dict[str, Any]]    # [{request_id, action, resolved_by, ts}]

    # Internal bookkeeping
    _iteration: int
