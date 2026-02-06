"""
Task Router

Dynamic task-routing engine for the Supervisor.  Uses weighted
heuristics (phase progress, pending approvals, discovered data,
tool success rates) to decide which specialist agent to invoke next.
"""

from __future__ import annotations

from typing import Any

from agents.shared.base_agent import Phase
from core.logging import get_logger

logger = get_logger(__name__)


class TaskRouter:
    """
    Routes the next specialist agent based on weighted state heuristics.

    Replaces the simple ``_should_advance_phase`` logic with a richer
    scoring system that considers multiple factors simultaneously.
    """

    PHASE_ORDER: list[str] = [
        Phase.RECON,
        Phase.VULN_ANALYSIS,
        Phase.EXPLOITATION,
        Phase.POST_EXPLOITATION,
        Phase.LATERAL_MOVEMENT,
        Phase.PERSISTENCE,
        Phase.EXFILTRATION,
        Phase.REPORTING,
    ]

    PHASE_AGENT_MAP: dict[str, str] = {
        Phase.RECON: "recon",
        Phase.VULN_ANALYSIS: "vuln_analysis",
        Phase.EXPLOITATION: "exploit",
        Phase.POST_EXPLOITATION: "post_exploit",
        Phase.LATERAL_MOVEMENT: "lateral",
        Phase.PERSISTENCE: "persist",
        Phase.EXFILTRATION: "exfil",
        Phase.REPORTING: "report",
    }

    APPROVAL_PHASES: set[str] = {
        Phase.EXPLOITATION,
        Phase.POST_EXPLOITATION,
        Phase.LATERAL_MOVEMENT,
    }

    # Weights for the advancement scoring
    _W_DATA = 0.40          # weight for data-completeness signals
    _W_TOOL_SUCCESS = 0.25  # weight for tool success rate
    _W_ITERATION = 0.20     # weight for iteration count in current phase
    _W_GOAL = 0.15          # weight for goal completion

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def route(self, state: dict[str, Any]) -> dict[str, Any]:
        """
        Evaluate the state and decide: stay in current phase, advance,
        or request approval.

        Returns a *mutated* copy of the state dict with updated
        ``current_phase``, ``next_agent``, and possibly new entries in
        ``pending_approvals``.
        """
        current_phase = state.get("current_phase", Phase.RECON)

        # 1. Check pending approvals — block until resolved
        pending = [
            a for a in state.get("pending_approvals", [])
            if a.get("status") == "pending"
        ]
        if pending:
            state["next_agent"] = "approval_wait"
            return state

        # 2. Score whether to advance
        advance_score = self._score_advancement(state, current_phase)
        next_phase = self._next_phase(current_phase)

        if advance_score >= 0.6 and next_phase is not None:
            if next_phase in self.APPROVAL_PHASES:
                state["pending_approvals"] = state.get("pending_approvals", []) + [{
                    "type": "phase_transition",
                    "from_phase": current_phase,
                    "to_phase": next_phase,
                    "description": f"Advance to {next_phase} phase (score={advance_score:.2f})",
                    "status": "pending",
                }]
                state["next_agent"] = "approval_wait"
                logger.info(
                    "Approval required",
                    from_phase=current_phase,
                    to_phase=next_phase,
                    score=advance_score,
                )
            else:
                self._transition(state, current_phase, next_phase)
        else:
            # Stay in current phase
            state["next_agent"] = self.PHASE_AGENT_MAP.get(current_phase, "recon")

        return state

    # ------------------------------------------------------------------
    # Scoring
    # ------------------------------------------------------------------

    def _score_advancement(self, state: dict[str, Any], phase: str) -> float:
        """
        Composite score in [0, 1] indicating readiness to advance.
        """
        data_score = self._data_readiness(state, phase)
        tool_score = self._tool_success_rate(state)
        iter_score = self._iteration_pressure(state)
        goal_score = self._goal_completion(state)

        score = (
            self._W_DATA * data_score
            + self._W_TOOL_SUCCESS * tool_score
            + self._W_ITERATION * iter_score
            + self._W_GOAL * goal_score
        )
        return min(1.0, max(0.0, score))

    def _data_readiness(self, state: dict[str, Any], phase: str) -> float:
        """How complete is the data for the current phase?"""
        if phase == Phase.RECON:
            hosts = len(state.get("discovered_hosts", []))
            return min(1.0, hosts / 5.0)   # 5+ hosts → ready

        if phase == Phase.VULN_ANALYSIS:
            vulns = len(state.get("discovered_vulns", []))
            return min(1.0, vulns / 3.0)

        if phase == Phase.EXPLOITATION:
            sessions = len(state.get("active_sessions", []))
            return min(1.0, sessions / 1.0)

        if phase == Phase.POST_EXPLOITATION:
            creds = len(state.get("harvested_creds", []))
            return min(1.0, creds / 2.0)

        if phase == Phase.LATERAL_MOVEMENT:
            compromised = len(state.get("compromised_hosts", []))
            return min(1.0, compromised / 2.0)

        if phase in (Phase.PERSISTENCE, Phase.EXFILTRATION):
            return 1.0  # always ready to advance past these

        return 0.0

    @staticmethod
    def _tool_success_rate(state: dict[str, Any]) -> float:
        """Average tool success rate across recent executions."""
        log = state.get("tool_execution_log", [])
        if not log:
            return 0.5  # neutral
        recent = log[-20:]
        successes = sum(1 for e in recent if e.get("success"))
        return successes / len(recent)

    @staticmethod
    def _iteration_pressure(state: dict[str, Any]) -> float:
        """Higher score the longer we stay in a phase (pressure to move on)."""
        iteration = state.get("_iteration", 0)
        return min(1.0, iteration / 30.0)

    @staticmethod
    def _goal_completion(state: dict[str, Any]) -> float:
        """Fraction of tactical goals completed."""
        goals = state.get("tactical_goals", [])
        if not goals:
            return 0.5
        completed = sum(1 for g in goals if g.get("status") == "completed")
        return completed / len(goals)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _next_phase(self, current: str) -> str | None:
        try:
            idx = self.PHASE_ORDER.index(current)
        except ValueError:
            return None
        if idx + 1 < len(self.PHASE_ORDER):
            return self.PHASE_ORDER[idx + 1]
        return None

    @staticmethod
    def _transition(
        state: dict[str, Any],
        from_phase: str,
        to_phase: str,
    ) -> None:
        from datetime import datetime, timezone

        state["current_phase"] = to_phase
        state["phase_history"] = state.get("phase_history", []) + [{
            "from": from_phase,
            "to": to_phase,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }]
        # Reset iteration counter for new phase
        state["_iteration"] = 0

        phase_agent_map = TaskRouter.PHASE_AGENT_MAP
        state["next_agent"] = phase_agent_map.get(to_phase, "recon")

        logger.info("Phase transition", from_phase=from_phase, to_phase=to_phase)
