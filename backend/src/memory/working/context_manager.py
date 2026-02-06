"""
Working Memory - Context Manager

Manages the active context window for the agent, including goal stacks,
recent events, and attention filters. Prevents context overflow by
prioritizing the most relevant information.
"""

from __future__ import annotations

import json
from collections import deque
from dataclasses import dataclass, field
from typing import Any

from core.logging import get_logger

logger = get_logger(__name__)


@dataclass
class Goal:
    """A hierarchical goal."""
    goal_id: str
    description: str
    level: str  # "strategic" | "tactical" | "operational"
    status: str = "active"  # "active" | "completed" | "failed" | "blocked"
    parent_id: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


class WorkingMemory:
    """
    Active context window with attention management.

    Maintains:
    - Goal stack (hierarchical: strategic → tactical → operational)
    - Recent events ring buffer
    - Key findings (high-importance items)
    - Current focus (what the agent is working on)
    """

    def __init__(self, max_tokens: int = 128_000) -> None:
        self.max_tokens = max_tokens

        # Goal management
        self._goals: dict[str, Goal] = {}

        # Recent events (ring buffer, most recent last)
        self._recent_events: deque[dict[str, Any]] = deque(maxlen=100)

        # Key findings (high importance, never auto-evicted)
        self._key_findings: list[dict[str, Any]] = []

        # Current focus
        self._current_focus: str | None = None
        self._current_phase: str = "initialization"

        # Attention filter: entity types to prioritize
        self._attention_filter: set[str] = set()

    # =========================================================================
    # Goal Management
    # =========================================================================

    def push_goal(self, goal: Goal) -> None:
        """Add a goal to the stack."""
        self._goals[goal.goal_id] = goal
        logger.debug("Goal pushed", goal_id=goal.goal_id, level=goal.level)

    def complete_goal(self, goal_id: str) -> None:
        """Mark a goal as completed."""
        if goal_id in self._goals:
            self._goals[goal_id].status = "completed"

    def fail_goal(self, goal_id: str) -> None:
        """Mark a goal as failed."""
        if goal_id in self._goals:
            self._goals[goal_id].status = "failed"

    def get_active_goals(self, level: str | None = None) -> list[Goal]:
        """Get all active goals, optionally filtered by level."""
        goals = [g for g in self._goals.values() if g.status == "active"]
        if level:
            goals = [g for g in goals if g.level == level]
        return goals

    def get_goal_hierarchy(self) -> dict[str, list[Goal]]:
        """Get goals organized by level."""
        hierarchy: dict[str, list[Goal]] = {
            "strategic": [],
            "tactical": [],
            "operational": [],
        }
        for goal in self._goals.values():
            if goal.level in hierarchy:
                hierarchy[goal.level].append(goal)
        return hierarchy

    # =========================================================================
    # Event Tracking
    # =========================================================================

    def add_event(self, event_id: str, observation: Any) -> None:
        """Add an event to the recent events buffer."""
        self._recent_events.append({
            "event_id": event_id,
            "tool": getattr(observation, "tool", "unknown"),
            "success": getattr(observation, "success", False),
            "timestamp": getattr(observation, "timestamp", ""),
            "summary": self._summarize(observation),
        })

    def get_recent_events(self, limit: int = 20) -> list[dict[str, Any]]:
        """Get the most recent events."""
        events = list(self._recent_events)
        return events[-limit:]

    # =========================================================================
    # Key Findings
    # =========================================================================

    def add_key_finding(self, finding: dict[str, Any]) -> None:
        """Add a high-importance finding (never auto-evicted)."""
        self._key_findings.append(finding)

    def get_key_findings(self) -> list[dict[str, Any]]:
        """Get all key findings."""
        return list(self._key_findings)

    # =========================================================================
    # Focus & Phase
    # =========================================================================

    def set_focus(self, focus: str) -> None:
        """Set the current focus of attention."""
        self._current_focus = focus

    def set_phase(self, phase: str) -> None:
        """Set the current operation phase."""
        self._current_phase = phase

    @property
    def current_focus(self) -> str | None:
        return self._current_focus

    @property
    def current_phase(self) -> str:
        return self._current_phase

    # =========================================================================
    # Context Snapshot
    # =========================================================================

    def snapshot(self) -> dict[str, Any]:
        """
        Generate a context snapshot for the agent's prompt.

        Returns a dictionary suitable for injecting into the agent's
        system prompt or context window.
        """
        return {
            "phase": self._current_phase,
            "focus": self._current_focus,
            "goals": {
                level: [
                    {"id": g.goal_id, "desc": g.description, "status": g.status}
                    for g in goals
                ]
                for level, goals in self.get_goal_hierarchy().items()
            },
            "recent_events": self.get_recent_events(10),
            "key_findings_count": len(self._key_findings),
            "key_findings": self._key_findings[:5],  # Top 5
        }

    # =========================================================================
    # Internal
    # =========================================================================

    @staticmethod
    def _summarize(observation: Any) -> str:
        """Generate a brief summary of an observation."""
        tool = getattr(observation, "tool", "unknown")
        success = getattr(observation, "success", False)
        status = "OK" if success else "FAIL"
        return f"[{status}] {tool}"
