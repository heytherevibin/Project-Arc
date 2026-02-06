"""
Goal Stack

Hierarchical goal management for the agent system.  Goals are
organized in three tiers: strategic → tactical → operational.

Strategic goals come from the mission objective.
Tactical goals are derived by the supervisor.
Operational goals are created by specialist agents for specific tasks.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from core.logging import get_logger

logger = get_logger(__name__)


@dataclass
class GoalNode:
    """A single goal in the hierarchy."""
    goal_id: str
    description: str
    level: str                      # strategic | tactical | operational
    status: str = "active"          # active | completed | failed | blocked | cancelled
    parent_id: str | None = None
    agent_id: str = ""              # Which agent owns this goal
    priority: int = 0               # Higher = more important
    metadata: dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    completed_at: str | None = None

    @property
    def is_terminal(self) -> bool:
        return self.status in ("completed", "failed", "cancelled")


class GoalStack:
    """
    Manages a hierarchical goal tree with dependency tracking.

    Goals cascade: completing all operational goals may complete
    their parent tactical goal, which may complete the strategic goal.
    """

    def __init__(self) -> None:
        self._goals: dict[str, GoalNode] = {}

    def push(
        self,
        description: str,
        level: str = "operational",
        parent_id: str | None = None,
        agent_id: str = "",
        priority: int = 0,
        metadata: dict[str, Any] | None = None,
    ) -> str:
        """Create and push a new goal. Returns goal_id."""
        goal_id = f"goal-{uuid.uuid4().hex[:8]}"
        goal = GoalNode(
            goal_id=goal_id,
            description=description,
            level=level,
            parent_id=parent_id,
            agent_id=agent_id,
            priority=priority,
            metadata=metadata or {},
        )
        self._goals[goal_id] = goal
        logger.debug("Goal pushed", goal_id=goal_id, level=level, desc=description[:50])
        return goal_id

    def complete(self, goal_id: str) -> bool:
        """Mark a goal as completed. Auto-cascades to parent if applicable."""
        goal = self._goals.get(goal_id)
        if not goal or goal.is_terminal:
            return False

        goal.status = "completed"
        goal.completed_at = datetime.now(timezone.utc).isoformat()

        # Check if parent should auto-complete
        if goal.parent_id:
            self._check_parent_completion(goal.parent_id)

        return True

    def fail(self, goal_id: str, reason: str = "") -> bool:
        """Mark a goal as failed."""
        goal = self._goals.get(goal_id)
        if not goal or goal.is_terminal:
            return False

        goal.status = "failed"
        goal.completed_at = datetime.now(timezone.utc).isoformat()
        goal.metadata["failure_reason"] = reason
        return True

    def block(self, goal_id: str, reason: str = "") -> bool:
        """Mark a goal as blocked (waiting for something)."""
        goal = self._goals.get(goal_id)
        if not goal or goal.is_terminal:
            return False

        goal.status = "blocked"
        goal.metadata["blocked_reason"] = reason
        return True

    def get_active(self, level: str | None = None, agent_id: str | None = None) -> list[GoalNode]:
        """Get active goals, optionally filtered by level or agent."""
        goals = [g for g in self._goals.values() if g.status == "active"]
        if level:
            goals = [g for g in goals if g.level == level]
        if agent_id:
            goals = [g for g in goals if g.agent_id == agent_id]
        goals.sort(key=lambda g: g.priority, reverse=True)
        return goals

    def get_children(self, parent_id: str) -> list[GoalNode]:
        """Get child goals of a parent."""
        return [g for g in self._goals.values() if g.parent_id == parent_id]

    def get_hierarchy(self) -> dict[str, list[dict[str, Any]]]:
        """Get the full goal hierarchy organized by level."""
        result: dict[str, list[dict[str, Any]]] = {
            "strategic": [],
            "tactical": [],
            "operational": [],
        }
        for goal in self._goals.values():
            level = goal.level if goal.level in result else "operational"
            result[level].append({
                "goal_id": goal.goal_id,
                "description": goal.description,
                "status": goal.status,
                "parent_id": goal.parent_id,
                "agent_id": goal.agent_id,
                "priority": goal.priority,
            })
        return result

    def get_progress(self) -> dict[str, Any]:
        """Get overall mission progress based on goal completion."""
        total = len(self._goals)
        if total == 0:
            return {"total": 0, "completed": 0, "active": 0, "failed": 0, "pct": 0.0}

        completed = sum(1 for g in self._goals.values() if g.status == "completed")
        active = sum(1 for g in self._goals.values() if g.status == "active")
        failed = sum(1 for g in self._goals.values() if g.status == "failed")

        return {
            "total": total,
            "completed": completed,
            "active": active,
            "failed": failed,
            "pct": round(completed / total * 100, 1),
        }

    def _check_parent_completion(self, parent_id: str) -> None:
        """Auto-complete parent if all children are completed."""
        parent = self._goals.get(parent_id)
        if not parent or parent.is_terminal:
            return

        children = self.get_children(parent_id)
        if not children:
            return

        all_done = all(c.status == "completed" for c in children)
        if all_done:
            parent.status = "completed"
            parent.completed_at = datetime.now(timezone.utc).isoformat()
            logger.info("Goal auto-completed (all children done)", goal_id=parent_id)

            # Cascade further up
            if parent.parent_id:
                self._check_parent_completion(parent.parent_id)
