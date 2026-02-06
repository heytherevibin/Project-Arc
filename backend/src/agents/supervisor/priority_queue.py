"""
Priority Task Queue

Manages a priority-ordered queue of tasks for the supervisor to
dispatch to specialist agents.  Tasks carry priority, target agent,
deadline, and dependency information.
"""

from __future__ import annotations

import heapq
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import IntEnum
from typing import Any

from core.logging import get_logger

logger = get_logger(__name__)


class Priority(IntEnum):
    """Task priority (lower value = higher priority for heapq)."""
    CRITICAL = 0
    HIGH = 1
    NORMAL = 2
    LOW = 3


@dataclass(order=True)
class Task:
    """
    A queued task for a specialist agent.

    ``sort_index`` is used by heapq; it combines priority and creation
    time so that equal-priority tasks are FIFO-ordered.
    """
    sort_index: tuple[int, str] = field(init=False, repr=False)

    task_id: str = field(default_factory=lambda: f"task-{uuid.uuid4().hex[:8]}")
    agent_target: str = ""
    description: str = ""
    priority: Priority = Priority.NORMAL
    phase: str = ""
    args: dict[str, Any] = field(default_factory=dict)
    dependencies: list[str] = field(default_factory=list)  # task_ids that must complete first
    deadline: str | None = None  # ISO timestamp
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    status: str = "pending"  # pending | running | completed | failed | cancelled

    def __post_init__(self) -> None:
        self.sort_index = (int(self.priority), self.created_at)


class PriorityTaskQueue:
    """
    Priority queue for supervisor task scheduling.

    Features:
    - Heap-ordered by (priority, creation_time)
    - Dependency tracking: tasks with unmet deps are held back
    - Deadline awareness: overdue tasks are promoted to CRITICAL
    - Idempotent push (duplicate task_ids ignored)
    """

    def __init__(self) -> None:
        self._heap: list[Task] = []
        self._tasks: dict[str, Task] = {}  # task_id → Task
        self._completed: set[str] = set()

    # ------------------------------------------------------------------
    # Core API
    # ------------------------------------------------------------------

    def push(self, task: Task) -> None:
        """Add a task to the queue. Duplicates (by task_id) are ignored."""
        if task.task_id in self._tasks:
            return
        self._tasks[task.task_id] = task
        heapq.heappush(self._heap, task)
        logger.debug("Task queued", task_id=task.task_id, priority=task.priority.name,
                      agent=task.agent_target)

    def pop(self) -> Task | None:
        """
        Pop the highest-priority task whose dependencies are met.

        Returns ``None`` if the queue is empty or all remaining tasks
        have unmet dependencies.
        """
        self._promote_overdue()

        # Collect tasks with unmet deps so we can re-insert them
        deferred: list[Task] = []
        result: Task | None = None

        while self._heap:
            task = heapq.heappop(self._heap)

            if task.status != "pending":
                continue  # skip non-pending

            if self._deps_met(task):
                task.status = "running"
                result = task
                break
            else:
                deferred.append(task)

        # Re-insert deferred tasks
        for t in deferred:
            heapq.heappush(self._heap, t)

        return result

    def peek(self) -> Task | None:
        """Peek at the highest-priority ready task without removing it."""
        self._promote_overdue()
        for task in sorted(self._heap):
            if task.status == "pending" and self._deps_met(task):
                return task
        return None

    def complete(self, task_id: str) -> None:
        """Mark a task as completed and record it for dependency resolution."""
        task = self._tasks.get(task_id)
        if task:
            task.status = "completed"
            self._completed.add(task_id)
            logger.debug("Task completed", task_id=task_id)

    def fail(self, task_id: str) -> None:
        """Mark a task as failed."""
        task = self._tasks.get(task_id)
        if task:
            task.status = "failed"
            logger.debug("Task failed", task_id=task_id)

    def cancel(self, task_id: str) -> None:
        """Cancel a task."""
        task = self._tasks.get(task_id)
        if task:
            task.status = "cancelled"

    # ------------------------------------------------------------------
    # Query helpers
    # ------------------------------------------------------------------

    @property
    def size(self) -> int:
        return sum(1 for t in self._tasks.values() if t.status == "pending")

    @property
    def pending(self) -> list[Task]:
        return sorted(
            [t for t in self._tasks.values() if t.status == "pending"],
            key=lambda t: t.sort_index,
        )

    @property
    def running(self) -> list[Task]:
        return [t for t in self._tasks.values() if t.status == "running"]

    def get_task(self, task_id: str) -> Task | None:
        return self._tasks.get(task_id)

    def get_tasks_for_agent(self, agent: str) -> list[Task]:
        return [
            t for t in self._tasks.values()
            if t.agent_target == agent and t.status in ("pending", "running")
        ]

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _deps_met(self, task: Task) -> bool:
        """Check if all dependencies have been completed."""
        if not task.dependencies:
            return True
        return all(dep_id in self._completed for dep_id in task.dependencies)

    def _promote_overdue(self) -> None:
        """Promote overdue tasks to CRITICAL priority."""
        now = datetime.now(timezone.utc).isoformat()
        rebuilt = False
        for task in self._tasks.values():
            if (
                task.status == "pending"
                and task.deadline
                and task.deadline < now
                and task.priority != Priority.CRITICAL
            ):
                task.priority = Priority.CRITICAL
                task.sort_index = (int(Priority.CRITICAL), task.created_at)
                rebuilt = True
                logger.info("Task promoted to CRITICAL (overdue)", task_id=task.task_id)

        if rebuilt:
            heapq.heapify(self._heap)
