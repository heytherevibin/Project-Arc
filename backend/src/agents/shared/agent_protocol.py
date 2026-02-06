"""
Agent Protocol

Defines the mission lifecycle and inter-agent communication protocol.
Manages mission creation, state persistence, and workflow execution.
"""

from __future__ import annotations

import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from core.logging import get_logger

logger = get_logger(__name__)


class MissionStatus(str, Enum):
    """Mission lifecycle states."""
    CREATED = "created"
    PLANNING = "planning"
    RUNNING = "running"
    PAUSED = "paused"           # Waiting for approval
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class Mission:
    """Represents a penetration testing mission."""
    mission_id: str
    project_id: str
    name: str
    objective: str
    target: str
    status: MissionStatus = MissionStatus.CREATED
    current_phase: str = "recon"
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    started_at: str | None = None
    completed_at: str | None = None
    created_by: str = ""
    config: dict[str, Any] = field(default_factory=dict)

    # Runtime state
    discovered_hosts: list[str] = field(default_factory=list)
    discovered_vulns: list[dict[str, Any]] = field(default_factory=list)
    active_sessions: list[dict[str, Any]] = field(default_factory=list)
    compromised_hosts: list[str] = field(default_factory=list)
    harvested_creds: list[dict[str, Any]] = field(default_factory=list)
    phase_history: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a dictionary."""
        data = asdict(self)
        data["status"] = self.status.value
        return data


@dataclass
class MissionEvent:
    """An event in the mission timeline."""
    event_id: str
    mission_id: str
    event_type: str          # "phase_change", "tool_execution", "approval", "finding", "error"
    timestamp: str
    agent_id: str = ""
    phase: str = ""
    summary: str = ""
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class MissionManager:
    """
    In-memory mission manager.

    Tracks active missions and their timeline events.
    A production deployment would back this with PostgreSQL.
    """

    def __init__(self) -> None:
        self._missions: dict[str, Mission] = {}
        self._events: dict[str, list[MissionEvent]] = {}  # mission_id → events

    def create_mission(
        self,
        project_id: str,
        name: str,
        objective: str,
        target: str,
        created_by: str = "",
        config: dict[str, Any] | None = None,
    ) -> Mission:
        """Create a new mission."""
        mission = Mission(
            mission_id=f"mission-{uuid.uuid4().hex[:12]}",
            project_id=project_id,
            name=name,
            objective=objective,
            target=target,
            created_by=created_by,
            config=config or {},
        )
        self._missions[mission.mission_id] = mission
        self._events[mission.mission_id] = []

        self._add_event(mission.mission_id, "mission_created", summary=f"Mission '{name}' created")
        logger.info("Mission created", mission_id=mission.mission_id, target=target)
        return mission

    def get_mission(self, mission_id: str) -> Mission | None:
        return self._missions.get(mission_id)

    def list_missions(
        self,
        project_id: str | None = None,
        status: MissionStatus | None = None,
        limit: int = 50,
    ) -> list[Mission]:
        """List missions with optional filters."""
        missions = list(self._missions.values())
        if project_id:
            missions = [m for m in missions if m.project_id == project_id]
        if status:
            missions = [m for m in missions if m.status == status]
        missions.sort(key=lambda m: m.created_at, reverse=True)
        return missions[:limit]

    def update_status(self, mission_id: str, status: MissionStatus) -> bool:
        """Update mission status."""
        mission = self._missions.get(mission_id)
        if not mission:
            return False

        old_status = mission.status
        mission.status = status
        mission.updated_at = datetime.now(timezone.utc).isoformat()

        if status == MissionStatus.RUNNING and not mission.started_at:
            mission.started_at = datetime.now(timezone.utc).isoformat()
        elif status in (MissionStatus.COMPLETED, MissionStatus.FAILED, MissionStatus.CANCELLED):
            mission.completed_at = datetime.now(timezone.utc).isoformat()

        self._add_event(
            mission_id,
            "status_change",
            summary=f"Status: {old_status.value} → {status.value}",
            details={"old_status": old_status.value, "new_status": status.value},
        )
        return True

    def update_phase(self, mission_id: str, phase: str) -> bool:
        """Update the current phase of a mission."""
        mission = self._missions.get(mission_id)
        if not mission:
            return False

        old_phase = mission.current_phase
        mission.current_phase = phase
        mission.updated_at = datetime.now(timezone.utc).isoformat()
        mission.phase_history.append({
            "from": old_phase,
            "to": phase,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

        self._add_event(
            mission_id,
            "phase_change",
            phase=phase,
            summary=f"Phase: {old_phase} → {phase}",
        )
        return True

    def sync_state(self, mission_id: str, state: dict[str, Any]) -> bool:
        """Sync the LangGraph state back to the mission."""
        mission = self._missions.get(mission_id)
        if not mission:
            return False

        mission.current_phase = state.get("current_phase", mission.current_phase)
        mission.discovered_hosts = state.get("discovered_hosts", mission.discovered_hosts)
        mission.discovered_vulns = state.get("discovered_vulns", mission.discovered_vulns)
        mission.active_sessions = state.get("active_sessions", mission.active_sessions)
        mission.compromised_hosts = state.get("compromised_hosts", mission.compromised_hosts)
        mission.harvested_creds = state.get("harvested_creds", mission.harvested_creds)
        mission.phase_history = state.get("phase_history", mission.phase_history)
        mission.updated_at = datetime.now(timezone.utc).isoformat()
        return True

    def get_timeline(self, mission_id: str, limit: int = 100) -> list[MissionEvent]:
        """Get the event timeline for a mission."""
        events = self._events.get(mission_id, [])
        return events[-limit:]

    def add_tool_event(
        self,
        mission_id: str,
        agent_id: str,
        tool_name: str,
        success: bool,
        phase: str = "",
        details: dict[str, Any] | None = None,
    ) -> None:
        """Record a tool execution event."""
        status_str = "success" if success else "failed"
        self._add_event(
            mission_id,
            "tool_execution",
            agent_id=agent_id,
            phase=phase,
            summary=f"Tool '{tool_name}' {status_str}",
            details=details or {},
        )

    def delete_mission(self, mission_id: str) -> bool:
        """Delete a mission and its events."""
        if mission_id not in self._missions:
            return False
        del self._missions[mission_id]
        self._events.pop(mission_id, None)
        return True

    def _add_event(
        self,
        mission_id: str,
        event_type: str,
        agent_id: str = "",
        phase: str = "",
        summary: str = "",
        details: dict[str, Any] | None = None,
    ) -> MissionEvent:
        """Create and store a mission event."""
        event = MissionEvent(
            event_id=f"evt-{uuid.uuid4().hex[:12]}",
            mission_id=mission_id,
            event_type=event_type,
            timestamp=datetime.now(timezone.utc).isoformat(),
            agent_id=agent_id,
            phase=phase,
            summary=summary,
            details=details or {},
        )
        if mission_id not in self._events:
            self._events[mission_id] = []
        self._events[mission_id].append(event)
        return event


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------

_manager: MissionManager | None = None


def get_mission_manager() -> MissionManager:
    """Get or create the global mission manager."""
    global _manager
    if _manager is None:
        _manager = MissionManager()
    return _manager
