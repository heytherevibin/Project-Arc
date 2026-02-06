"""
Session Memory

Manages per-session context including conversation history,
active tool state, and session-scoped variables.  Enables
continuity across agent interactions within a single mission run.
"""

from __future__ import annotations

import uuid
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from core.logging import get_logger

logger = get_logger(__name__)


@dataclass
class SessionMessage:
    """A single message in the session conversation."""
    role: str              # "system", "user", "assistant", "tool"
    content: str
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class SessionState:
    """Snapshot of a session's state at a point in time."""
    session_id: str
    mission_id: str
    phase: str
    variables: dict[str, Any]
    message_count: int
    created_at: str
    last_activity: str


class SessionMemory:
    """
    In-memory session management for agent conversations.

    Maintains per-session:
    - Conversation history (ring buffer)
    - Session variables (key-value pairs)
    - Tool execution context
    """

    def __init__(self, max_messages: int = 200) -> None:
        self._max_messages = max_messages
        self._sessions: dict[str, _Session] = {}

    def create_session(
        self,
        mission_id: str = "",
        initial_phase: str = "recon",
    ) -> str:
        """Create a new session and return its ID."""
        session_id = f"sess-{uuid.uuid4().hex[:12]}"
        self._sessions[session_id] = _Session(
            session_id=session_id,
            mission_id=mission_id,
            phase=initial_phase,
            max_messages=self._max_messages,
        )
        logger.debug("Session created", session_id=session_id)
        return session_id

    def get_session(self, session_id: str) -> _Session | None:
        """Get a session by ID."""
        return self._sessions.get(session_id)

    def add_message(
        self,
        session_id: str,
        role: str,
        content: str,
        metadata: dict[str, Any] | None = None,
    ) -> bool:
        """Add a message to the session conversation."""
        session = self._sessions.get(session_id)
        if not session:
            return False
        session.add_message(role, content, metadata)
        return True

    def get_messages(
        self,
        session_id: str,
        limit: int | None = None,
    ) -> list[SessionMessage]:
        """Get recent messages from a session."""
        session = self._sessions.get(session_id)
        if not session:
            return []
        return session.get_messages(limit)

    def set_variable(self, session_id: str, key: str, value: Any) -> bool:
        """Set a session-scoped variable."""
        session = self._sessions.get(session_id)
        if not session:
            return False
        session.variables[key] = value
        return True

    def get_variable(self, session_id: str, key: str, default: Any = None) -> Any:
        """Get a session-scoped variable."""
        session = self._sessions.get(session_id)
        if not session:
            return default
        return session.variables.get(key, default)

    def get_state(self, session_id: str) -> SessionState | None:
        """Get the current state of a session."""
        session = self._sessions.get(session_id)
        if not session:
            return None
        return session.snapshot()

    def close_session(self, session_id: str) -> bool:
        """Close and remove a session."""
        if session_id in self._sessions:
            del self._sessions[session_id]
            logger.debug("Session closed", session_id=session_id)
            return True
        return False

    def list_sessions(self, mission_id: str | None = None) -> list[SessionState]:
        """List active sessions, optionally filtered by mission."""
        sessions = list(self._sessions.values())
        if mission_id:
            sessions = [s for s in sessions if s.mission_id == mission_id]
        return [s.snapshot() for s in sessions]


class _Session:
    """Internal session representation."""

    def __init__(
        self,
        session_id: str,
        mission_id: str,
        phase: str,
        max_messages: int,
    ) -> None:
        self.session_id = session_id
        self.mission_id = mission_id
        self.phase = phase
        self.variables: dict[str, Any] = {}
        self.created_at = datetime.now(timezone.utc).isoformat()
        self.last_activity = self.created_at
        self._messages: deque[SessionMessage] = deque(maxlen=max_messages)

    def add_message(
        self,
        role: str,
        content: str,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        msg = SessionMessage(role=role, content=content, metadata=metadata or {})
        self._messages.append(msg)
        self.last_activity = msg.timestamp

    def get_messages(self, limit: int | None = None) -> list[SessionMessage]:
        msgs = list(self._messages)
        if limit:
            return msgs[-limit:]
        return msgs

    def snapshot(self) -> SessionState:
        return SessionState(
            session_id=self.session_id,
            mission_id=self.mission_id,
            phase=self.phase,
            variables=dict(self.variables),
            message_count=len(self._messages),
            created_at=self.created_at,
            last_activity=self.last_activity,
        )
