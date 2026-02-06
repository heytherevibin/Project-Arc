"""
Base Agent

Abstract base class for all Arc specialist agents. Provides common
infrastructure for tool execution, memory access, phase tracking,
and inter-agent communication.
"""

from __future__ import annotations

import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, AsyncIterator

from core.logging import get_logger
from memory.cognitive import CognitiveMemory, Context, Observation

logger = get_logger(__name__)


@dataclass
class AgentMessage:
    """Inter-agent communication message."""
    message_id: str
    from_agent: str
    to_agent: str
    content: str
    message_type: str = "info"  # "info" | "request" | "result" | "alert"
    data: dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


@dataclass
class ToolCall:
    """Represents a tool invocation."""
    tool_name: str
    args: dict[str, Any]
    requires_approval: bool = False
    risk_level: str = "low"  # "low" | "medium" | "high" | "critical"


@dataclass
class ToolResponse:
    """Result from a tool invocation."""
    tool_name: str
    success: bool
    data: Any = None
    error: str | None = None
    duration_ms: float = 0.0


class Phase:
    """Attack phases."""
    RECON = "recon"
    VULN_ANALYSIS = "vuln_analysis"
    EXPLOITATION = "exploitation"
    POST_EXPLOITATION = "post_exploitation"
    LATERAL_MOVEMENT = "lateral_movement"
    PERSISTENCE = "persistence"
    EXFILTRATION = "exfiltration"
    REPORTING = "reporting"


class BaseAgent(ABC):
    """
    Abstract base class for all Arc agents.

    Provides:
    - Tool execution with memory recording
    - Phase-aware operation
    - Inter-agent messaging
    - Human approval gate support
    """

    # Subclasses must set these
    agent_id: str = "base"
    agent_name: str = "Base Agent"
    supported_phases: list[str] = []
    available_tools: list[str] = []

    def __init__(self, memory: CognitiveMemory | None = None) -> None:
        self.memory = memory
        self._session_id = f"session-{uuid.uuid4().hex[:12]}"
        self._outbox: list[AgentMessage] = []

    @abstractmethod
    async def plan(self, state: dict[str, Any]) -> list[ToolCall]:
        """
        Given the current state, decide which tools to call.

        Returns a list of ToolCall objects representing the next actions.
        """
        ...

    @abstractmethod
    async def analyze(self, state: dict[str, Any], results: list[ToolResponse]) -> dict[str, Any]:
        """
        Analyze tool results and update the state.

        Returns updated state dictionary.
        """
        ...

    async def execute_tool(self, tool_call: ToolCall) -> ToolResponse:
        """
        Execute a tool and record the result in memory.

        Override in subclasses to connect to actual MCP tool servers.
        """
        start = datetime.now(timezone.utc)

        try:
            # Subclasses implement actual tool execution
            result = await self._run_tool(tool_call)

            duration = (datetime.now(timezone.utc) - start).total_seconds() * 1000
            response = ToolResponse(
                tool_name=tool_call.tool_name,
                success=True,
                data=result,
                duration_ms=duration,
            )

        except Exception as e:
            duration = (datetime.now(timezone.utc) - start).total_seconds() * 1000
            response = ToolResponse(
                tool_name=tool_call.tool_name,
                success=False,
                error=str(e)[:500],
                duration_ms=duration,
            )
            logger.warning(
                "Tool execution failed",
                agent=self.agent_id,
                tool=tool_call.tool_name,
                error=str(e),
            )

        # Record in memory
        if self.memory:
            await self.memory.remember(Observation(
                timestamp=datetime.now(timezone.utc).isoformat(),
                agent_id=self.agent_id,
                tool=tool_call.tool_name,
                args=tool_call.args,
                output=response.data if response.success else response.error,
                success=response.success,
            ))

        return response

    async def _run_tool(self, tool_call: ToolCall) -> Any:
        """
        Execute a tool via the MCP tool executor.

        Falls back to a no-op if the executor is unavailable (e.g. in
        unit tests or when MCP servers are not running).
        """
        try:
            from agents.shared.tool_executor import get_tool_executor, ToolExecutionError
            executor = get_tool_executor()
            return await executor.execute(tool_call)
        except Exception as e:
            logger.warning(
                "MCP tool execution unavailable, returning empty result",
                agent=self.agent_id,
                tool=tool_call.tool_name,
                error=str(e)[:200],
            )
            return {}

    def send_message(self, to_agent: str, content: str, **data: Any) -> AgentMessage:
        """Send an inter-agent message."""
        msg = AgentMessage(
            message_id=f"msg-{uuid.uuid4().hex[:12]}",
            from_agent=self.agent_id,
            to_agent=to_agent,
            content=content,
            data=data,
        )
        self._outbox.append(msg)
        return msg

    def drain_outbox(self) -> list[AgentMessage]:
        """Get and clear pending messages."""
        messages = list(self._outbox)
        self._outbox.clear()
        return messages

    async def get_context(self, project_id: str, query: str = "") -> Context:
        """Build a memory context for the current state."""
        return Context(
            session_id=self._session_id,
            project_id=project_id,
            current_phase=self.supported_phases[0] if self.supported_phases else "unknown",
            available_tools=self.available_tools,
        )
