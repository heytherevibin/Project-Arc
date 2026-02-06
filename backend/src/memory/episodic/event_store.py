"""
Episodic Memory - Event Store

Records all agent actions and tool executions as timestamped events.
Supports temporal retrieval (e.g., "what happened in the last 10 minutes?")
and session-scoped queries.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from core.logging import get_logger
from graph.client import Neo4jClient

logger = get_logger(__name__)


@dataclass
class Event:
    """A single episodic memory event."""
    event_id: str
    timestamp: str
    agent_id: str
    tool_name: str
    input_args: dict[str, Any]
    output: Any
    success: bool
    session_id: str | None = None
    project_id: str | None = None
    tags: list[str] = field(default_factory=list)


class EpisodicMemory:
    """
    Event store backed by Neo4j.

    Stores tool executions, agent observations, and phase transitions
    as (:EpisodicEvent) nodes linked to sessions and scans.
    """

    def __init__(self, client: Neo4jClient) -> None:
        self._client = client

    async def store_event(
        self,
        timestamp: str,
        agent_id: str,
        tool_name: str,
        input_args: dict[str, Any],
        output: Any,
        success: bool,
        session_id: str | None = None,
        project_id: str | None = None,
        tags: list[str] | None = None,
    ) -> str:
        """Store a new event and return its ID."""
        event_id = f"evt-{uuid.uuid4().hex[:16]}"
        output_json = json.dumps(output, default=str)[:10_000]
        args_json = json.dumps(input_args, default=str)[:5_000]

        await self._client.execute_write(
            """
            CREATE (e:EpisodicEvent {
                event_id:   $event_id,
                timestamp:  $timestamp,
                agent_id:   $agent_id,
                tool_name:  $tool_name,
                input_args: $input_args,
                output:     $output,
                success:    $success,
                session_id: $session_id,
                project_id: $project_id,
                tags:       $tags
            })
            """,
            {
                "event_id": event_id,
                "timestamp": timestamp,
                "agent_id": agent_id,
                "tool_name": tool_name,
                "input_args": args_json,
                "output": output_json,
                "success": success,
                "session_id": session_id or "",
                "project_id": project_id or "",
                "tags": tags or [],
            },
        )

        logger.debug("Stored episodic event", event_id=event_id, tool=tool_name)
        return event_id

    async def get_session_events(
        self,
        session_id: str,
        limit: int = 50,
    ) -> list[Event]:
        """Retrieve recent events for a session (most recent first)."""
        records = await self._client.execute_read(
            """
            MATCH (e:EpisodicEvent {session_id: $session_id})
            RETURN e
            ORDER BY e.timestamp DESC
            LIMIT $limit
            """,
            {"session_id": session_id, "limit": limit},
        )
        return [self._to_event(r["e"]) for r in records]

    async def get_events_by_tool(
        self,
        tool_name: str,
        project_id: str | None = None,
        limit: int = 20,
    ) -> list[Event]:
        """Retrieve events for a specific tool."""
        if project_id:
            records = await self._client.execute_read(
                """
                MATCH (e:EpisodicEvent {tool_name: $tool, project_id: $pid})
                RETURN e ORDER BY e.timestamp DESC LIMIT $limit
                """,
                {"tool": tool_name, "pid": project_id, "limit": limit},
            )
        else:
            records = await self._client.execute_read(
                """
                MATCH (e:EpisodicEvent {tool_name: $tool})
                RETURN e ORDER BY e.timestamp DESC LIMIT $limit
                """,
                {"tool": tool_name, "limit": limit},
            )
        return [self._to_event(r["e"]) for r in records]

    async def get_events_in_range(
        self,
        start: str,
        end: str,
        project_id: str | None = None,
        limit: int = 100,
    ) -> list[Event]:
        """Retrieve events within a time range."""
        params: dict[str, Any] = {"start": start, "end": end, "limit": limit}
        where = "WHERE e.timestamp >= $start AND e.timestamp <= $end"
        if project_id:
            where += " AND e.project_id = $pid"
            params["pid"] = project_id

        records = await self._client.execute_read(
            f"MATCH (e:EpisodicEvent) {where} RETURN e ORDER BY e.timestamp DESC LIMIT $limit",
            params,
        )
        return [self._to_event(r["e"]) for r in records]

    async def get_failures(
        self,
        project_id: str | None = None,
        limit: int = 20,
    ) -> list[Event]:
        """Retrieve failed events (for learning from mistakes)."""
        params: dict[str, Any] = {"limit": limit}
        where = "WHERE e.success = false"
        if project_id:
            where += " AND e.project_id = $pid"
            params["pid"] = project_id

        records = await self._client.execute_read(
            f"MATCH (e:EpisodicEvent) {where} RETURN e ORDER BY e.timestamp DESC LIMIT $limit",
            params,
        )
        return [self._to_event(r["e"]) for r in records]

    @staticmethod
    def _to_event(node: dict[str, Any]) -> Event:
        return Event(
            event_id=node.get("event_id", ""),
            timestamp=node.get("timestamp", ""),
            agent_id=node.get("agent_id", ""),
            tool_name=node.get("tool_name", ""),
            input_args=json.loads(node.get("input_args", "{}")),
            output=json.loads(node.get("output", "null")),
            success=node.get("success", False),
            session_id=node.get("session_id"),
            project_id=node.get("project_id"),
            tags=node.get("tags", []),
        )
