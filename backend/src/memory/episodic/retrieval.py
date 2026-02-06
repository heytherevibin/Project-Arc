"""
Temporal Retrieval

Advanced episodic memory retrieval with time-range queries,
similarity-based lookup, and related-event chaining.
Wraps and extends EpisodicMemory for richer retrieval patterns.
"""

from __future__ import annotations

from datetime import datetime, timezone, timedelta
from typing import Any

from core.logging import get_logger
from graph.client import Neo4jClient
from memory.episodic.event_store import EpisodicMemory, Event

logger = get_logger(__name__)


class TemporalRetrieval:
    """
    Rich retrieval layer on top of EpisodicMemory.

    Provides time-windowed queries, similarity-based event search,
    and related-event graph traversal using Neo4j temporal queries
    on :EpisodicEvent nodes.
    """

    def __init__(self, client: Neo4jClient) -> None:
        self._client = client
        self._episodic = EpisodicMemory(client)

    # ------------------------------------------------------------------
    # Time-range queries
    # ------------------------------------------------------------------

    async def query_by_timerange(
        self,
        start: str | datetime,
        end: str | datetime | None = None,
        session_id: str | None = None,
        agent_id: str | None = None,
        limit: int = 100,
    ) -> list[Event]:
        """
        Retrieve events within a time window.

        Parameters
        ----------
        start : ISO timestamp or datetime
        end   : ISO timestamp or datetime (defaults to now)
        session_id : optional filter
        agent_id   : optional filter
        """
        if isinstance(start, datetime):
            start = start.isoformat()
        if end is None:
            end = datetime.now(timezone.utc).isoformat()
        elif isinstance(end, datetime):
            end = end.isoformat()

        filters = ["e.timestamp >= $start", "e.timestamp <= $end"]
        params: dict[str, Any] = {"start": start, "end": end, "limit": limit}

        if session_id:
            filters.append("e.session_id = $session_id")
            params["session_id"] = session_id
        if agent_id:
            filters.append("e.agent_id = $agent_id")
            params["agent_id"] = agent_id

        where = " AND ".join(filters)

        query = f"""
        MATCH (e:EpisodicEvent)
        WHERE {where}
        RETURN e
        ORDER BY e.timestamp DESC
        LIMIT $limit
        """

        records = await self._client.execute_read(query, params)
        return [self._record_to_event(r["e"]) for r in records]

    async def query_recent(
        self,
        minutes: int = 30,
        session_id: str | None = None,
        limit: int = 50,
    ) -> list[Event]:
        """Convenience: get events from the last *n* minutes."""
        start = datetime.now(timezone.utc) - timedelta(minutes=minutes)
        return await self.query_by_timerange(
            start=start, session_id=session_id, limit=limit,
        )

    # ------------------------------------------------------------------
    # Similarity-based retrieval
    # ------------------------------------------------------------------

    async def query_by_similarity(
        self,
        tool_name: str | None = None,
        target: str | None = None,
        success: bool | None = None,
        limit: int = 20,
    ) -> list[Event]:
        """
        Find events similar to the given criteria.

        Matches on tool name, target substring, and success status.
        """
        filters: list[str] = []
        params: dict[str, Any] = {"limit": limit}

        if tool_name:
            filters.append("e.tool_name = $tool_name")
            params["tool_name"] = tool_name
        if target:
            filters.append("e.input_args CONTAINS $target")
            params["target"] = target
        if success is not None:
            filters.append("e.success = $success")
            params["success"] = success

        where = " AND ".join(filters) if filters else "TRUE"

        query = f"""
        MATCH (e:EpisodicEvent)
        WHERE {where}
        RETURN e
        ORDER BY e.timestamp DESC
        LIMIT $limit
        """

        records = await self._client.execute_read(query, params)
        return [self._record_to_event(r["e"]) for r in records]

    # ------------------------------------------------------------------
    # Related-event graph traversal
    # ------------------------------------------------------------------

    async def get_related_events(
        self,
        event_id: str,
        depth: int = 2,
        limit: int = 20,
    ) -> list[Event]:
        """
        Find events related to a given event through shared entities.

        Traverses the graph from the source event through linked hosts,
        vulnerabilities, or credentials to find causally or contextually
        related events.
        """
        query = """
        MATCH (source:EpisodicEvent {event_id: $event_id})
        MATCH (source)-[*1..$depth]-(related:EpisodicEvent)
        WHERE related.event_id <> $event_id
        RETURN DISTINCT related
        ORDER BY related.timestamp DESC
        LIMIT $limit
        """
        params = {"event_id": event_id, "depth": depth, "limit": limit}

        records = await self._client.execute_read(query, params)
        return [self._record_to_event(r["related"]) for r in records]

    async def get_event_chain(
        self,
        session_id: str,
        tool_name: str | None = None,
    ) -> list[Event]:
        """
        Get the full ordered chain of events in a session,
        optionally filtered by tool.
        """
        filters = ["e.session_id = $session_id"]
        params: dict[str, Any] = {"session_id": session_id}

        if tool_name:
            filters.append("e.tool_name = $tool_name")
            params["tool_name"] = tool_name

        where = " AND ".join(filters)

        query = f"""
        MATCH (e:EpisodicEvent)
        WHERE {where}
        RETURN e
        ORDER BY e.timestamp ASC
        """

        records = await self._client.execute_read(query, params)
        return [self._record_to_event(r["e"]) for r in records]

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _record_to_event(node: Any) -> Event:
        """Convert a Neo4j node to an Event dataclass."""
        props = dict(node) if hasattr(node, "__iter__") else {}
        import json as _json

        input_args = props.get("input_args", "{}")
        if isinstance(input_args, str):
            try:
                input_args = _json.loads(input_args)
            except _json.JSONDecodeError:
                input_args = {}

        output = props.get("output", "")
        if isinstance(output, str):
            try:
                output = _json.loads(output)
            except _json.JSONDecodeError:
                pass

        return Event(
            event_id=props.get("event_id", ""),
            timestamp=props.get("timestamp", ""),
            agent_id=props.get("agent_id", ""),
            tool_name=props.get("tool_name", ""),
            input_args=input_args,
            output=output,
            success=props.get("success", False),
            session_id=props.get("session_id"),
            project_id=props.get("project_id"),
            tags=props.get("tags", []),
        )
