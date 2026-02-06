"""
Failure Memory

Dedicated store for failed attack attempts so the agent can avoid
repeating the same mistakes.  Queries :TechniqueRecord nodes where
success = false to provide "should_avoid" guidance.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from core.logging import get_logger
from graph.client import Neo4jClient

logger = get_logger(__name__)


@dataclass
class FailureRecord:
    """A recorded failure."""
    record_id: str
    technique: str
    target: str
    tool: str
    error: str
    timestamp: str
    context: dict[str, Any] = field(default_factory=dict)
    retry_count: int = 0


class FailureMemory:
    """
    Neo4j-backed store for failed attack attempts.

    Helps the agent avoid:
    - Repeating the same tool/technique on the same target
    - Using techniques that consistently fail in similar contexts
    - Wasting time on known-bad approaches
    """

    # Number of failures before we start strongly advising avoidance
    AVOID_THRESHOLD = 2

    def __init__(self, client: Neo4jClient) -> None:
        self._client = client

    # ------------------------------------------------------------------
    # Record
    # ------------------------------------------------------------------

    async def record_failure(
        self,
        technique: str,
        target: str,
        tool: str,
        error: str,
        context: dict[str, Any] | None = None,
    ) -> str:
        """
        Record a failed attempt.

        Upserts a :FailureRecord node keyed on (technique, target, tool).
        Increments retry_count on subsequent failures for the same combo.
        """
        now = datetime.now(timezone.utc).isoformat()
        record_id = f"fail-{technique}-{target}-{tool}"

        query = """
        MERGE (f:FailureRecord {record_id: $record_id})
        ON CREATE SET
            f.technique   = $technique,
            f.target      = $target,
            f.tool        = $tool,
            f.error       = $error,
            f.context     = $context,
            f.timestamp   = $now,
            f.retry_count = 1
        ON MATCH SET
            f.retry_count = f.retry_count + 1,
            f.error       = $error,
            f.context     = $context,
            f.timestamp   = $now
        RETURN f.record_id AS rid
        """

        params = {
            "record_id": record_id,
            "technique": technique,
            "target": target,
            "tool": tool,
            "error": error[:1000],
            "context": json.dumps(context or {}),
            "now": now,
        }

        await self._client.execute_write(query, params)
        logger.debug("Failure recorded", record_id=record_id, technique=technique)
        return record_id

    # ------------------------------------------------------------------
    # Query
    # ------------------------------------------------------------------

    async def should_avoid(
        self,
        technique: str,
        target: str,
        tool: str | None = None,
    ) -> bool:
        """
        Check if a particular technique/target combination should be
        avoided based on past failures.

        Returns True if the number of past failures meets or exceeds
        the avoidance threshold.
        """
        filters = [
            "f.technique = $technique",
            "f.target = $target",
        ]
        params: dict[str, Any] = {
            "technique": technique,
            "target": target,
        }

        if tool:
            filters.append("f.tool = $tool")
            params["tool"] = tool

        where = " AND ".join(filters)

        query = f"""
        MATCH (f:FailureRecord)
        WHERE {where}
        RETURN sum(f.retry_count) AS total_failures
        """

        records = await self._client.execute_read(query, params)
        if records:
            total = records[0].get("total_failures", 0) or 0
            return total >= self.AVOID_THRESHOLD
        return False

    async def get_failures_for_target(
        self,
        target: str,
        limit: int = 20,
    ) -> list[FailureRecord]:
        """Get all failure records for a target, most recent first."""
        query = """
        MATCH (f:FailureRecord)
        WHERE f.target = $target
        RETURN f
        ORDER BY f.timestamp DESC
        LIMIT $limit
        """

        records = await self._client.execute_read(
            query, {"target": target, "limit": limit},
        )
        return [self._to_record(r["f"]) for r in records]

    async def get_failures_for_technique(
        self,
        technique: str,
        limit: int = 20,
    ) -> list[FailureRecord]:
        """Get all failures for a specific technique across targets."""
        query = """
        MATCH (f:FailureRecord)
        WHERE f.technique = $technique
        RETURN f
        ORDER BY f.retry_count DESC
        LIMIT $limit
        """

        records = await self._client.execute_read(
            query, {"technique": technique, "limit": limit},
        )
        return [self._to_record(r["f"]) for r in records]

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _to_record(node: Any) -> FailureRecord:
        props = dict(node) if hasattr(node, "__iter__") else {}
        ctx_raw = props.get("context", "{}")
        if isinstance(ctx_raw, str):
            try:
                ctx = json.loads(ctx_raw)
            except json.JSONDecodeError:
                ctx = {}
        else:
            ctx = ctx_raw or {}

        return FailureRecord(
            record_id=props.get("record_id", ""),
            technique=props.get("technique", ""),
            target=props.get("target", ""),
            tool=props.get("tool", ""),
            error=props.get("error", ""),
            timestamp=props.get("timestamp", ""),
            context=ctx,
            retry_count=int(props.get("retry_count", 0)),
        )
