"""
Procedural Memory - Technique Library

Records successful and failed attack techniques so the agent can learn
from past engagements. Tracks which techniques work against which
target types, avoiding repeating failures.
"""

from __future__ import annotations

import json
import uuid
from typing import Any

from core.logging import get_logger
from graph.client import Neo4jClient

logger = get_logger(__name__)


class ProceduralMemory:
    """
    Procedural memory backed by Neo4j.

    Stores (:Technique) nodes representing attack techniques,
    with success/failure counts and context metadata.
    """

    # Phase → technique mapping for recommendation
    PHASE_TECHNIQUES: dict[str, list[str]] = {
        "recon": [
            "subdomain_enumeration", "port_scanning", "http_probing",
            "web_crawling", "osint", "dns_resolution", "technology_fingerprint",
        ],
        "vuln_analysis": [
            "nuclei_scan", "nikto_scan", "openvas_scan",
            "web_vuln_scan", "ssl_analysis",
        ],
        "exploitation": [
            "metasploit_exploit", "sqlmap_injection", "command_injection",
            "file_upload", "deserialization", "ssrf",
        ],
        "post_exploitation": [
            "privilege_escalation", "credential_dump", "lateral_movement",
            "persistence", "data_exfiltration",
        ],
        "identity": [
            "bloodhound_collection", "kerberoasting", "asreproasting",
            "dcsync", "adcs_abuse", "password_spray",
        ],
    }

    def __init__(self, client: Neo4jClient) -> None:
        self._client = client

    async def record_success(
        self,
        technique: str,
        context: dict[str, Any],
        payload: dict[str, Any] | None = None,
    ) -> str:
        """Record a successful technique execution."""
        record_id = f"tech-{uuid.uuid4().hex[:12]}"
        ctx_json = json.dumps(context, default=str)[:5_000]
        payload_json = json.dumps(payload or {}, default=str)[:5_000]

        await self._client.execute_write(
            """
            MERGE (t:Technique {name: $technique})
            ON CREATE SET
                t.success_count = 1,
                t.failure_count = 0,
                t.created_at = datetime()
            ON MATCH SET
                t.success_count = t.success_count + 1,
                t.updated_at = datetime()
            WITH t
            CREATE (r:TechniqueRecord {
                record_id: $record_id,
                success: true,
                context: $context,
                payload: $payload,
                recorded_at: datetime()
            })
            CREATE (t)-[:HAS_RECORD]->(r)
            """,
            {
                "technique": technique,
                "record_id": record_id,
                "context": ctx_json,
                "payload": payload_json,
            },
        )

        logger.debug("Recorded successful technique", technique=technique)
        return record_id

    async def record_failure(
        self,
        technique: str,
        context: dict[str, Any],
        error: str = "",
    ) -> str:
        """Record a failed technique execution (what NOT to do)."""
        record_id = f"tech-{uuid.uuid4().hex[:12]}"
        ctx_json = json.dumps(context, default=str)[:5_000]

        await self._client.execute_write(
            """
            MERGE (t:Technique {name: $technique})
            ON CREATE SET
                t.success_count = 0,
                t.failure_count = 1,
                t.created_at = datetime()
            ON MATCH SET
                t.failure_count = t.failure_count + 1,
                t.updated_at = datetime()
            WITH t
            CREATE (r:TechniqueRecord {
                record_id: $record_id,
                success: false,
                context: $context,
                error: $error,
                recorded_at: datetime()
            })
            CREATE (t)-[:HAS_RECORD]->(r)
            """,
            {
                "technique": technique,
                "record_id": record_id,
                "context": ctx_json,
                "error": error[:500],
            },
        )

        logger.debug("Recorded failed technique", technique=technique)
        return record_id

    async def get_techniques(
        self,
        phase: str | None = None,
        target_type: str | None = None,
        available_tools: list[str] | None = None,
        limit: int = 20,
    ) -> list[dict[str, Any]]:
        """
        Retrieve relevant techniques for the current phase.

        Prioritizes techniques with higher success rates and
        filters by phase and available tools.
        """
        # Get techniques sorted by success rate
        records = await self._client.execute_read(
            """
            MATCH (t:Technique)
            WITH t,
                 t.success_count AS successes,
                 t.failure_count AS failures,
                 CASE WHEN (t.success_count + t.failure_count) > 0
                      THEN toFloat(t.success_count) / (t.success_count + t.failure_count)
                      ELSE 0.5
                 END AS success_rate
            RETURN t.name AS technique,
                   successes,
                   failures,
                   success_rate
            ORDER BY success_rate DESC, successes DESC
            LIMIT $limit
            """,
            {"limit": limit},
        )

        techniques = [dict(r) for r in records]

        # Filter by phase if specified
        if phase and phase in self.PHASE_TECHNIQUES:
            phase_techs = set(self.PHASE_TECHNIQUES[phase])
            # Include phase-specific techniques first, then others
            prioritized = [t for t in techniques if t["technique"] in phase_techs]
            others = [t for t in techniques if t["technique"] not in phase_techs]
            techniques = prioritized + others

        return techniques[:limit]

    async def get_playbook(
        self,
        technique: str,
        success_only: bool = True,
        limit: int = 5,
    ) -> list[dict[str, Any]]:
        """Get recorded instances of a technique (playbook entries)."""
        success_filter = "AND r.success = true" if success_only else ""
        records = await self._client.execute_read(
            f"""
            MATCH (t:Technique {{name: $technique}})-[:HAS_RECORD]->(r:TechniqueRecord)
            WHERE true {success_filter}
            RETURN r.record_id AS record_id,
                   r.success AS success,
                   r.context AS context,
                   r.payload AS payload,
                   r.error AS error,
                   r.recorded_at AS recorded_at
            ORDER BY r.recorded_at DESC
            LIMIT $limit
            """,
            {"technique": technique, "limit": limit},
        )
        return [dict(r) for r in records]

    async def get_success_rate(self, technique: str) -> float:
        """Get the success rate for a specific technique."""
        records = await self._client.execute_read(
            """
            MATCH (t:Technique {name: $technique})
            RETURN CASE WHEN (t.success_count + t.failure_count) > 0
                        THEN toFloat(t.success_count) / (t.success_count + t.failure_count)
                        ELSE 0.0
                   END AS rate
            """,
            {"technique": technique},
        )
        return records[0]["rate"] if records else 0.0
