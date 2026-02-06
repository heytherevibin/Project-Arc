"""
Unified Cognitive Memory Interface

Coordinates episodic, semantic, procedural, and working memory stores.
Implements Located Memory Activation to prevent context forgetting
during long multi-step operations.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from core.logging import get_logger
from graph.client import Neo4jClient
from memory.episodic.event_store import EpisodicMemory, Event
from memory.semantic.knowledge_base import SemanticMemory
from memory.procedural.technique_library import ProceduralMemory
from memory.working.context_manager import WorkingMemory

logger = get_logger(__name__)


@dataclass
class Observation:
    """An observation from tool execution or analysis."""
    timestamp: str
    agent_id: str
    tool: str
    args: dict[str, Any]
    output: Any
    success: bool
    technique: str | None = None
    context: dict[str, Any] = field(default_factory=dict)


@dataclass
class MemoryBundle:
    """Bundle of recalled memories from all stores."""
    episodic: list[Event]
    semantic: list[dict[str, Any]]
    procedural: list[dict[str, Any]]


@dataclass
class Context:
    """Current execution context for memory retrieval."""
    session_id: str
    project_id: str
    current_phase: str
    current_target: str | None = None
    target_type: str | None = None
    available_tools: list[str] = field(default_factory=list)


class CognitiveMemory:
    """
    Unified memory interface with Located Memory Activation.

    Prevents context forgetting during long multi-step operations
    by coordinating retrieval across all memory stores based on
    current context.
    """

    EXPLOIT_TOOLS = {
        "metasploit", "sqlmap", "commix", "sliver",
        "impacket", "certipy", "crackmapexec",
    }

    def __init__(self, neo4j_client: Neo4jClient, redis_url: str | None = None) -> None:
        self.episodic = EpisodicMemory(neo4j_client)
        self.semantic = SemanticMemory(neo4j_client)
        self.procedural = ProceduralMemory(neo4j_client)
        self.working = WorkingMemory(max_tokens=128_000)
        self._neo4j = neo4j_client

    async def remember(self, observation: Observation) -> str:
        """
        Store an observation across all appropriate memory stores.

        Returns the episodic event ID.
        """
        # Episodic: raw event with timestamp
        event_id = await self.episodic.store_event(
            timestamp=observation.timestamp,
            agent_id=observation.agent_id,
            tool_name=observation.tool,
            input_args=observation.args,
            output=observation.output,
            success=observation.success,
        )

        # Semantic: extract and link entities
        entities = await self._extract_entities(observation)
        for entity in entities:
            await self.semantic.upsert_entity(entity)

        # Procedural: learn from successful exploits
        if observation.tool in self.EXPLOIT_TOOLS and observation.success:
            await self.procedural.record_success(
                technique=observation.technique or observation.tool,
                context=observation.context,
                payload=observation.args,
            )

        # Procedural: learn from failures
        if observation.tool in self.EXPLOIT_TOOLS and not observation.success:
            await self.procedural.record_failure(
                technique=observation.technique or observation.tool,
                context=observation.context,
                error=str(observation.output)[:500],
            )

        # Update working memory
        self.working.add_event(event_id, observation)

        logger.debug(
            "Observation stored in memory",
            event_id=event_id,
            tool=observation.tool,
            entities=len(entities),
        )

        return event_id

    async def recall(self, query: str, context: Context) -> MemoryBundle:
        """
        Located Memory Activation: retrieve relevant memories
        based on current context and query.
        """
        # Episodic: recent events in this session
        recent_events = await self.episodic.get_session_events(
            session_id=context.session_id,
            limit=50,
        )

        # Semantic: similar knowledge chunks
        knowledge = await self.semantic.search(
            query=query,
            project_id=context.project_id,
            target=context.current_target,
            limit=10,
        )

        # Procedural: relevant techniques for current phase
        techniques = await self.procedural.get_techniques(
            phase=context.current_phase,
            target_type=context.target_type,
            available_tools=context.available_tools,
        )

        bundle = MemoryBundle(
            episodic=recent_events,
            semantic=knowledge,
            procedural=techniques,
        )

        logger.debug(
            "Memory recall",
            episodic_count=len(bundle.episodic),
            semantic_count=len(bundle.semantic),
            procedural_count=len(bundle.procedural),
        )

        return bundle

    async def _extract_entities(self, observation: Observation) -> list[dict[str, Any]]:
        """Extract structured entities from an observation for semantic memory."""
        entities: list[dict[str, Any]] = []
        output = observation.output

        if not isinstance(output, dict):
            return entities

        # Extract hosts/IPs
        for ip in output.get("ips", []):
            entities.append({"type": "ip", "value": ip, "source": observation.tool})
        for host in output.get("hosts", []):
            entities.append({"type": "host", "value": host, "source": observation.tool})

        # Extract subdomains
        for sub in output.get("subdomains", []):
            entities.append({"type": "subdomain", "value": sub, "source": observation.tool})

        # Extract URLs
        for url in output.get("urls", output.get("live_urls", [])):
            entities.append({"type": "url", "value": url, "source": observation.tool})

        # Extract vulnerabilities
        for vuln in output.get("vulnerabilities", []):
            entities.append({
                "type": "vulnerability",
                "value": vuln.get("template_id", "unknown"),
                "severity": vuln.get("severity"),
                "cve": vuln.get("cve_id"),
                "source": observation.tool,
            })

        # Extract credentials
        for cred in output.get("credentials", []):
            entities.append({
                "type": "credential",
                "value": cred.get("username", "unknown"),
                "credential_type": cred.get("type"),
                "source": observation.tool,
            })

        return entities
