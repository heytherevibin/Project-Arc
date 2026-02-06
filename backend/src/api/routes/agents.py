"""
AI Agent / Chat Endpoints

Provides the operator chat interface for interacting with the Arc
AI agent system.  Supports:
  - Sending chat messages to the supervisor
  - Streaming agent responses
  - Listing available agents and their capabilities
  - Agent status and health checks
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel, Field

from agents.specialists import (
    ExfilSpecialist,
    ExploitSpecialist,
    PersistenceSpecialist,
    PivotSpecialist,
    PostExploitSpecialist,
    ReconSpecialist,
    ReportSpecialist,
    VulnAnalysisSpecialist,
)
from core.config import get_settings
from core.logging import get_logger

router = APIRouter()
logger = get_logger(__name__)


# =============================================================================
# Request/Response Models
# =============================================================================

class ChatMessage(BaseModel):
    """A chat message to the AI operator."""
    message: str = Field(..., min_length=1, max_length=10000)
    project_id: str | None = None
    mission_id: str | None = None
    context: dict[str, Any] = Field(default_factory=dict)


class ChatResponse(BaseModel):
    """Response from the AI operator."""
    response: str
    agent_id: str = "supervisor"
    suggestions: list[str] = []
    actions_taken: list[dict[str, Any]] = []


class AgentInfo(BaseModel):
    """Information about a specialist agent."""
    agent_id: str
    agent_name: str
    supported_phases: list[str]
    available_tools: list[str]
    status: str = "available"


class AgentListResponse(BaseModel):
    """List of available agents."""
    agents: list[AgentInfo]


# =============================================================================
# Endpoints
# =============================================================================

@router.post("/chat", response_model=ChatResponse)
async def chat(body: ChatMessage) -> dict[str, Any]:
    """
    Send a message to the AI operator.

    The operator routes the message to the appropriate specialist
    or provides a direct response based on the query.
    """
    settings = get_settings()
    user_message = body.message.strip()

    # Attempt to generate an intelligent response using LLM
    try:
        response_text, suggestions = await _generate_response(
            user_message, body.project_id, body.mission_id, body.context, settings
        )
    except Exception as e:
        logger.warning("LLM chat failed, using fallback", error=str(e))
        response_text = _fallback_response(user_message)
        suggestions = _get_default_suggestions()

    return {
        "response": response_text,
        "agent_id": "supervisor",
        "suggestions": suggestions,
        "actions_taken": [],
    }


@router.get("/agents", response_model=AgentListResponse)
async def list_agents() -> dict[str, Any]:
    """List all available specialist agents and their capabilities."""
    agents = _get_all_agents()
    return {
        "agents": [
            {
                "agent_id": a.agent_id,
                "agent_name": a.agent_name,
                "supported_phases": a.supported_phases,
                "available_tools": a.available_tools,
                "status": "available",
            }
            for a in agents
        ]
    }


@router.get("/agents/{agent_id}", response_model=AgentInfo)
async def get_agent(agent_id: str) -> dict[str, Any]:
    """Get details about a specific agent."""
    agents = {a.agent_id: a for a in _get_all_agents()}
    agent = agents.get(agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail=f"Agent '{agent_id}' not found")
    return {
        "agent_id": agent.agent_id,
        "agent_name": agent.agent_name,
        "supported_phases": agent.supported_phases,
        "available_tools": agent.available_tools,
        "status": "available",
    }


@router.get("/tools")
async def list_all_tools() -> dict[str, Any]:
    """List all available tools across all agents."""
    agents = _get_all_agents()
    tools: dict[str, list[str]] = {}
    for agent in agents:
        for tool in agent.available_tools:
            if tool not in tools:
                tools[tool] = []
            tools[tool].append(agent.agent_id)
    return {
        "tools": [
            {"name": name, "agents": agent_ids}
            for name, agent_ids in sorted(tools.items())
        ],
        "total": len(tools),
    }


# =============================================================================
# Helpers
# =============================================================================

def _get_all_agents() -> list[Any]:
    """Instantiate all specialist agents for info queries."""
    return [
        ReconSpecialist(),
        VulnAnalysisSpecialist(),
        ExploitSpecialist(),
        PostExploitSpecialist(),
        PivotSpecialist(),
        PersistenceSpecialist(),
        ExfilSpecialist(),
        ReportSpecialist(),
    ]


async def _generate_response(
    message: str,
    project_id: str | None,
    mission_id: str | None,
    context: dict[str, Any],
    settings: Any,
) -> tuple[str, list[str]]:
    """Generate a response using the configured LLM provider."""
    provider = settings.LLM_PROVIDER
    api_key = settings.llm_api_key
    model = settings.llm_model

    if not api_key or api_key.startswith("sk-your-"):
        # No real API key configured
        return _fallback_response(message), _get_default_suggestions()

    system_prompt = (
        "You are Arc, an AI-powered penetration testing operator. "
        "You help security professionals plan and execute penetration tests. "
        "Be concise, technical, and actionable. "
        "When asked about targets, suggest appropriate tools and techniques. "
        "Always recommend getting approval before exploitation."
    )

    if provider == "openai":
        import openai
        client = openai.AsyncOpenAI(api_key=api_key)
        response = await client.chat.completions.create(
            model=model or "gpt-4o",
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": message},
            ],
            max_tokens=1024,
        )
        text = response.choices[0].message.content or ""
    elif provider == "anthropic":
        import anthropic
        client = anthropic.AsyncAnthropic(api_key=api_key)
        response = await client.messages.create(
            model=model or "claude-3-5-sonnet-20241022",
            max_tokens=1024,
            system=system_prompt,
            messages=[{"role": "user", "content": message}],
        )
        text = response.content[0].text if response.content else ""
    else:
        text = _fallback_response(message)

    suggestions = _get_context_suggestions(message)
    return text, suggestions


def _fallback_response(message: str) -> str:
    """Generate a basic response when LLM is unavailable."""
    lower = message.lower()

    if any(w in lower for w in ["scan", "recon", "discover"]):
        return (
            "I can help with reconnaissance. To start scanning a target, "
            "create a mission from the Missions page or use the Scans page "
            "for quick recon. Available tools: subfinder, naabu, httpx, "
            "nuclei, katana, and more."
        )
    if any(w in lower for w in ["exploit", "attack", "pwn"]):
        return (
            "Exploitation requires careful planning. First ensure you have "
            "discovered vulnerabilities via scanning. Then create a mission "
            "with exploitation objectives — all exploit actions require "
            "human approval before execution."
        )
    if any(w in lower for w in ["help", "what can you do", "commands"]):
        return (
            "I'm Arc, your AI pentesting operator. I can:\n"
            "• Plan and execute reconnaissance\n"
            "• Analyze vulnerabilities\n"
            "• Coordinate exploitation (with approval)\n"
            "• Manage lateral movement and persistence\n"
            "• Generate penetration test reports\n\n"
            "Start by creating a mission or running a scan."
        )

    return (
        "I'm ready to assist with your penetration testing engagement. "
        "You can ask me about scanning targets, analyzing vulnerabilities, "
        "planning exploitation, or generating reports."
    )


def _get_default_suggestions() -> list[str]:
    return [
        "Scan a target domain",
        "List discovered vulnerabilities",
        "Plan an attack strategy",
        "Generate a report",
    ]


def _get_context_suggestions(message: str) -> list[str]:
    lower = message.lower()
    if "recon" in lower or "scan" in lower:
        return [
            "Run a full recon pipeline",
            "Check scan results",
            "Analyze discovered hosts",
        ]
    if "vuln" in lower:
        return [
            "Prioritize by CVSS score",
            "Check EPSS exploitation probability",
            "Plan exploitation for critical vulns",
        ]
    return _get_default_suggestions()
