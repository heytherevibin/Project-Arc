"""
Recon Sub-graph

Dedicated LangGraph StateGraph for the reconnaissance phase.

Flow:  passive_recon → active_recon → enrichment → (end)

Each node runs specific tool sets through the corresponding specialist
agent and conditional edges decide whether to continue or short-circuit.
"""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from agents.shared.base_agent import Phase
from agents.supervisor.state import AgentState
from core.logging import get_logger

logger = get_logger(__name__)


# ---------------------------------------------------------------------------
# Node implementations
# ---------------------------------------------------------------------------

async def passive_recon_node(state: AgentState) -> AgentState:
    """
    Passive recon: subdomain enumeration, OSINT, certificate transparency.
    Low-noise operations that don't touch the target directly.
    """
    from agents.specialists.recon_agent import ReconSpecialist

    agent = ReconSpecialist()
    target = state.get("target", "")
    if not target:
        return state

    # Passive-only tool calls
    from agents.shared.base_agent import ToolCall
    passive_tools = [
        ToolCall(tool_name="subfinder", args={"domain": target, "silent": True}),
        ToolCall(tool_name="whois", args={"domain": target}),
        ToolCall(tool_name="gau", args={"domain": target, "threads": 5}),
    ]

    results = []
    for tc in passive_tools:
        result = await agent.execute_tool(tc)
        results.append(result)

    state = await agent.analyze(state, results)

    state["messages"] = state.get("messages", []) + [{
        "role": "agent",
        "content": f"[Recon/Passive] Discovered {len(state.get('discovered_hosts', []))} hosts via passive recon",
    }]

    logger.info("Passive recon complete", hosts=len(state.get("discovered_hosts", [])))
    return state


async def active_recon_node(state: AgentState) -> AgentState:
    """
    Active recon: port scanning, HTTP probing, service detection.
    Slightly noisier — touches target systems directly.
    """
    from agents.specialists.recon_agent import ReconSpecialist

    agent = ReconSpecialist()
    hosts = state.get("discovered_hosts", [])
    if not hosts:
        return state

    from agents.shared.base_agent import ToolCall
    active_tools = []

    for host in hosts[:20]:  # cap to avoid excessive scanning
        active_tools.append(
            ToolCall(tool_name="naabu", args={"host": host, "top_ports": "1000"})
        )

    # HTTP probing on all hosts
    active_tools.append(
        ToolCall(tool_name="httpx", args={"targets": hosts[:50], "status_code": True, "title": True})
    )

    results = []
    for tc in active_tools:
        result = await agent.execute_tool(tc)
        results.append(result)

    state = await agent.analyze(state, results)

    state["messages"] = state.get("messages", []) + [{
        "role": "agent",
        "content": f"[Recon/Active] Port scanning and HTTP probing complete on {len(hosts)} hosts",
    }]

    logger.info("Active recon complete", hosts_scanned=len(hosts))
    return state


async def enrichment_node(state: AgentState) -> AgentState:
    """
    Enrichment: technology detection, directory brute-forcing,
    vulnerability pre-scanning with Nuclei.
    """
    from agents.specialists.recon_agent import ReconSpecialist

    agent = ReconSpecialist()
    hosts = state.get("discovered_hosts", [])
    if not hosts:
        return state

    from agents.shared.base_agent import ToolCall
    enrichment_tools = [
        ToolCall(tool_name="nuclei", args={
            "targets": hosts[:30],
            "severity": "critical,high,medium",
            "silent": True,
        }),
        ToolCall(tool_name="katana", args={
            "targets": hosts[:10],
            "depth": 3,
        }),
    ]

    results = []
    for tc in enrichment_tools:
        result = await agent.execute_tool(tc)
        results.append(result)

    state = await agent.analyze(state, results)

    vulns = state.get("discovered_vulns", [])
    state["messages"] = state.get("messages", []) + [{
        "role": "agent",
        "content": f"[Recon/Enrichment] Found {len(vulns)} potential vulnerabilities during enrichment",
    }]

    logger.info("Enrichment complete", vulns=len(vulns))
    return state


# ---------------------------------------------------------------------------
# Conditional edges
# ---------------------------------------------------------------------------

def _should_do_active_recon(state: AgentState) -> str:
    """Only proceed to active if passive found at least one host."""
    if state.get("discovered_hosts"):
        return "active_recon"
    return "__end__"


def _should_enrich(state: AgentState) -> str:
    """Only enrich if active scanning returned results."""
    if state.get("discovered_hosts"):
        return "enrichment"
    return "__end__"


# ---------------------------------------------------------------------------
# Builder
# ---------------------------------------------------------------------------

def build_recon_subgraph() -> StateGraph:
    """
    Build the recon sub-graph.

    Returns an uncompiled StateGraph — the caller may compose it into
    the main workflow or compile it standalone.
    """
    graph = StateGraph(AgentState)

    graph.add_node("passive_recon", passive_recon_node)
    graph.add_node("active_recon", active_recon_node)
    graph.add_node("enrichment", enrichment_node)

    graph.set_entry_point("passive_recon")

    graph.add_conditional_edges(
        "passive_recon",
        _should_do_active_recon,
        {"active_recon": "active_recon", "__end__": END},
    )
    graph.add_conditional_edges(
        "active_recon",
        _should_enrich,
        {"enrichment": "enrichment", "__end__": END},
    )
    graph.add_edge("enrichment", END)

    return graph
