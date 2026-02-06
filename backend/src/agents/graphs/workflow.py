"""
LangGraph Workflow Engine

Compiles the supervisor + specialist agents into a runnable LangGraph
StateGraph with conditional edges, checkpointing, and approval gates.
"""

from __future__ import annotations

import asyncio
from typing import Any

from langgraph.graph import END, StateGraph

from agents.graphs.supervisor_graph import (
    APPROVAL_WAIT,
    EXPLOIT,
    LATERAL,
    RECON,
    REPORT,
    SUPERVISOR,
    VULN_ANALYSIS,
    POST_EXPLOIT,
    route_after_approval,
    route_after_specialist,
    route_after_supervisor,
    supervisor_node,
)
from agents.supervisor.supervisor_agent import AgentState
from core.logging import get_logger


logger = get_logger(__name__)


async def recon_node(state: AgentState) -> AgentState:
    """Recon specialist — plan & execute recon tools."""
    from agents.specialists.recon_agent import ReconSpecialist

    agent = ReconSpecialist()
    tool_calls = await agent.plan(state)

    results = []
    for tc in tool_calls:
        result = await agent.execute_tool(tc)
        results.append(result)

    state = await agent.analyze(state, results)

    # Attach messages from the agent
    messages = agent.drain_outbox()
    if messages:
        state["agent_messages"] = state.get("agent_messages", []) + [
            {"from": m.from_agent, "to": m.to_agent, "content": m.content}
            for m in messages
        ]

    return state


async def vuln_analysis_node(state: AgentState) -> AgentState:
    """Vuln analysis specialist."""
    from agents.specialists.vuln_agent import VulnAnalysisSpecialist

    agent = VulnAnalysisSpecialist()
    tool_calls = await agent.plan(state)
    results = []
    for tc in tool_calls:
        result = await agent.execute_tool(tc)
        results.append(result)
    state = await agent.analyze(state, results)
    return state


async def exploit_node(state: AgentState) -> AgentState:
    """Exploit specialist — requires prior approval."""
    from agents.specialists.exploit_agent import ExploitSpecialist

    agent = ExploitSpecialist()
    tool_calls = await agent.plan(state)
    results = []
    for tc in tool_calls:
        result = await agent.execute_tool(tc)
        results.append(result)
    state = await agent.analyze(state, results)
    return state


async def post_exploit_node(state: AgentState) -> AgentState:
    """Post-exploitation specialist."""
    from agents.specialists.post_exploit_agent import PostExploitSpecialist

    agent = PostExploitSpecialist()
    tool_calls = await agent.plan(state)
    results = []
    for tc in tool_calls:
        result = await agent.execute_tool(tc)
        results.append(result)
    state = await agent.analyze(state, results)
    return state


async def lateral_node(state: AgentState) -> AgentState:
    """Lateral movement via pivot agent."""
    from agents.specialists.pivot_agent import PivotSpecialist

    agent = PivotSpecialist()
    tool_calls = await agent.plan(state)
    results = []
    for tc in tool_calls:
        result = await agent.execute_tool(tc)
        results.append(result)
    state = await agent.analyze(state, results)
    return state


async def report_node(state: AgentState) -> AgentState:
    """Report specialist — generates final report."""
    from agents.specialists.report_agent import ReportSpecialist

    agent = ReportSpecialist()
    tool_calls = await agent.plan(state)
    results = []
    for tc in tool_calls:
        result = await agent.execute_tool(tc)
        results.append(result)
    state = await agent.analyze(state, results)
    state["next_agent"] = "__end__"
    return state


async def approval_wait_node(state: AgentState) -> AgentState:
    """
    Pause node — the graph yields here and waits for external approval.

    When resumed after approval, pending_approvals will have been updated
    and the supervisor will route to the next phase.
    """
    logger.info(
        "Waiting for approval",
        pending=[a for a in state.get("pending_approvals", []) if a.get("status") == "pending"],
    )
    # The graph will interrupt here.  External code calls
    # approve_and_resume() to continue.
    return state


# ---------------------------------------------------------------------------
# Graph builder
# ---------------------------------------------------------------------------

def build_workflow() -> StateGraph:
    """
    Build and compile the Arc pentest workflow graph.

    Returns a compiled LangGraph StateGraph ready for invocation.
    """
    graph = StateGraph(AgentState)

    # Add nodes
    graph.add_node(SUPERVISOR, supervisor_node)
    graph.add_node(RECON, recon_node)
    graph.add_node(VULN_ANALYSIS, vuln_analysis_node)
    graph.add_node(EXPLOIT, exploit_node)
    graph.add_node(POST_EXPLOIT, post_exploit_node)
    graph.add_node(LATERAL, lateral_node)
    graph.add_node(REPORT, report_node)
    graph.add_node(APPROVAL_WAIT, approval_wait_node)

    # Entry point
    graph.set_entry_point(SUPERVISOR)

    # Supervisor → specialist (conditional)
    graph.add_conditional_edges(
        SUPERVISOR,
        route_after_supervisor,
        {
            RECON: RECON,
            VULN_ANALYSIS: VULN_ANALYSIS,
            EXPLOIT: EXPLOIT,
            POST_EXPLOIT: POST_EXPLOIT,
            LATERAL: LATERAL,
            REPORT: REPORT,
            APPROVAL_WAIT: APPROVAL_WAIT,
            END: END,
        },
    )

    # Specialist → supervisor (loop back)
    for specialist in [RECON, VULN_ANALYSIS, EXPLOIT, POST_EXPLOIT, LATERAL]:
        graph.add_conditional_edges(
            specialist,
            route_after_specialist,
            {SUPERVISOR: SUPERVISOR, END: END},
        )

    # Report → end
    graph.add_edge(REPORT, END)

    # Approval wait → supervisor (when resumed)
    graph.add_edge(APPROVAL_WAIT, SUPERVISOR)

    return graph


def compile_workflow(**kwargs: Any) -> Any:
    """
    Build and compile the workflow graph.

    Accepts optional kwargs passed to graph.compile() such as
    checkpointer or interrupt_before.
    """
    graph = build_workflow()

    # Interrupt before approval_wait so external code can inject approval
    interrupt_before = kwargs.pop("interrupt_before", [APPROVAL_WAIT])

    compiled = graph.compile(
        interrupt_before=interrupt_before,
        **kwargs,
    )

    logger.info("Workflow compiled", nodes=compiled.get_graph().nodes)
    return compiled
